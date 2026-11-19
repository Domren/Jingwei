package server

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Domren/jingwei/db"
	"github.com/Domren/jingwei/scanner"
)

// 载荷族（P15）：同一模板 + 同一密钥版本的 shell 归为一族，family_id 由
// db.WebshellFamilyID 派生（与库侧触发器一致）。本文件给出按族批量轮换与
// 批量撤离的 HTTP 入口：两者都逐壳走单壳时的同一套原语（轮换要先在目标上
// 用旧密钥认证、撤离要先证明目标已不再响应），不因为「批量」就跳过确认。

// rotateOneShell 把一个 v2 壳换到新密钥，返回封好的新 secret。它是单壳
// rotateWebshellKey 与批量轮换共用的内核：任何一步失败都保留旧密钥不动，
// 不把「目标已换、账本没跟上」的半成品状态留给操作者。
func (s *Server) rotateOneShell(shell *db.Webshell, client *scanner.DeepClient, newKey []byte) (string, error) {
	payload, err := s.shellPayloadFor(shell)
	if err != nil {
		return "", err
	}
	if err := scanner.RotateShellKey(s.ctx, client, shell.URL, payload, newKey); err != nil {
		return "", err
	}
	return sealShellSecret(s.jwtKey, scanner.EncodeShellKey(newKey))
}

// rotateWebshellFamily 一次轮换同族的全部 shell。新密钥逐壳生成、逐壳封存，
// 但用同一条批量 UPDATE 落库；任一台目标上的轮换失败即中止并逐条报出，已经
// 成功的目标各自更新，绝不把没轮成的壳记成已轮换。
func (s *Server) rotateWebshellFamily(w http.ResponseWriter, r *http.Request) {
	familyID := strings.TrimSpace(r.PathValue("familyID"))
	if familyID == "" {
		writeErr(w, 400, "族 ID 为空")
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	shells, err := pg.ListWebshellsByFamily(familyID)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if len(shells) == 0 {
		writeErr(w, 404, "该族没有 webshell")
		return
	}
	client := scanner.NewDeepClient(20 * time.Second)
	type rotated struct {
		ID      int64  `json:"id"`
		URL     string `json:"url"`
		Secret  string `json:"-"`
		KeyVer  int    `json:"key_version"`
		SHA256  string `json:"sha256"`
		Err     string `json:"error,omitempty"`
		Skipped bool   `json:"skipped,omitempty"`
	}
	details := []rotated{}
	succeeded := 0
	for _, shell := range shells {
		if !strings.EqualFold(shell.Protocol, scanner.ShellProtocolV2) || strings.TrimSpace(shell.URL) == "" {
			details = append(details, rotated{ID: shell.ID, URL: shell.URL, Err: "仅加密 v2 且有地址的壳可轮换", Skipped: true})
			continue
		}
		if reason, allowed := shellAllowed(pg, shell.URL); !allowed {
			details = append(details, rotated{ID: shell.ID, URL: shell.URL, Err: "命中资产拦截规则：" + reason, Skipped: true})
			continue
		}
		newKey, gerr := scanner.GenerateShellKey()
		if gerr != nil {
			details = append(details, rotated{ID: shell.ID, URL: shell.URL, Err: gerr.Error(), Skipped: true})
			continue
		}
		sealed, rerr := s.rotateOneShell(shell, client, newKey)
		if rerr != nil {
			_ = pg.UpdateWebshellState(shell.ID, "dead", "", "批量轮换失败: "+rerr.Error())
			details = append(details, rotated{ID: shell.ID, URL: shell.URL, Err: rerr.Error()})
			continue
		}
		keyVer := shell.KeyVersion + 1
		if keyVer <= 0 {
			keyVer = 2
		}
		// 单壳落库：family_id 由触发器按新 key_version 重算，整族自动迁移到下一代。
		if uerr := pg.UpdateWebshellSecret(shell.ID, sealed, shell.Carrier, shell.PayloadSHA256, keyVer); uerr != nil {
			details = append(details, rotated{ID: shell.ID, URL: shell.URL, Err: "新密钥已生效但落库失败: " + uerr.Error()})
			continue
		}
		_ = pg.UpdateWebshellState(shell.ID, "alive", "", "密钥轮换到 v"+strconv.Itoa(keyVer))
		details = append(details, rotated{ID: shell.ID, URL: shell.URL, Secret: sealed, KeyVer: keyVer, SHA256: shell.PayloadSHA256})
		succeeded++
	}
	writeJSON(w, 200, map[string]any{
		"ok": succeeded == len(shells), "family_id": familyID,
		"total": len(shells), "succeeded": succeeded, "details": details,
	})
}

// evacuateWebshellFamily 一次撤离同族的全部 shell：逐壳发自删除并复核，
// 只用复核通过的 id 清账。批量 DELETE 按 family_id 只在全部通过时使用，
// 部分失败时逐 id 删除已确认的，避免把还活着的壳从台账抹掉。
func (s *Server) evacuateWebshellFamily(w http.ResponseWriter, r *http.Request) {
	familyID := strings.TrimSpace(r.PathValue("familyID"))
	if familyID == "" {
		writeErr(w, 400, "族 ID 为空")
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	shells, err := pg.ListWebshellsByFamily(familyID)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if len(shells) == 0 {
		writeErr(w, 404, "该族没有 webshell")
		return
	}
	client := scanner.NewDeepClient(20 * time.Second)
	type evicted struct {
		ID      int64  `json:"id"`
		URL     string `json:"url"`
		Removed bool   `json:"removed"`
		Note    string `json:"note"`
	}
	results := []evicted{}
	confirmed := []int64{}
	blocked := 0
	for _, shell := range shells {
		if !strings.EqualFold(shell.Protocol, scanner.ShellProtocolV2) || strings.TrimSpace(shell.URL) == "" {
			results = append(results, evicted{ID: shell.ID, URL: shell.URL, Note: "仅加密 v2 且有地址的壳可自删除"})
			blocked++
			continue
		}
		if reason, allowed := shellAllowed(pg, shell.URL); !allowed {
			results = append(results, evicted{ID: shell.ID, URL: shell.URL, Note: "命中资产拦截规则：" + reason})
			blocked++
			continue
		}
		payload, perr := s.shellPayloadFor(shell)
		if perr != nil {
			results = append(results, evicted{ID: shell.ID, URL: shell.URL, Note: perr.Error()})
			blocked++
			continue
		}
		_, derr := scanner.DeleteShellSelf(s.ctx, client, shell.URL, payload)
		removed, note := scanner.VerifyShellRemoved(s.ctx, client, shell.URL, payload)
		if derr != nil {
			note = derr.Error() + "；" + note
		}
		results = append(results, evicted{ID: shell.ID, URL: shell.URL, Removed: removed, Note: note})
		if removed {
			confirmed = append(confirmed, shell.ID)
		} else {
			blocked++
		}
	}
	all := blocked == 0
	var deleted int64
	if all {
		deleted, err = pg.DeleteWebshellsByFamily(familyID)
	} else {
		for _, id := range confirmed {
			if ok, _ := pg.DeleteWebshell(id); ok {
				deleted++
			}
		}
	}
	if err != nil {
		writeErr(w, 500, fmt.Sprintf("目标已确认撤离 %d 个，但清账失败: %v", deleted, err))
		return
	}
	for _, id := range confirmed {
		s.releaseWebshellResource(id, "载荷族批量撤离")
	}
	writeJSON(w, 200, map[string]any{
		"ok": all, "family_id": familyID, "total": len(shells),
		"confirmed": len(confirmed), "deleted": deleted, "results": results,
	})
}
