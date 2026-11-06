package server

import (
	"context"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/jingwei/db"
	"github.com/Autumn-27/jingwei/notify"
	"github.com/Autumn-27/jingwei/scanner"
)

// 密钥轮换后的补救流程（G3）。
//
// 换过平台签名根密钥（platform_secret.jwt_key）之后，库里所有密封值都解不开了，但**看起来
// 一切正常**：shell 的「检测」只问它答不答话，答话就算活；真正要用的时候才在解封那步失败，
// 报出来像目标的问题。1.5.0 的自检只在启动日志里按类别报个条数，剩下的靠人一条条试。
//
// 这里把那条日志变成一条能执行、也能演练的流程：自检给出「哪几条、属于哪类、平台能不能自己
// 做完」，补救按条做——
//
//   - webshell：重新发密钥、重出载荷、把台账改成「等重新投放」并把新载荷交给人。平台**不**
//     假装已经投放好了：文件在目标上，只有人（或一条还活着的通道）能覆盖它。
//   - 内存马：不能只换库里的密钥就完事——目标 JVM 里那个注入物用的还是旧密钥，换了库内值
//     等于台账在说一件目标上不存在的事。所以这里只标注并指出经哪条父壳重注入；旧注入物无法
//     用新密钥撤销，会作为残留记下来。
//   - 凭据与模型密钥：平台读不出旧口令，也就无法替你填回去。列出来、说清去哪儿填，绝不猜。
//
// 「能自动的那一半做掉，不能的那一半说清楚」是这条流程的边界；把四类都说成「已修复」比不做
// 更糟。

// SealRemediationItem 是一条记录的补救动作与结果。
type SealRemediationItem struct {
	Category string `json:"category"`
	ID       int64  `json:"id"`
	Label    string `json:"label"`
	// Action 是这一条要做什么（dry-run 时是计划，执行后是已做）。
	Action string `json:"action"`
	// Done 为 true 只表示**平台这一半已经做完**；还需要人做的事在 Next 里。
	Done  bool   `json:"done"`
	Error string `json:"error"`

	KeyVersion      int    `json:"key_version,omitempty"`
	PayloadFilename string `json:"payload_filename,omitempty"`
	PayloadSHA256   string `json:"payload_sha256,omitempty"`
	// Payload 是重新生成的载荷源码（含新密钥），只在真正执行时返回；与载荷下载接口同口径。
	Payload string `json:"payload,omitempty"`
	Next    string `json:"next"`
}

// SealRemediation 是一次补救的结果汇总。
type SealRemediation struct {
	DryRun     bool                  `json:"dry_run"`
	Audit      db.SealAudit          `json:"audit"`
	Items      []SealRemediationItem `json:"items"`
	Reissued   int                   `json:"reissued"`
	Remaining  int                   `json:"remaining"`
	Note       string                `json:"note"`
	FinishedAt time.Time             `json:"finished_at"`
}

// sealAuditHandler 把自检结果原样交给界面：条数、id、每类能不能自动补救。
func (s *Server) sealAuditHandler(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	audit := pg.AuditSealedSecrets()
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{"audit": audit, "summary": sealAuditSummary(audit)})
}

// sealRemediationHandler 执行补救。dry_run 只出计划，一个字节都不改。
func (s *Server) sealRemediationHandler(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16)
	var req struct {
		DryRun bool `json:"dry_run"`
	}
	if err := decode(r, &req); err != nil && r.ContentLength != 0 {
		writeErr(w, 400, "请求格式错误")
		return
	}
	res := s.runSealRemediation(req.DryRun)
	if !req.DryRun {
		s.recordSealRemediationEvent(res)
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, res)
}

func sealAuditSummary(a db.SealAudit) string {
	if !a.SealEnabled {
		return "当前进程没有加载平台签名密钥，密封值读不出来；这不是轮换问题，而是回滚到了更早的二进制。"
	}
	if len(a.QueryErrors) > 0 {
		return "自检不完整：" + strings.Join(a.QueryErrors, "；")
	}
	if a.UnreadableTotal == 0 {
		return "没有用当前签名密钥解不开的值。"
	}
	parts := make([]string, 0, len(a.Categories))
	for _, c := range a.Categories {
		if c.Unreadable > 0 {
			parts = append(parts, c.Name+" "+strconv.Itoa(c.Unreadable)+" 条")
		}
	}
	return "共 " + strconv.Itoa(a.UnreadableTotal) + " 条解不开（" + strings.Join(parts, "、") + "），" +
		"平台签名密钥换过；webshell 可由平台重发密钥并重出载荷，其余需要人工补一步。"
}

// runSealRemediation 按条执行补救。它不并发：轮换是小概率事件，条数量级是「几十」，
// 而顺序执行让每一次写库的失败都能精确落到某一条上。
func (s *Server) runSealRemediation(dryRun bool) SealRemediation {
	res := SealRemediation{DryRun: dryRun, Items: []SealRemediationItem{}, FinishedAt: time.Now()}
	pg := s.m.pg
	if pg == nil {
		res.Note = "没有数据库配置来源，无法自检或补救。"
		return res
	}
	res.Audit = pg.AuditSealedSecrets()
	if !res.Audit.SealEnabled {
		res.Note = "当前进程没有加载平台签名密钥：先确认没有用更早的二进制回滚，再重跑自检。"
		return res
	}
	if res.Audit.UnreadableTotal == 0 {
		res.Note = sealAuditSummary(res.Audit)
		return res
	}
	brokenShells := map[int64]bool{}
	for _, id := range res.Audit.UnreadableIDs(db.SealCategoryWebshell) {
		brokenShells[id] = true
	}
	for _, row := range res.Audit.Categories {
		switch row.Key {
		case db.SealCategoryWebshell:
			for _, item := range row.Rows {
				res.addItem(s.reissueWebshell(pg, item, dryRun))
			}
		case db.SealCategoryMemshell:
			for _, item := range row.Rows {
				res.addItem(s.remediateMemshell(pg, row, item, brokenShells, dryRun))
			}
		case db.SealCategoryCredential:
			for _, item := range row.Rows {
				res.addItem(SealRemediationItem{Category: row.Key, ID: item.ID, Label: item.Label,
					Action: row.Fix,
					Next: "这条凭据的旧口令平台已经读不出来，只能由你重新登记一次；" +
						"平台不会猜测、也不会把密文当成口令拿去登录。"})
			}
		case db.SealCategoryLLMKey:
			for _, item := range row.Rows {
				res.addItem(SealRemediationItem{Category: row.Key, ID: item.ID, Label: item.Label,
					Action: row.Fix,
					Next:   "在「系统 → 模型」里重新填写这个 profile 的 API 密钥；在此之前该 profile 不会被当成可用配置。"})
			}
		}
	}
	res.Reissued, res.Remaining = 0, 0
	for _, it := range res.Items {
		if it.Done && it.Error == "" {
			res.Reissued++
			continue
		}
		res.Remaining++
	}
	res.Note = sealRemediationNote(dryRun, res.Reissued, res.Remaining)
	return res
}

func sealRemediationNote(dryRun bool, done, remaining int) string {
	if dryRun {
		return "演练：以上是计划，库里一个字节都没改。去掉 dry_run 才会真正重发密钥与重出载荷。"
	}
	if remaining == 0 {
		return "平台这一半已全部做完。"
	}
	return "平台已重发 " + strconv.Itoa(done) + " 条；剩下 " + strconv.Itoa(remaining) +
		" 条需要人工补一步（每条后面都写了具体做什么），做完前不要把相关结论当成已验证。"
}

func (r *SealRemediation) addItem(item SealRemediationItem) {
	r.Items = append(r.Items, item)
}

// reissueWebshell 给一条 webshell 重新发密钥并重出载荷。
//
// 与「轮换」接口的区别是这里**不能**走原通道：原通道要用旧密钥说话，而旧密钥正是读不出来的
// 那个。所以它做的是「平台侧换新 + 把新载荷交出去」，投放那一步由人或一条活着的通道完成。
func (s *Server) reissueWebshell(pg *db.DB, row db.SealRow, dryRun bool) SealRemediationItem {
	item := SealRemediationItem{Category: db.SealCategoryWebshell, ID: row.ID, Label: row.Label,
		Action: "重新发密钥、重出载荷，并把台账改成「等待重新投放」"}
	if dryRun {
		item.Next = "执行后会把新载荷（文件名、指纹、源码）交给你；覆盖目标上的原文件后点「检测」。"
		return item
	}
	shell, err := pg.GetWebshell(row.ID)
	if err != nil {
		item.Error = "读取这条记录失败：" + err.Error()
		item.Next = "确认记录还在（可能已被删除），再重跑自检。"
		return item
	}
	if !strings.EqualFold(shell.Protocol, scanner.ShellProtocolV2) {
		item.Error = "不是加密 v2 shell，密钥不在平台侧密封"
		item.Next = "旧版 shell 用口令而非平台密封密钥；如需换成 v2，重新导出并投放。"
		return item
	}
	keyVersion := shell.KeyVersion + 1
	payload, sealed, err := s.reissueShellMaterial(shell.ShellType, shell.Source, keyVersion)
	if err != nil {
		item.Error = "生成新载荷失败：" + err.Error()
		item.Next = "修掉上面这个错误后重跑；台账没有被改动。"
		return item
	}
	if err := pg.UpdateWebshellSecret(shell.ID, sealed, payload.Carrier, payload.SHA256, keyVersion); err != nil {
		// 新密钥已经生成但没落库：这条记录仍然是旧的密封值，下一次自检照样会列出来。
		item.Error = "新密钥写入数据库失败：" + err.Error()
		item.Next = "这条保持原样（仍是旧密钥），修好数据库写入后重跑。"
		return item
	}
	note := "签名密钥换过：已重新发密钥（v" + strconv.Itoa(keyVersion) + "），等待重新投放载荷"
	if err := pg.UpdateWebshellState(shell.ID, "needs_reland", "", note); err != nil {
		logSealRemediationWarn("写 shell 状态失败 #%d: %v", shell.ID, err)
	}
	item.Done = true
	item.KeyVersion = keyVersion
	item.PayloadFilename = payload.Filename
	item.PayloadSHA256 = payload.SHA256
	item.Payload = payload.Content
	item.Next = "把 " + payload.Filename + " 覆盖到目标上的原路径，然后点「检测」确认新载荷生效。"
	return item
}

// reissueShellMaterial 按记录来源选对的载荷模板：半持久化（php_prepend）的载荷结构与
// 普通文件壳不同，用错模板等于交出去一个目标上跑不起来的东西。
func (s *Server) reissueShellMaterial(shellType, source string, keyVersion int) (scanner.ShellPayload, string, error) {
	key, err := scanner.GenerateShellKey()
	if err != nil {
		return scanner.ShellPayload{}, "", err
	}
	carrier, err := scanner.GenerateShellCarrier()
	if err != nil {
		return scanner.ShellPayload{}, "", err
	}
	var payload scanner.ShellPayload
	if strings.EqualFold(source, "php_prepend") {
		payload, err = scanner.BuildPHPSemiPersistPayloadV2(key, carrier)
	} else {
		payload, err = scanner.BuildShellPayloadV2(shellType, key, carrier)
	}
	if err != nil {
		return scanner.ShellPayload{}, "", err
	}
	payload.KeyVersion = keyVersion
	sealed, err := sealShellSecret(s.jwtKey, scanner.EncodeShellKey(key))
	if err != nil {
		return scanner.ShellPayload{}, "", err
	}
	return payload, sealed, nil
}

// remediateMemshell 只标注与指路：改库内密钥而不重注入，等于台账声称了一件目标上
// 不存在的事——那个 JVM 里的注入物仍然只认旧密钥。
func (s *Server) remediateMemshell(pg *db.DB, row db.SealCategoryAudit, item db.SealRow, brokenShells map[int64]bool, dryRun bool) SealRemediationItem {
	out := SealRemediationItem{Category: row.Key, ID: item.ID, Label: item.Label,
		Action: "标注为需重新注入，并指出可用的父壳"}
	mem, err := pg.GetJavaMemshell(item.ID)
	if err != nil {
		out.Error = "读取这条内存马记录失败：" + err.Error()
		out.Next = "确认记录还在，再重跑自检。"
		return out
	}
	if mem.WebshellID != nil {
		parentID := *mem.WebshellID
		if brokenShells[parentID] {
			out.Next = "先补救父壳 #" + strconv.FormatInt(parentID, 10) + "（它的密钥也读不出来），再经它重新注入这条内存马。"
		} else {
			out.Next = "父壳 #" + strconv.FormatInt(parentID, 10) + " 可用：在「内存马」页对它重新注入一次即可；" +
				"旧注入物无法用新密钥撤销，撤离时会作为账外残留列出。"
		}
	} else {
		out.Next = "这条没有记录父壳：只能按新壳重新注入一次。"
	}
	if dryRun {
		return out
	}
	note := "签名密钥换过：这条内存马的密钥已读不出来，需重新注入；旧注入物无法用新密钥撤销"
	if err := pg.UpdateJavaMemshellState(mem.ID, mem.Status, mem.LastOutput, note); err != nil {
		logSealRemediationWarn("写内存马备注失败 #%d: %v", mem.ID, err)
	}
	return out
}

func logSealRemediationWarn(format string, args ...any) {
	// 写状态失败不能把整次补救判成失败：新密钥已经在库里，回滚它反而更危险。
	// 这里把它记下来，并在这一条的 Next 里保留人工动作，不谎报「一切正常」。
	log.Printf("[seal][remediation] "+format, args...)
}

// recordSealRemediationEvent 把这次补救写成一条运维事件：轮换的后果不该只活在日志里，
// 而「还剩几条要人做」正是需要被推送到渠道的那句话。
func (s *Server) recordSealRemediationEvent(res SealRemediation) {
	pg := s.m.pg
	if pg == nil || len(res.Items) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(s.ctx), 10*time.Second)
	defer cancel()
	summary := res.Note
	if _, err := pg.AddNotificationEvent(ctx, notify.EventSecretRotation, 0, notify.Snapshot{
		Kind: notify.EventSecretRotation, Name: "签名密钥轮换后的补救",
		VulnClass: "system", Severity: "high", Summary: summary,
	}); err != nil {
		logSealRemediationWarn("写入轮换补救事件失败: %v", err)
	}
}
