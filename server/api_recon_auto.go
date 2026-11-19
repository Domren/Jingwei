package server

// P6 · api-recon 自动化升级：扫描完成后自动触发静态收尾，不再等 agent 手动
// 加载 skill。本文件提供 host 工具 auto_api_recon：复用平台既有 skill 加载器
// （skill.LoadDir）确认 api-recon 可见，返回自动化执行计划与去重后端点。
//
// 去重口径与 scripts/js_denoise_extract.py 保持一致（归一化路径），因此手动
// 与自动两路产出一致；1.5.0 的目录枚举 / JS-URL 提取结果作为既有集合传入。

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/Autumn-27/norma/skill"
	actool "github.com/Autumn-27/norma/tool"
)

// APIReconAutoPlan 是自动触发的执行计划（纯数据，可写夹具）。
type APIReconAutoPlan struct {
	Target         string   `json:"target"`
	SkillName      string   `json:"skill_name"`
	Steps          []string `json:"steps"`
	EndpointsAuto  []string `json:"endpoints_auto"`
	DedupedAgainst int      `json:"deduped_against"`
	SkillAvailable bool     `json:"skill_available"`
}

// normalizeReconPath 与 Python 脚本的 normalize_path 同口径：去协议/主机/查询串/
// hash、路径参数归一、去尾斜杠。用于手动与自动两路对齐。
func normalizeReconPath(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	if u, err := url.Parse(s); err == nil && u.Host != "" && u.Path != "" {
		s = u.Path
	}
	if i := strings.IndexAny(s, "?#"); i >= 0 {
		s = s[:i]
	}
	s = strings.TrimRight(s, "/")
	return s
}

// BuildAPIReconAutoPlan 构造自动化计划。jsEndpoints 来自新提取，existing 来自
// 1.5.0 目录枚举 / JS-URL 提取；返回按路径排序的确定性结果。
func BuildAPIReconAutoPlan(target string, jsEndpoints, existing []string) APIReconAutoPlan {
	deduped := make(map[string]struct{}, len(existing))
	for _, e := range existing {
		if p := normalizeReconPath(e); p != "" {
			deduped[p] = struct{}{}
		}
	}
	added := make(map[string]struct{}, len(jsEndpoints))
	for _, e := range jsEndpoints {
		p := normalizeReconPath(e)
		if p == "" {
			continue
		}
		if _, seen := deduped[p]; seen {
			continue
		}
		added[p] = struct{}{}
	}
	auto := make([]string, 0, len(added))
	for p := range added {
		auto = append(auto, p)
	}
	sort.Strings(auto)
	return APIReconAutoPlan{
		Target:         strings.TrimSpace(target),
		SkillName:      "api-recon",
		EndpointsAuto:  auto,
		DedupedAgainst: len(deduped),
		Steps: []string{
			"scripts/js_denoise_extract.py <JSDIR|JSFILE...> --existing <1.5.0-result> --out api_auto.json",
			"merge endpoints_auto with 1.5.0 dir_enum / js_urls (dedupe by normalized path)",
			"scripts/build_perm_tree.py <JSDIR> <OUTDIR>  # 权限树还原（静态层）",
		},
	}
}

// apiReconSkillAvailable 复用平台既有 skill 加载器确认 skill 可见。
func (s *Server) apiReconSkillAvailable() bool {
	if s == nil || s.skillDir == "" {
		return false
	}
	reg, err := skill.LoadDir(s.skillDir)
	if err != nil || reg == nil {
		return false
	}
	for _, sk := range reg.List() {
		if sk.Dir != "" && hasDirName(sk.Dir, "api-recon") {
			return true
		}
	}
	return false
}

func hasDirName(dir, want string) bool {
	base := dir
	if i := strings.LastIndexAny(base, `/\`); i >= 0 {
		base = base[i+1:]
	}
	return strings.EqualFold(base, want)
}

// toolAutoAPIRecon 是注册给编排 agent / 扫描完成钩子的 host 工具。
func (s *Server) toolAutoAPIRecon() actool.CoreTool {
	return roTool("auto_api_recon",
		"扫描完成后自动触发 api-recon 静态收尾：JS 去噪、端点/参数提取、权限树还原，并与 1.5.0 目录枚举/JS-URL 结果去重。复用平台既有 skill 加载器，无需手动加载 skill。",
		objSchema(map[string]any{
			"target":       strParam("目标 URL 或域名"),
			"js_endpoints": map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "新提取的 JS 端点"},
			"existing":     map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "1.5.0 目录枚举 / JS-URL 既有结果，用于去重"},
		}, "target"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Target      string   `json:"target"`
				JSEndpoints []string `json:"js_endpoints"`
				Existing    []string `json:"existing"`
			}
			_ = json.Unmarshal(in, &a)
			if strings.TrimSpace(a.Target) == "" {
				return actool.Errorf("target 为必填"), nil
			}
			plan := BuildAPIReconAutoPlan(a.Target, a.JSEndpoints, a.Existing)
			plan.SkillAvailable = s.apiReconSkillAvailable()
			if !plan.SkillAvailable {
				return actool.Errorf(fmt.Sprintf("api-recon skill 不可见（skillDir=%s）", s.skillDir)), nil
			}
			return jsonResult(plan)
		})
}
