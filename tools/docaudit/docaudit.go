// Package docaudit 锁住「发版时文档漏改」这一类缺陷：CHANGELOG 与 README 的版本号
// 分别写在不同形状的位置上（一个是 `## [1.6.0] - 日期`，另一个是标题里的
// `## Jingwei 1.5.0`、版本历史里的 `### 1.5.0 — 日期`，外加下载命令、镜像标签、
// ldflags 里散着六处硬编码），靠人眼对，最容易在发版当天只改一半。
//
// 这里只做静态解析：不连网络、不看 git 历史，因此它能在 `go test ./...` 里跑，
// 也能在发版前手动跑一次。判定分两级：
//
//   - error：文档之间互相矛盾（README 记的版本 CHANGELOG 里没有、日期不一致、
//     下载命令与标题版本不是同一个版本、CHANGELOG 版本号不递减）；
//   - warn：文档与「发布状态」对不上（比如 CHANGELOG 最新版标了「未发布」，
//     而 README 已经把它当正式版宣传）。warn 不失败，但发版脚本会把它打出来。
package docaudit

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Version 是 主.次.修订 三段式版本号。本项目正式版只允许这种形状（release.yml 也这么卡）。
type Version struct {
	Major, Minor, Patch int
	Raw                 string
}

var versionRe = regexp.MustCompile(`^(\d+)\.(\d+)\.(\d+)$`)

// ParseVersion 解析 `1.6.0` 形式的版本号；带 v 前缀也接受（README 的下载命令是 v1.5.0）。
func ParseVersion(s string) (Version, bool) {
	s = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(s), "v"))
	m := versionRe.FindStringSubmatch(s)
	if m == nil {
		return Version{}, false
	}
	major, _ := strconv.Atoi(m[1])
	minor, _ := strconv.Atoi(m[2])
	patch, _ := strconv.Atoi(m[3])
	return Version{Major: major, Minor: minor, Patch: patch, Raw: s}, true
}

func (v Version) String() string {
	return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
}

// Compare 返回 -1/0/1。
func (v Version) Compare(o Version) int {
	switch {
	case v.Major != o.Major:
		return sign(v.Major - o.Major)
	case v.Minor != o.Minor:
		return sign(v.Minor - o.Minor)
	case v.Patch != o.Patch:
		return sign(v.Patch - o.Patch)
	}
	return 0
}

func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	}
	return 0
}

// ReleaseEntry 是 CHANGELOG 里的一条版本头。
type ReleaseEntry struct {
	Version Version
	Date    string // YYYY-MM-DD
	// Placeholder 是 `## [Unreleased]` 那个占位节，只会出现在文件最前面。
	Placeholder bool
	// NotReleased 取自版本标题里是否出现「未发布」：1.6.0 在打 tag 之前一直是这个状态。
	// 它与 Placeholder 是两件事——前者是「这一版还没发」，后者是「这里不写版本号」。
	NotReleased bool
	// HasContent 表示版本头与下一条版本头之间有非空正文。
	HasContent bool
	Line       int
	Raw        string
}

var (
	changelogHeadRe = regexp.MustCompile(`^##\s+\[([^\]]+)\](?:\s*-\s*(\d{4}-\d{2}-\d{2}))?(.*)$`)
	readmeBannerRe  = regexp.MustCompile(`^##\s+Jingwei\s+v?(\d+\.\d+\.\d+)\s*$`)
	// 版本历史条目：`### 1.5.0 — 2026-11-05`。分隔符历史上用过 em dash 与 `-`，都认。
	readmeHistoryRe = regexp.MustCompile(`^###\s+v?(\d+\.\d+\.\d+)\s*[—–-]\s*(\d{4}-\d{2}-\d{2})\s*$`)
)

// ParseChangelog 只认 `## [x.y.z] - date` 与 `## [Unreleased]` 两种版本头。
// 其它 `##`（比如文件末尾的链接定义不在标题里）一律忽略：解析器宁可少认，不可乱认。
func ParseChangelog(src string) []ReleaseEntry {
	lines := strings.Split(src, "\n")
	var out []ReleaseEntry
	for i, line := range lines {
		m := changelogHeadRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		raw := strings.TrimSpace(m[1])
		if strings.EqualFold(raw, "Unreleased") {
			out = append(out, ReleaseEntry{Placeholder: true, NotReleased: true, Line: i + 1, Raw: raw})
			continue
		}
		ver, ok := ParseVersion(raw)
		if !ok {
			continue
		}
		out = append(out, ReleaseEntry{
			Version:     ver,
			Date:        m[2],
			NotReleased: strings.Contains(m[3], "未发布"),
			Line:        i + 1,
			Raw:         strings.TrimSpace(line),
		})
	}
	// 标记每条有没有正文：空条目在发版时等于「这版什么都没写」。
	for idx := range out {
		start := out[idx].Line // 0-based 的下一行
		end := len(lines)
		if idx+1 < len(out) {
			end = out[idx+1].Line - 1
		}
		for j := start; j < end && j < len(lines); j++ {
			body := strings.TrimSpace(lines[j])
			if body != "" && !strings.HasPrefix(body, "###") {
				out[idx].HasContent = true
				break
			}
		}
	}
	return out
}

// ReadmeRef 是 README 里一处硬编码的当前版本（下载命令、镜像标签、ldflags 等）。
type ReadmeRef struct {
	Kind    string
	Version Version
	Line    int
	Text    string
}

// ReadmeHistory 是「版本历史」里的一条。
type ReadmeHistory struct {
	Version Version
	Date    string
	Line    int
}

// ReadmeDoc 是 README 里与版本有关的部分。
type ReadmeDoc struct {
	Banner  *Version
	History []ReadmeHistory
	Refs    []ReadmeRef
}

var readmeRefPatterns = []struct {
	kind string
	re   *regexp.Regexp
}{
	{"git clone --branch", regexp.MustCompile(`--branch\s+v(\d+\.\d+\.\d+)\b`)},
	{"Release 下载", regexp.MustCompile(`releases/download/v(\d+\.\d+\.\d+)/`)},
	{"raw.githubusercontent", regexp.MustCompile(`raw\.githubusercontent\.com/[^\s/]+/[^\s/]+/v(\d+\.\d+\.\d+)/`)},
	{"docker pull", regexp.MustCompile(`docker\s+pull\s+ghcr\.io/domren/jingwei:(\d+\.\d+\.\d+)`)},
	{"JINGWEI_IMAGE 默认值", regexp.MustCompile("`JINGWEI_IMAGE`[^`]*`ghcr\\.io/domren/jingwei:(\\d+\\.\\d+\\.\\d+)`")},
	{"ldflags main.version", regexp.MustCompile(`-X\s+main\.version=(\d+\.\d+\.\d+)`)},
	{"docker build -t", regexp.MustCompile(`-t\s+jingwei:(\d+\.\d+\.\d+)\b`)},
}

// ParseReadme 抓三样东西：顶部宣传版本、版本历史、以及散在各处的当前版本引用。
func ParseReadme(src string) ReadmeDoc {
	var doc ReadmeDoc
	lines := strings.Split(src, "\n")
	for i, line := range lines {
		if m := readmeBannerRe.FindStringSubmatch(line); m != nil {
			if v, ok := ParseVersion(m[1]); ok && doc.Banner == nil {
				doc.Banner = &v
			}
			continue
		}
		if m := readmeHistoryRe.FindStringSubmatch(line); m != nil {
			if v, ok := ParseVersion(m[1]); ok {
				doc.History = append(doc.History, ReadmeHistory{Version: v, Date: m[2], Line: i + 1})
			}
			continue
		}
		for _, p := range readmeRefPatterns {
			for _, m := range p.re.FindAllStringSubmatch(line, -1) {
				if v, ok := ParseVersion(m[1]); ok {
					doc.Refs = append(doc.Refs, ReadmeRef{Kind: p.kind, Version: v, Line: i + 1, Text: strings.TrimSpace(line)})
				}
			}
		}
	}
	return doc
}

// Problem 是一条审计结论。Level 为 "error" 时调用方应让检查失败。
type Problem struct {
	Level   string
	Where   string
	Message string
}

func (p Problem) String() string {
	return fmt.Sprintf("[%s] %s: %s", p.Level, p.Where, p.Message)
}

// Check 把两份文档放在一起对。它只在「文档之间互相矛盾」时报 error；
// 「文档与发布状态不一致」报 warn，避免未发布的版本把日常测试打红。
func Check(changelogSrc, readmeSrc string) []Problem {
	var problems []Problem
	addErr := func(where, format string, args ...any) {
		problems = append(problems, Problem{Level: "error", Where: where, Message: fmt.Sprintf(format, args...)})
	}
	addWarn := func(where, format string, args ...any) {
		problems = append(problems, Problem{Level: "warn", Where: where, Message: fmt.Sprintf(format, args...)})
	}

	entries := ParseChangelog(changelogSrc)
	if len(entries) == 0 {
		addErr("CHANGELOG.md", "没有解析到任何 `## [x.y.z] - 日期` 版本头")
		return problems
	}

	// 1. CHANGELOG 自身的形状：版本唯一、严格递减、日期合法、有空正文。
	seen := map[string]int{}
	for i, e := range entries {
		if e.Placeholder {
			if i != 0 {
				addErr(fmt.Sprintf("CHANGELOG.md:%d", e.Line), "`[Unreleased]` 只能出现在第一条，当前在第 %d 条", i+1)
			}
			continue
		}
		key := e.Version.String()
		if prev, dup := seen[key]; dup {
			addErr(fmt.Sprintf("CHANGELOG.md:%d", e.Line), "版本 %s 重复出现（另一处在第 %d 行）", key, prev)
		}
		seen[key] = e.Line
		if e.Date == "" {
			addErr(fmt.Sprintf("CHANGELOG.md:%d", e.Line), "版本 %s 的标题没有 - YYYY-MM-DD 日期", key)
		}
		if !e.HasContent {
			addErr(fmt.Sprintf("CHANGELOG.md:%d", e.Line), "版本 %s 的条目没有正文", key)
		}
		if i > 0 && !entries[i-1].Placeholder {
			if d := entries[i-1].Version.Compare(e.Version); d <= 0 {
				addErr(fmt.Sprintf("CHANGELOG.md:%d", e.Line), "版本顺序错误：%s 不应排在 %s 之后",
					key, entries[i-1].Version.String())
			}
		}
	}

	// 2. README 的版本历史必须能在 CHANGELOG 里找到，且日期一致。
	byVersion := map[string]ReleaseEntry{}
	for _, e := range entries {
		if !e.Placeholder {
			byVersion[e.Version.String()] = e
		}
	}
	doc := ParseReadme(readmeSrc)
	if doc.Banner == nil {
		addErr("README.md", "没有找到 `## Jingwei x.y.z` 标题，无法确定当前宣传版本")
	}
	for i, h := range doc.History {
		key := h.Version.String()
		e, ok := byVersion[key]
		if !ok {
			addErr(fmt.Sprintf("README.md:%d", h.Line), "版本历史里的 %s 在 CHANGELOG 中不存在", key)
			continue
		}
		if e.Date != "" && h.Date != e.Date {
			addErr(fmt.Sprintf("README.md:%d", h.Line), "版本 %s 的日期与 CHANGELOG 不一致：README %s / CHANGELOG %s",
				key, h.Date, e.Date)
		}
		if i > 0 {
			if d := doc.History[i-1].Version.Compare(h.Version); d <= 0 {
				addErr(fmt.Sprintf("README.md:%d", h.Line), "版本历史顺序错误：%s 不应排在 %s 之后",
					key, doc.History[i-1].Version.String())
			}
		}
	}
	if doc.Banner != nil && len(doc.History) > 0 {
		if d := doc.Banner.Compare(doc.History[0].Version); d != 0 {
			addErr("README.md", "标题版本 %s 与版本历史最新一条 %s 不一致",
				doc.Banner.String(), doc.History[0].Version.String())
		}
	}

	// 3. 散落的硬编码必须与标题版本一致：这是发版当天最容易漏的一半。
	if doc.Banner != nil {
		for _, ref := range doc.Refs {
			if d := ref.Version.Compare(*doc.Banner); d != 0 {
				addErr(fmt.Sprintf("README.md:%d", ref.Line), "%s 写着 %s，标题版本是 %s",
					ref.Kind, ref.Version.String(), doc.Banner.String())
			}
		}
		if len(doc.Refs) == 0 {
			addWarn("README.md", "没有找到任何当前版本引用（下载命令 / 镜像标签 / ldflags），检查是否漏写")
		}
	}

	// 4. 发布状态：CHANGELOG 里比标题新的版本必须是「未发布」；
	//    而标了「未发布」的版本若已被 README 当成正式版，就是发版时忘了摘标记。
	if doc.Banner != nil {
		for _, e := range entries {
			if e.Placeholder {
				continue
			}
			switch d := e.Version.Compare(*doc.Banner); {
			case d > 0 && !e.NotReleased:
				addWarn(fmt.Sprintf("CHANGELOG.md:%d", e.Line),
					"版本 %s 比 README 的 %s 新，但标题里没有写「未发布」", e.Version.String(), doc.Banner.String())
			case d == 0 && e.NotReleased:
				addErr(fmt.Sprintf("CHANGELOG.md:%d", e.Line),
					"README 已把 %s 当正式版，CHANGELOG 标题却仍标「未发布」", e.Version.String())
			}
		}
	}
	return problems
}

// Errors 过滤出 error 级结论。
func Errors(problems []Problem) []Problem {
	out := make([]Problem, 0, len(problems))
	for _, p := range problems {
		if p.Level == "error" {
			out = append(out, p)
		}
	}
	return out
}
