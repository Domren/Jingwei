package docaudit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseChangelog(t *testing.T) {
	src := `# 更新日志

## [Unreleased]

（暂无）

## [1.6.0] - 2026-11-09（未发布：等授权）

### 新增

- 一条正文

## [1.5.0] - 2026-11-05

- 上一版正文
`
	got := ParseChangelog(src)
	if len(got) != 3 {
		t.Fatalf("解析到 %d 条版本头，want 3: %+v", len(got), got)
	}
	if !got[0].Placeholder || got[0].Line != 3 {
		t.Fatalf("第一条应当是第 3 行的 Unreleased: %+v", got[0])
	}
	if got[1].Version.String() != "1.6.0" || got[1].Date != "2026-11-09" || !got[1].NotReleased {
		t.Fatalf("1.6.0 解析错误: %+v", got[1])
	}
	if !got[1].HasContent {
		t.Fatal("1.6.0 有正文，HasContent 应当是 true")
	}
	if got[2].Version.String() != "1.5.0" || got[2].NotReleased || !got[2].HasContent {
		t.Fatalf("1.5.0 解析错误: %+v", got[2])
	}
}

func TestParseReadme(t *testing.T) {
	src := `# Jingwei（精卫）

## Jingwei 1.5.0

## 版本历史

### 1.5.0 — 2026-11-05

- 正文

### 1.4.2 — 2026-11-04

` + "```bash\ngit clone --depth 1 --branch v1.5.0 https://example/repo.git\n" +
		"docker pull ghcr.io/domren/jingwei:1.5.0\n" +
		"go build -ldflags \"-s -w -X main.version=1.5.0\"\n```\n" + `
| ` + "`JINGWEI_IMAGE`" + ` | 否 | 默认 ` + "`ghcr.io/domren/jingwei:1.5.0`" + ` |
`
	doc := ParseReadme(src)
	if doc.Banner == nil || doc.Banner.String() != "1.5.0" {
		t.Fatalf("banner = %+v", doc.Banner)
	}
	if len(doc.History) != 2 || doc.History[0].Version.String() != "1.5.0" || doc.History[0].Date != "2026-11-05" {
		t.Fatalf("版本历史 = %+v", doc.History)
	}
	kinds := map[string]int{}
	for _, r := range doc.Refs {
		kinds[r.Kind]++
	}
	for _, want := range []string{"git clone --branch", "docker pull", "ldflags main.version", "JINGWEI_IMAGE 默认值"} {
		if kinds[want] == 0 {
			t.Fatalf("没有识别出 %q 这类引用，已识别：%v", want, kinds)
		}
	}
}

// TestCheckCleanBaseline 是所有规则都满足的基线：有它才能证明下面每条用例的
// error 是被对应规则抓到的，而不是基线本身就不干净。
func TestCheckCleanBaseline(t *testing.T) {
	changelog := `## [Unreleased]

（暂无）

## [1.6.0] - 2026-11-09（未发布：等授权）

- 正文

## [1.5.0] - 2026-11-05

- 正文
`
	readme := `## Jingwei 1.5.0

## 版本历史

### 1.5.0 — 2026-11-05

` + "```bash\ndocker pull ghcr.io/domren/jingwei:1.5.0\ngit clone --branch v1.5.0 x\n" +
		"go build -ldflags \"-X main.version=1.5.0\"\n```\n" +
		"| `JINGWEI_IMAGE` | 否 | 默认 `ghcr.io/domren/jingwei:1.5.0` |\n"
	if errs := Errors(Check(changelog, readme)); len(errs) != 0 {
		t.Fatalf("基线应当干净，实际 %d 条 error: %v", len(errs), errs)
	}
}

func TestCheckRuleTable(t *testing.T) {
	baseChangelog := `## [Unreleased]

（暂无）

## [1.6.0] - 2026-11-09（未发布：等授权）

- 正文

## [1.5.0] - 2026-11-05

- 正文
`
	baseReadme := `## Jingwei 1.5.0

## 版本历史

### 1.5.0 — 2026-11-05

` + "```bash\ndocker pull ghcr.io/domren/jingwei:1.5.0\n```\n" +
		"| `JINGWEI_IMAGE` | 否 | 默认 `ghcr.io/domren/jingwei:1.5.0` |\n"

	cases := []struct {
		name      string
		changelog string
		readme    string
		want      string // error 里必须出现这段文字
	}{
		{
			name:      "README 版本历史里的版本 CHANGELOG 没有",
			changelog: baseChangelog,
			readme:    strings.Replace(baseReadme, "### 1.5.0 — 2026-11-05", "### 1.4.2 — 2026-11-04", 1),
			want:      "在 CHANGELOG 中不存在",
		},
		{
			name:      "日期不一致",
			changelog: baseChangelog,
			readme:    strings.Replace(baseReadme, "### 1.5.0 — 2026-11-05", "### 1.5.0 — 2026-11-06", 1),
			want:      "日期与 CHANGELOG 不一致",
		},
		{
			name:      "下载命令还是旧版本",
			changelog: baseChangelog,
			readme:    strings.Replace(baseReadme, "docker pull ghcr.io/domren/jingwei:1.5.0", "docker pull ghcr.io/domren/jingwei:1.4.2", 1),
			want:      "标题版本是 1.5.0",
		},
		{
			name:      "标题版本与版本历史首条不一致",
			changelog: baseChangelog,
			readme:    strings.Replace(baseReadme, "## Jingwei 1.5.0", "## Jingwei 1.6.0", 1),
			want:      "不一致",
		},
		{
			name:      "CHANGELOG 版本号不递减",
			changelog: strings.Replace(baseChangelog, "## [1.6.0] - 2026-11-09（未发布：等授权）", "## [1.4.0] - 2026-11-09", 1),
			readme:    baseReadme,
			want:      "版本顺序错误",
		},
		{
			name:      "条目没有正文",
			changelog: strings.Replace(baseChangelog, "- 正文\n\n## [1.5.0]", "\n## [1.5.0]", 1),
			readme:    baseReadme,
			want:      "没有正文",
		},
		{
			name:      "已当正式版发布但 CHANGELOG 还标未发布",
			changelog: baseChangelog,
			readme:    strings.ReplaceAll(baseReadme, "1.5.0", "1.6.0"),
			want:      "仍标「未发布」",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			errs := Errors(Check(c.changelog, c.readme))
			if len(errs) == 0 {
				t.Fatalf("应当报 error，实际干净")
			}
			for _, e := range errs {
				if strings.Contains(e.Message, c.want) {
					return
				}
			}
			t.Fatalf("error 里没有 %q：%v", c.want, errs)
		})
	}
}

// TestRepoDocsConsistent 是本包存在的理由：拿仓库里真实的两份文档对一遍。
// 只允许 warn（比如 CHANGELOG 有比 README 新的未发布版本），error 一律失败。
func TestRepoDocsConsistent(t *testing.T) {
	root := filepath.Join("..", "..")
	changelog, err := os.ReadFile(filepath.Join(root, "CHANGELOG.md"))
	if err != nil {
		t.Fatalf("读 CHANGELOG.md: %v", err)
	}
	readme, err := os.ReadFile(filepath.Join(root, "README.md"))
	if err != nil {
		t.Fatalf("读 README.md: %v", err)
	}
	problems := Check(string(changelog), string(readme))
	for _, p := range problems {
		t.Log(p.String())
	}
	if errs := Errors(problems); len(errs) > 0 {
		t.Fatalf("CHANGELOG 与 README 有 %d 处矛盾（发版前必须修掉）：\n%v", len(errs), errs)
	}
}
