// Package envaudit 锁住一类反复出现的部署缺陷：代码里 os.Getenv 读的开关，
// compose 用白名单式注入却没带上，操作员在 .env 里配了也进不了容器。
// JINGWEI_PIVOT_SERVER 与 JINGWEI_LLM_CALL_TIMEOUT 都踩过这个坑（后者甚至写在 DEPLOY 的排障建议里）。
package envaudit

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"
)

// 这些变量不需要 compose 注入，理由必须写在这里，否则审计不放行。
var exemptFromCompose = map[string]string{
	"PATH":                            "系统变量，只用于与容器内 PATH 比对（intercept/python_modules.go）",
	"NEW_PG_DSN":                      "cmd/pocimport 的一次性迁移工具参数，在容器外由操作员提供",
	"OLD_PG_DSN":                      "cmd/pocimport 的一次性迁移工具参数，在容器外由操作员提供",
	"JINGWEI_SHOT_BROWSER":            "取证截图的浏览器路径，镜像内已内置，只有本机开发才需要覆盖",
	"JINGWEI_OUTBOUND_UA":             "出站 UA 口径：留空=内置浏览器串、none=不发 UA 头；默认值就是正确行为，不需要每台部署各配一份",
	"JINGWEI_LLM_FIRST_EVENT_TIMEOUT": "LLM 首帧超时：默认 45s 已合理，用于在代理/中转端故障时快速判卡；不需要 compose 注入",
}

// 两份 compose 都必须带上这些键；.env.example 必须给出注释与留空默认。
var composeFiles = []string{"docker-compose.yml", "deploy/docker-compose.yml"}

func repoRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("拿不到当前测试文件路径")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", ".."))
}

func goFilesWithoutTests(t *testing.T, root string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "dist", "build", ".next", "testdata", "web":
				if d.Name() == "web" {
					return filepath.SkipDir // 前端不是 Go 代码，整棵跳过
				}
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go") {
			out = append(out, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("遍历源码失败: %v", err)
	}
	return out
}

// TestRuntimeEnvVarsAreInjectable 要求：源码（非测试文件）里读的每一个环境变量，
// 要么在豁免表里写明理由，要么能在两份 compose 与 .env.example 里找到。
func TestRuntimeEnvVarsAreInjectable(t *testing.T) {
	root := repoRoot(t)

	pattern := regexp.MustCompile(`Getenv\("([A-Z][A-Z0-9_]*)"`)
	declared := map[string][]string{}
	for _, f := range goFilesWithoutTests(t, root) {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("读 %s: %v", f, err)
		}
		for _, m := range pattern.FindAllStringSubmatch(string(b), -1) {
			declared[m[1]] = append(declared[m[1]], strings.TrimPrefix(f, root+string(os.PathSeparator)))
		}
	}
	if len(declared) == 0 {
		t.Fatal("一个环境变量都没扫到，八成是路径或正则坏了")
	}
	// 防自己失效：遍历或正则坏掉时会扫出空集合，那样上面的断言就形同虚设。
	for _, must := range []string{"JINGWEI_PG_DSN", "JINGWEI_LLM_MODEL", "JINGWEI_PIVOT_SERVER"} {
		if _, ok := declared[must]; !ok {
			t.Fatalf("源码里一定在读 %s，扫不到说明本测试的遍历范围坏了", must)
		}
	}

	contents := map[string]string{}
	for _, rel := range composeFiles {
		b, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			t.Fatalf("读 %s: %v", rel, err)
		}
		contents[rel] = string(b)
	}
	example, err := os.ReadFile(filepath.Join(root, ".env.example"))
	if err != nil {
		t.Fatalf("读 .env.example: %v", err)
	}

	var missing []string
	names := make([]string, 0, len(declared))
	for name := range declared {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		if _, ok := exemptFromCompose[name]; ok {
			continue
		}
		var absent []string
		for _, rel := range composeFiles {
			// 必须匹配成 YAML 键（行首缩进 + 名字 + 冒号）。
			// 不能用 strings.Contains(name+":")——`${NAME:-}` 里就含这个子串，断言会永远为真。
			keyAtLineStart := regexp.MustCompile(`(?m)^[ \t]*` + name + `:[ \t]`)
			if !keyAtLineStart.MatchString(contents[rel]) {
				absent = append(absent, rel)
			}
		}
		if !regexp.MustCompile(`(?m)^` + name + `=`).Match(example) {
			absent = append(absent, ".env.example")
		}
		if len(absent) > 0 {
			missing = append(missing, name+" 缺于 "+strings.Join(absent, ", ")+"（读于 "+strings.Join(declared[name], ", ")+"）")
		}
	}
	if len(missing) > 0 {
		t.Errorf("以下运行时开关无法通过部署配置注入，操作员在 .env 里写了也没用：\n  %s",
			strings.Join(missing, "\n  "))
	}
}

// TestExemptEntriesStayTrue 防止豁免表变成垃圾桶：理由写进去的变量，必须真的还在源码里被读。
func TestExemptEntriesStayTrue(t *testing.T) {
	root := repoRoot(t)
	present := map[string]bool{}
	for _, f := range goFilesWithoutTests(t, root) {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		for _, m := range regexp.MustCompile(`Getenv\("([A-Z][A-Z0-9_]*)"`).FindAllStringSubmatch(string(b), -1) {
			present[m[1]] = true
		}
	}
	for name := range exemptFromCompose {
		if !present[name] {
			t.Errorf("豁免表里的 %s 已经没有源码在读它，请从豁免表删掉", name)
		}
	}
}
