package report

import (
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/jingwei/db"
)

// R16：参数来源在报告里的渲染（HTML/DOCX）与「无来源（模型推断）」标记。

func r16Finding() *db.DBFinding {
	f := reproFinding()
	f.Reproduction.ParamSources = []db.ParamSource{
		{Name: "file", Value: "shell.php", Source: "form", URL: "http://lab.example/upload.php", Detail: "multipart 表单 avatar 字段"},
		{Name: "cmd", Value: "id", Source: "query", URL: "http://lab.example/uploads/shell.php?cmd=id"},
		{Name: "role", Value: "admin", Source: "json", Detail: "注册接口响应 JSON 的 data.role", Inferred: true},
	}
	return f
}

func TestFindingsHTMLRendersParamSources(t *testing.T) {
	out := string(FindingsHTML([]*db.DBFinding{r16Finding()}, FindingsHTMLOptions{
		GeneratedAt: time.Date(2026, 11, 12, 10, 0, 0, 0, time.Local),
		ScopeLabel:  "筛选结果（1 条）",
	}))
	for _, want := range []string{
		"参数来源",
		"file",
		"shell.php",
		"form",
		"multipart 表单 avatar 字段",
		"无来源（模型推断）：注册接口响应 JSON 的 data.role",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("HTML report missing %q", want)
		}
	}
}

// 反向验证：没有 param_sources 就不该渲染参数来源段（空台账不是内容）。
func TestFindingsHTMLNoParamSourcesNoTable(t *testing.T) {
	f := reproFinding()
	f.Reproduction.ParamSources = nil
	out := string(FindingsHTML([]*db.DBFinding{f}, FindingsHTMLOptions{
		GeneratedAt: time.Date(2026, 11, 12, 10, 0, 0, 0, time.Local),
		ScopeLabel:  "筛选结果（1 条）",
	}))
	if strings.Contains(out, "参数来源") {
		t.Fatal("no param_sources recorded, nothing should claim 参数来源")
	}
}

func TestFindingsDOCXRendersParamSources(t *testing.T) {
	raw, err := FindingsDOCX([]*db.DBFinding{r16Finding()}, FindingsDOCXOptions{
		GeneratedAt: time.Date(2026, 11, 12, 10, 0, 0, 0, time.Local),
		ScopeLabel:  "筛选结果（1 条）",
	})
	if err != nil {
		t.Fatalf("render docx: %v", err)
	}
	xml := string(readDOCXParts(t, raw)["word/document.xml"])
	for _, want := range []string{
		"参数来源",
		"file = shell.php（form，http://lab.example/upload.php multipart 表单 avatar 字段）",
		"无来源（模型推断）：注册接口响应 JSON 的 data.role",
	} {
		if !strings.Contains(xml, want) {
			t.Fatalf("DOCX missing %q", want)
		}
	}
}
