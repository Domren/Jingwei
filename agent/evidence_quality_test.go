package agent

import "testing"

func TestValidateFindingEvidence(t *testing.T) {
	// 占位指向一律拒收
	for _, bad := range []string{
		"真实抓包见取证截图",
		"详见报告",
		"见取证截图。",
		"同上",
		"略",
		"N/A",
		"",
		"   ",
	} {
		if err := validateFindingEvidence(bad); err == nil {
			t.Fatalf("占位证据 %q 应被拒收", bad)
		}
	}

	// 实质内容要能过
	good := "GET /vul/sqli/sqli_x.php?name=kobe'&submit=1 HTTP/1.1\nHost: pikachu-lab\n\n响应：HTTP/1.1 200 OK，正文回显 You have an error in your SQL syntax ... near ''kobe'') at line 1。name 参数存在报错型 SQL 注入。"
	if err := validateFindingEvidence(good); err != nil {
		t.Fatalf("实质证据被误拒: %v", err)
	}

	// 太短也不行
	if err := validateFindingEvidence("有 SQL 注入"); err == nil {
		t.Fatal("过短证据应被拒收")
	}
}
