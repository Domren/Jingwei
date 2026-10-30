package db

import "testing"

func reproBinding(position int, id, method, url string) FindingTrafficBinding {
	return FindingTrafficBinding{
		ID:         int64(position + 1),
		SnapshotID: id,
		Position:   position,
		Snapshot:   TrafficEvidenceSnapshot{ID: id, Method: method, URL: url},
	}
}

func TestResolveReproStepsMatchesMethodAndPath(t *testing.T) {
	bindings := []FindingTrafficBinding{
		reproBinding(0, "s1", "POST", "http://lab.example/upload.php"),
		reproBinding(1, "s2", "GET", "http://lab.example/uploads/shell.php?cmd=id"),
	}
	repro := &Reproduction{Steps: []ReproStep{
		{Request: "POST /upload.php HTTP/1.1\r\nHost: lab.example\r\n\r\nmultipart body"},
		{Request: "curl -s 'http://lab.example/uploads/shell.php?cmd=id'"},
	}}
	if !ResolveReproSteps(repro, bindings) {
		t.Fatal("expected steps to resolve")
	}
	if repro.Steps[0].SnapshotID != "s1" || repro.Steps[1].SnapshotID != "s2" {
		t.Fatalf("unexpected links: %q %q", repro.Steps[0].SnapshotID, repro.Steps[1].SnapshotID)
	}
	if repro.Steps[0].Match != "request" {
		t.Fatalf("expected request match, got %q", repro.Steps[0].Match)
	}
}

// 同一个接口被打了两次时，步骤必须按先后顺序各取一条：第 1 步最早，第 2 步紧随其后。
func TestResolveReproStepsRespectsOrderForRepeatedEndpoint(t *testing.T) {
	bindings := []FindingTrafficBinding{
		reproBinding(0, "first", "GET", "http://lab.example/vul.php?id=1"),
		reproBinding(1, "second", "GET", "http://lab.example/vul.php?id=1"),
	}
	repro := &Reproduction{Steps: []ReproStep{
		{Request: "GET /vul.php?id=1 HTTP/1.1"},
		{Request: "GET /vul.php?id=1 HTTP/1.1"},
	}}
	ResolveReproSteps(repro, bindings)
	if repro.Steps[0].SnapshotID != "first" || repro.Steps[1].SnapshotID != "second" {
		t.Fatalf("order not respected: %q %q", repro.Steps[0].SnapshotID, repro.Steps[1].SnapshotID)
	}
}

// 绑定 URL 带站点前缀时（/pikachu/vul/x.php vs /vul/x.php），仍应命中真实接口。
func TestResolveReproStepsAcceptsSuffixPath(t *testing.T) {
	bindings := []FindingTrafficBinding{
		reproBinding(0, "s1", "GET", "http://lab:8080/pikachu/vul/sqli/sqli_str.php?id=1"),
	}
	repro := &Reproduction{Steps: []ReproStep{{Request: "GET /vul/sqli/sqli_str.php?id=1 HTTP/1.1"}}}
	ResolveReproSteps(repro, bindings)
	if repro.Steps[0].SnapshotID != "s1" {
		t.Fatalf("suffix path not matched, got %q", repro.Steps[0].SnapshotID)
	}
}

// 步骤数量与绑定数量一致且请求无法解析时，按顺序一一对应（唯一安全的猜法）。
func TestResolveReproStepsPositionalFallbackWhenCountsMatch(t *testing.T) {
	bindings := []FindingTrafficBinding{
		reproBinding(0, "s1", "GET", "http://lab.example/a"),
		reproBinding(1, "s2", "GET", "http://lab.example/b"),
	}
	repro := &Reproduction{Steps: []ReproStep{
		{Request: "PING\r\n"},
		{Request: "INFO\r\n"},
	}}
	ResolveReproSteps(repro, bindings)
	if repro.Steps[0].SnapshotID != "s1" || repro.Steps[1].SnapshotID != "s2" {
		t.Fatalf("positional fallback failed: %q %q", repro.Steps[0].SnapshotID, repro.Steps[1].SnapshotID)
	}
	if repro.Steps[0].Match != "position" {
		t.Fatalf("expected position match, got %q", repro.Steps[0].Match)
	}
}

// 数量不一致又没有可解析请求时必须留空——宁可没有链接，也不能给出错误的报文。
func TestResolveReproStepsLeavesUnmatchedEmpty(t *testing.T) {
	bindings := []FindingTrafficBinding{
		reproBinding(0, "s1", "GET", "http://lab.example/a"),
	}
	repro := &Reproduction{Steps: []ReproStep{
		{Request: "PING\r\n"},
		{Request: "INFO\r\n"},
	}}
	ResolveReproSteps(repro, bindings)
	for i, st := range repro.Steps {
		if st.SnapshotID != "" {
			t.Fatalf("step %d should stay unlinked, got %q", i+1, st.SnapshotID)
		}
	}
}

func TestParseReproductionRejectsEmptyShapes(t *testing.T) {
	for _, raw := range []string{"", "null", "{}", `{"steps":[]}`} {
		if r := ParseReproduction(raw); r != nil {
			t.Fatalf("expected nil for %q, got %+v", raw, r)
		}
	}
	r := ParseReproduction(`{"entry_point":"POST /a","steps":[{"request":"x","expected":"e"}]}`)
	if r == nil || len(r.Steps) != 1 || r.EntryPoint != "POST /a" {
		t.Fatalf("unexpected parse result: %+v", r)
	}
}

func TestParseStepRequestFromCommand(t *testing.T) {
	method, path := ParseStepRequest("curl -X PUT 'http://lab.example/api/item/1' -d 'x=1'")
	if method != "PUT" || path != "/api/item/1" {
		t.Fatalf("got %q %q", method, path)
	}
	method, path = ParseStepRequest("curl -s http://lab.example/login -d 'u=a&p=b'")
	if method != "POST" || path != "/login" {
		t.Fatalf("form post should be POST, got %q %q", method, path)
	}
}
