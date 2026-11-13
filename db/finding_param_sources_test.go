package db

import "testing"

// R16：参数来源的校验与归一。

func TestNormalizeParamSources(t *testing.T) {
	r := &Reproduction{ParamSources: []ParamSource{
		{Name: "file", Source: "path", URL: "http://x/download/:file"},                                   // 合规
		{Name: "token", Source: "JSON", Detail: "POST /api/login 响应 JSON 的 data.token", Inferred: false}, // 大小写归一 + 仅 detail 合规
		{Name: "cmd", Source: "form", Inferred: true, URL: "http://x/f"},                                 // 推断条目清空 url
	}}
	if err := r.NormalizeParamSources(); err != nil {
		t.Fatal(err)
	}
	if r.ParamSources[1].Source != "json" {
		t.Fatalf("source must normalize to lowercase, got %q", r.ParamSources[1].Source)
	}
	if r.ParamSources[2].URL != "" {
		t.Fatalf("inferred entry must not keep a url（无来源是台账语义）, got %q", r.ParamSources[2].URL)
	}

	// 反向验证：非推断条目既无 url 也无 detail → 拒绝（否则参数来源台账是摆设）。
	bad := &Reproduction{ParamSources: []ParamSource{{Name: "id", Source: "query"}}}
	if err := bad.NormalizeParamSources(); err == nil {
		t.Fatal("来源缺失且未标 inferred 必须被拒绝")
	}
	// source 枚举外 → 拒绝
	bad2 := &Reproduction{ParamSources: []ParamSource{{Name: "id", Source: "guess", URL: "http://x"}}}
	if err := bad2.NormalizeParamSources(); err == nil {
		t.Fatal("source 枚举外必须被拒绝")
	}
	// name 缺失 → 拒绝
	bad3 := &Reproduction{ParamSources: []ParamSource{{Source: "form", URL: "http://x"}}}
	if err := bad3.NormalizeParamSources(); err == nil {
		t.Fatal("name 缺失必须被拒绝")
	}
}

// Normalize（void）丢全空条目并归一字段，再交给 NormalizeParamSources 校验。
func TestReproductionNormalizeTrimsParamSources(t *testing.T) {
	r := &Reproduction{ParamSources: []ParamSource{
		{Name: "  file ", Source: " PATH ", URL: " http://x/ "},
		{Name: "", Value: ""}, // 全空条目被丢
	}}
	r.Normalize()
	if len(r.ParamSources) != 1 {
		t.Fatalf("empty entry must be dropped, got %d", len(r.ParamSources))
	}
	if r.ParamSources[0].Name != "file" || r.ParamSources[0].Source != "path" || r.ParamSources[0].URL != "http://x/" {
		t.Fatalf("trim/normalize failed: %+v", r.ParamSources[0])
	}
	if err := r.NormalizeParamSources(); err != nil {
		t.Fatal(err)
	}
}
