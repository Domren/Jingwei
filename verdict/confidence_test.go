package verdict

// P10：置信度旁路口径不改 Assess 的二值语义。

import "testing"

func TestAssessConfidence(t *testing.T) {
	cases := []struct {
		name string
		obs  Observation
		want string
	}{
		{
			name: "普通命中仍为 observed",
			obs:  Observation{TemplateID: "sqli", Type: "http", StatusCode: 200, Response: "<div>User ID: 1</div>"},
			want: ConfidenceObserved,
		},
		{
			name: "WAF 改写夹具落 inferred",
			obs:  Observation{TemplateID: "sqli", Type: "http", StatusCode: 200, Response: "WAF_REWRITE_MARKER captcha 人机验证"},
			want: ConfidenceInferred,
		},
		{
			name: "WAF 绕过模板落 inferred",
			obs:  Observation{TemplateID: "waf-bypass", Type: "http", StatusCode: 200, Response: "keyword present"},
			want: ConfidenceInferred,
		},
		{
			name: "5xx 落 failed",
			obs:  Observation{TemplateID: "sqli", Type: "http", StatusCode: 500, Response: "oops"},
			want: ConfidenceFailed,
		},
		{
			name: "HTTP 无响应落 failed",
			obs:  Observation{TemplateID: "sqli", Type: "http", StatusCode: 200, Response: ""},
			want: ConfidenceFailed,
		},
	}
	for _, tc := range cases {
		if got := AssessConfidence(tc.obs); got != tc.want {
			t.Fatalf("%s：AssessConfidence = %q，期望 %q", tc.name, got, tc.want)
		}
	}
}

func TestAssessSemanticsUnchanged(t *testing.T) {
	// 置信度旁路不触碰 Assess：普通命中仍 confirmed，WAF 绕过的 Assess 仍按既有规则。
	if got := Assess(Observation{TemplateID: "sqli", Type: "http", StatusCode: 200, Response: "evidence"}).Verdict; got != Confirmed {
		t.Fatalf("Assess 普通命中应仍为 confirmed，得到 %s", got)
	}
	if got := Assess(Observation{TemplateID: "sqli", Type: "http", StatusCode: 500, Response: "evidence"}).Verdict; got != NeedsReview {
		t.Fatalf("Assess 5xx 应仍为 needs_review，得到 %s", got)
	}
	// WAF 改写夹具虽然置信度是 inferred，Assess 的二值结论不受影响。
	obs := Observation{TemplateID: "sqli", Type: "http", StatusCode: 200, Response: "captcha WAF_REWRITE_MARKER"}
	if AssessConfidence(obs) != ConfidenceInferred {
		t.Fatal("夹具应判 inferred")
	}
	if got := Assess(obs).Verdict; got != Confirmed {
		t.Fatalf("Assess 不应被置信度旁路改写，得到 %s", got)
	}
}
