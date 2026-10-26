package scanner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DalfoxOptions bounds one dalfox run. Requests are capped through Workers,
// RateLimit and MaxPayloadsPerParam so one XSS verification cannot turn into a
// mass scan.
type DalfoxOptions struct {
	Target              string
	Method              string
	Data                string // request body for POST-style injection points
	Params              []string
	Cookie              string
	Headers             []string
	Workers             int
	RateLimit           int
	TimeoutSeconds      int
	DelayMS             int
	ScanTimeoutSeconds  int
	MaxPayloadsPerParam int
	Stored              bool   // stored-XSS mode
	StoredURL           string // page that renders the stored payload
	BlindURL            string // blind XSS callback, no external OAST by default
	Proxy               string
	ScopeHost           string // only this host may be requested
	WallSeconds         int
}

// DalfoxFinding is one XSS point dalfox verified.
type DalfoxFinding struct {
	Param           string `json:"param"`
	Location        string `json:"location"`
	Method          string `json:"method"`
	Payload         string `json:"payload"`
	URL             string `json:"data"`
	Type            string `json:"type"`
	TypeDescription string `json:"type_description"`
	Severity        string `json:"severity"`
	Confidence      string `json:"confidence"`
	ConfidenceWhy   string `json:"confidence_reason"`
	CWE             string `json:"cwe"`
	InjectType      string `json:"inject_type"`
	Detection       string `json:"detection_method"`
	Evidence        string `json:"evidence"`
	Message         string `json:"message_str"`
	Request         string `json:"request"`
	Response        string `json:"response"`
}

// DalfoxRun is the outcome of one dalfox invocation.
type DalfoxRun struct {
	Findings       []DalfoxFinding
	Blockers       []DalfoxBlocker
	Version        string
	FailedRequests int
	Incomplete     bool
	Log            string
	Elapsed        time.Duration
	TimedOut       bool
	Missing        bool
	Err            error
}

// DalfoxBlocker is one target dalfox gave up on, with the reason it wrote in the
// report. A non-zero exit alone cannot tell a missing login from a crash, and
// only the first is something the operator can fix by handing over a session.
type DalfoxBlocker struct {
	Target       string `json:"target"`
	ErrorCode    string `json:"error_code"`
	ErrorMessage string `json:"error_message"`
	Status       string `json:"status"`
}

// NeedsSession says dalfox stopped because the credentials it was given did not
// authenticate. That is the target asking for a login, not a statement about the
// parameter, so it must not be read as a negative injection verdict.
func (b DalfoxBlocker) NeedsSession() bool {
	code := strings.ToUpper(b.ErrorCode)
	for _, want := range []string{"SESSION", "AUTH", "CREDENT", "LOGIN"} {
		if strings.Contains(code, want) {
			return true
		}
	}
	msg := strings.ToLower(b.ErrorMessage)
	return strings.Contains(msg, "unauthenticated") || strings.Contains(msg, "credentials")
}

// Blocked returns dalfox's own reason for one target. A run covers a single
// point, so a lone blocker belongs to it even when the report normalised the URL.
func (r DalfoxRun) Blocked(target string) (DalfoxBlocker, bool) {
	for _, b := range r.Blockers {
		if b.Target == target {
			return b, true
		}
	}
	if len(r.Blockers) == 1 {
		return r.Blockers[0], true
	}
	return DalfoxBlocker{}, false
}

// Vulnerable counts the findings dalfox itself rated as executed XSS (v) rather
// than mere reflection (r) or DOM candidates (a).
func (r DalfoxRun) Vulnerable() int {
	n := 0
	for _, f := range r.Findings {
		if f.Verdict() == "verified" {
			n++
		}
	}
	return n
}

// Verdict maps dalfox's finding type onto the platform's three-way judgement:
// verified (payload executed), reflected (needs review) or informational.
func (f DalfoxFinding) Verdict() string {
	switch strings.ToLower(f.Type) {
	case "v":
		return "verified"
	case "r":
		return "reflected"
	case "a":
		return "dom_candidate"
	case "i":
		return "informational"
	}
	if strings.EqualFold(f.Confidence, "high") {
		return "verified"
	}
	return "reflected"
}

const maxDalfoxOutput = 4 << 20

var (
	dalfoxLookOnce sync.Once
	dalfoxPath     string
	dalfoxLookErr  error
)

// DalfoxAvailable reports whether the dalfox binary can be executed.
func DalfoxAvailable() bool {
	_, err := dalfoxBinary()
	return err == nil
}

func dalfoxBinary() (string, error) {
	dalfoxLookOnce.Do(func() { dalfoxPath, dalfoxLookErr = exec.LookPath("dalfox") })
	return dalfoxPath, dalfoxLookErr
}

// DalfoxVersion returns the installed dalfox version, or "" when unavailable.
func DalfoxVersion() string {
	bin, err := dalfoxBinary()
	if err != nil {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var out limitedBuffer
	out.limit = 128 << 10
	cmd := exec.CommandContext(ctx, bin, "payload", "--limit", "1")
	cmd.Stdout, cmd.Stderr = &out, &out
	_ = cmd.Run()
	if m := regexp.MustCompile(`Dalfox v[0-9][0-9.]*`).FindString(out.String()); m != "" {
		return strings.TrimPrefix(m, "Dalfox ")
	}
	return ""
}

// RunDalfox verifies one reflected/stored XSS point. The target must already be
// scope-checked by the caller; ScopeHost adds dalfox's own filter as well.
func RunDalfox(ctx context.Context, opts DalfoxOptions) DalfoxRun {
	run := DalfoxRun{}
	bin, err := dalfoxBinary()
	if err != nil {
		run.Missing = true
		run.Err = errors.New("dalfox 未安装")
		return run
	}
	target := strings.TrimSpace(opts.Target)
	if target == "" {
		run.Err = errors.New("缺少验证地址")
		return run
	}
	tmp, err := os.MkdirTemp("", "jingwei-dalfox-*")
	if err != nil {
		run.Err = err
		return run
	}
	defer os.RemoveAll(tmp)
	outFile := filepath.Join(tmp, "report.json")

	args := []string{"url", target,
		"-f", "json", "-o", outFile, "-S", "--no-color",
		"--include-request", "--include-response",
		"--workers", clampRangeStr(opts.Workers, 1, 20, 8),
		// A bounded rate is mandatory here: an unset rate would let dalfox hammer
		// the host with its own 50-worker default.
		"--rate-limit", clampRangeStr(opts.RateLimit, 1, 200, 20),
		"--timeout", clampRangeStr(opts.TimeoutSeconds, 1, 60, 10),
		"--scan-timeout", clampRangeStr(opts.ScanTimeoutSeconds, 1, 600, 120),
		"--max-payloads-per-param", clampRangeStr(opts.MaxPayloadsPerParam, 1, 200, 30),
		"--only-poc", "v,r,a",
		// Hidden-parameter mining pulls remote wordlists; keep the run local
		// and bounded to the points the caller named.
		"--skip-mining",
	}
	if d := clampOptional(opts.DelayMS, 0, 5000); d > 0 {
		args = append(args, "--delay", strconv.Itoa(d))
	}
	if m := strings.ToUpper(strings.TrimSpace(opts.Method)); m != "" && m != "GET" {
		args = append(args, "-X", sanitizeWord(m))
	}
	if body := opts.Data; body != "" && !strings.Contains(body, "\n") {
		args = append(args, "-d", body)
	}
	for _, p := range opts.Params {
		if p = sanitizeWord(p); p != "" {
			args = append(args, "-p", p)
		}
	}
	if c := strings.TrimSpace(opts.Cookie); c != "" && !strings.Contains(c, "\n") {
		args = append(args, "--cookies", c)
	}
	for _, h := range opts.Headers {
		if h = strings.TrimSpace(h); h != "" && !strings.Contains(h, "\n") {
			args = append(args, "-H", h)
		}
	}
	if opts.Stored {
		args = append(args, "--sxss")
		if u := strings.TrimSpace(opts.StoredURL); u != "" {
			args = append(args, "--sxss-url", u)
		}
	}
	if b := strings.TrimSpace(opts.BlindURL); b != "" {
		args = append(args, "-b", b)
	}
	if p := strings.TrimSpace(opts.Proxy); p != "" {
		args = append(args, "--proxy", p)
	}
	if host := strings.TrimSpace(opts.ScopeHost); host != "" {
		args = append(args, "--include-url", "^https?://"+regexp.QuoteMeta(host)+"/")
	}

	runCtx := ctx
	var cancel context.CancelFunc
	if opts.WallSeconds > 0 {
		runCtx, cancel = context.WithTimeout(ctx, time.Duration(opts.WallSeconds)*time.Second)
		defer cancel()
	}
	var stdout, stderr limitedBuffer
	stdout.limit, stderr.limit = maxDalfoxOutput, 256<<10
	started := time.Now()
	cmd := exec.CommandContext(runCtx, bin, args...)
	cmd.Dir = tmp
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	runErr := cmd.Run()
	run.Elapsed = time.Since(started)
	run.TimedOut = errors.Is(runCtx.Err(), context.DeadlineExceeded)

	raw, readErr := os.ReadFile(outFile)
	// Keep the tool's own words whatever happens: a run that exits non-zero after
	// writing a report still explains itself on stderr, and the caller needs that
	// text to say why a point was not decided.
	run.Log = tailText(stdout.String()+"\n"+stderr.String(), 8_000)
	if readErr == nil && len(raw) > 0 {
		run.ParseReport(raw)
	}
	if runErr != nil && len(run.Findings) == 0 && run.Err == nil && !run.TimedOut {
		run.Err = fmt.Errorf("dalfox 执行失败: %v", runErr)
	}
	return run
}

// ParseReport reads dalfox's JSON report; a missing FTS-style report leaves the
// run empty rather than failing the whole deep task.
func (r *DalfoxRun) ParseReport(raw []byte) {
	var doc struct {
		Findings []DalfoxFinding `json:"findings"`
		Meta     struct {
			Version        string          `json:"dalfox_version"`
			FailedRequests int             `json:"failed_requests"`
			Incomplete     bool            `json:"incomplete"`
			FindingsCount  int             `json:"findings_count"`
			TargetSummary  []DalfoxBlocker `json:"target_summary"`
		} `json:"meta"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		r.Log = tailText(string(raw), 4_000)
		return
	}
	r.Findings = doc.Findings
	r.Version = doc.Meta.Version
	r.FailedRequests = doc.Meta.FailedRequests
	r.Incomplete = doc.Meta.Incomplete
	r.Blockers = doc.Meta.TargetSummary
}

// clampRange bounds one tool option; a non-positive value falls back to the
// default because the option only makes sense above zero.
func clampRange(value, min, max, def int) int {
	if value <= 0 {
		value = def
	}
	if value < min {
		value = min
	}
	if value > max {
		value = max
	}
	return value
}

// clampOptional bounds an option where zero is a valid setting (--delay,
// --retries, --rate-limit all mean "off" at zero).
func clampOptional(value, min, max int) int {
	if value < min {
		value = min
	}
	if value > max {
		value = max
	}
	return value
}

func clampRangeStr(value, min, max, def int) string {
	return strconv.Itoa(clampRange(value, min, max, def))
}

func clampOptionalStr(value, min, max int) string {
	return strconv.Itoa(clampOptional(value, min, max))
}
