package scanner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// WebCrackOptions bounds one web-login weak credential run. The check is
// dictionary-driven (a small username set against the vendored password list)
// and stops at the first valid pair per URL.
type WebCrackOptions struct {
	URLs          []string // login page candidates, already scope-checked
	Users         []string // extra usernames beyond the tool's default
	PerURLSeconds int      // wall budget per URL inside the tool
	DelayMS       int      // pause between attempts
	TimeoutSecond int      // total wall budget for the whole run
}

// WebCrackResult is the outcome of one login URL.
type WebCrackResult struct {
	URL       string   `json:"url"`
	Found     bool     `json:"found"`
	Username  string   `json:"username"`
	Password  string   `json:"password"`
	Kind      string   `json:"kind"` // weak | universal
	Attempts  int      `json:"attempts"`
	ElapsedMS int64    `json:"elapsed_ms"`
	Request   string   `json:"request"`
	Response  string   `json:"response"`
	Error     string   `json:"error"`
	Log       []string `json:"log"`
}

// WebCrackRun is the outcome of one bridge invocation.
type WebCrackRun struct {
	Results  []WebCrackResult
	Elapsed  time.Duration
	Missing  bool
	NotFound bool // bridge present but produced no usable output
	Err      error
}

type webCrackBridgeOutput struct {
	Tool    string           `json:"tool"`
	Results []WebCrackResult `json:"results"`
	Missing bool             `json:"missing"`
	Error   string           `json:"error"`
}

var (
	webCrackLookOnce sync.Once
	webCrackBin      string // "python3 <bridge>"
	webCrackLookErr  error
	webCrackLookEnv  string
)

// WebCrackAvailable reports whether the vendored bridge script can run.
func WebCrackAvailable() bool {
	_, err := webCrackBinary()
	return err == nil
}

func webCrackBinary() (string, error) {
	key := os.Getenv("JINGWEI_WEBCRACK_BRIDGE") + "|" + os.Getenv("JINGWEI_WEBCRACK_PYTHON")
	webCrackLookOnce.Do(func() {
		webCrackLookEnv = key
		webCrackResolve()
	})
	if key != webCrackLookEnv {
		// The bridge and interpreter are configurable; a test (or an operator)
		// can point them elsewhere after a first lookup, so re-resolve on change.
		webCrackLookOnce = sync.Once{}
		return webCrackBinary()
	}
	return webCrackBin, webCrackLookErr
}

func webCrackResolve() {
	webCrackBin, webCrackLookErr = "", nil
	py := strings.TrimSpace(os.Getenv("JINGWEI_WEBCRACK_PYTHON"))
	if py == "" {
		var err error
		py, err = exec.LookPath("python3")
		if err != nil {
			if py2, err2 := exec.LookPath("python"); err2 == nil {
				py, err = py2, nil
			}
		}
		if err != nil {
			webCrackLookErr = errors.New("python3 未安装")
			return
		}
	}
	script, err := webCrackBridgeScript()
	if err != nil {
		webCrackLookErr = err
		return
	}
	if strings.ContainsAny(py, " \t\n") || strings.ContainsAny(script, " \t\n") {
		// webCrackBin is split on whitespace by the caller: refuse paths that
		// would not survive that, rather than silently mangling the command.
		webCrackLookErr = errors.New("webcrack：python 或脚本路径含空白字符，请改用引号安全的路径")
		return
	}
	webCrackBin = py + " " + script
}

func webCrackBridgeScript() (string, error) {
	if p := strings.TrimSpace(os.Getenv("JINGWEI_WEBCRACK_BRIDGE")); p != "" {
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
		return "", fmt.Errorf("JINGWEI_WEBCRACK_BRIDGE 指向的脚本不存在: %s", p)
	}
	candidates := []string{
		"/app/tools/webcrack/jingweibridge.py",
		filepath.Join("tools", "webcrack", "jingweibridge.py"),
	}
	for _, c := range candidates {
		if abs, err := filepath.Abs(c); err == nil {
			if _, err := os.Stat(abs); err == nil {
				return abs, nil
			}
		}
	}
	return "", errors.New("webcrack 桥接脚本未找到（镜像应包含 /app/tools/webcrack）")
}

// RunWebCrack executes the vendored WebCrack login checker against the given
// URLs. Callers must already have scope-checked every URL.
func RunWebCrack(ctx context.Context, opts WebCrackOptions) WebCrackRun {
	run := WebCrackRun{}
	start := time.Now()
	bin, err := webCrackBinary()
	if err != nil {
		run.Missing = true
		run.Err = errors.New("webcrack 未安装：" + err.Error())
		return run
	}
	parts := strings.Fields(bin)
	args := make([]string, 0, 8+2*len(opts.URLs))
	args = append(args, parts[1:]...)
	for _, u := range opts.URLs {
		if u = strings.TrimSpace(u); u != "" {
			args = append(args, "--url", u)
		}
	}
	if len(args) <= len(parts)-1 {
		run.Err = errors.New("webcrack：没有可测试的 URL")
		return run
	}
	for _, u := range opts.Users {
		if u = strings.TrimSpace(u); u != "" {
			args = append(args, "--user", u)
		}
	}
	perURL := opts.PerURLSeconds
	if perURL <= 0 {
		perURL = 90
	}
	args = append(args, "--per-url-timeout", fmt.Sprintf("%d", perURL))
	delay := opts.DelayMS
	if delay <= 0 {
		delay = 50
	}
	args = append(args, "--delay", fmt.Sprintf("%.3f", float64(delay)/1000))

	runCtx := ctx
	var cancel context.CancelFunc
	if opts.TimeoutSecond > 0 {
		runCtx, cancel = context.WithTimeout(ctx, time.Duration(opts.TimeoutSecond)*time.Second)
		defer cancel()
	}
	var out limitedBuffer
	out.limit = 8 << 20
	cmd := exec.CommandContext(runCtx, parts[0], args...)
	cmd.Stdout, cmd.Stderr = &out, &out
	cmdErr := cmd.Run()
	run.Elapsed = time.Since(start)

	// The bridge prints one JSON document; anything else on stdout is noise.
	payload := extractWebCrackJSON(out.String())
	if payload == "" {
		run.NotFound = true
		run.Err = fmt.Errorf("webcrack 无输出（exit=%v）", cmdErr)
		return run
	}
	var parsed webCrackBridgeOutput
	if err := json.Unmarshal([]byte(payload), &parsed); err != nil {
		run.Err = fmt.Errorf("解析 webcrack 输出失败: %w", err)
		return run
	}
	run.Results = parsed.Results
	if parsed.Error != "" && len(parsed.Results) == 0 {
		run.Err = errors.New(parsed.Error)
	}
	return run
}

// extractWebCrackJSON returns the last balanced JSON object in the output.
// The bridge normally prints exactly one; a native banner before it (ddddocr)
// must not break parsing.
func extractWebCrackJSON(s string) string {
	trim := strings.TrimSpace(s)
	if trim == "" {
		return ""
	}
	if strings.HasPrefix(trim, "{") && strings.HasSuffix(trim, "}") && json.Valid([]byte(trim)) {
		return trim
	}
	if idx := strings.LastIndex(trim, "\n{"); idx >= 0 {
		candidate := strings.TrimSpace(trim[idx+1:])
		if strings.HasPrefix(candidate, "{") && json.Valid([]byte(candidate)) {
			return candidate
		}
	}
	return ""
}
