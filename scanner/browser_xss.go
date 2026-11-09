package scanner

import (
	"context"
	_ "embed"
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

// D1：用真实浏览器确认 XSS。dalfox 判的是「payload 出现在响应里、且它自己的
// 检测器认为可执行」；本模块把那条 PoC URL 真的放进 Chromium 跑一遍，只有观察
// 到 JS 执行（弹窗 / DOM marker）才算执行成功。两者差异就是可量化的误报下降。

//go:embed xssbrowser_verify.cjs
var xssBrowserScript []byte

// BrowserXSSTarget is one PoC URL to replay in a browser. Only URL-carried
// injections are supported: a POST body / Cookie / Header payload needs form
// automation, and pretending otherwise would produce false "not executed".
type BrowserXSSTarget struct {
	URL     string `json:"url"`
	Payload string `json:"payload,omitempty"`
}

// BrowserXSSOptions bounds one browser verification run.
type BrowserXSSOptions struct {
	Targets        []BrowserXSSTarget
	TimeoutSeconds int // 单个页面加载超时，默认 15
	MaxTargets     int // 默认 5，硬上限 20
}

// BrowserXSSResult is the verification of one PoC URL.
type BrowserXSSResult struct {
	URL         string   `json:"url"`
	Executed    bool     `json:"executed"`
	Signals     []string `json:"signals,omitempty"`
	Dialogs     []string `json:"dialogs,omitempty"`
	Reflected   bool     `json:"reflected"`
	MarkerTried bool     `json:"marker_tried,omitempty"`
	MarkerHit   bool     `json:"marker_hit,omitempty"`
	FinalURL    string   `json:"final_url,omitempty"`
	ElapsedMS   int64    `json:"elapsed_ms"`
	Error       string   `json:"error,omitempty"`
}

// BrowserXSSRun is the outcome of one run.
type BrowserXSSRun struct {
	Results []BrowserXSSResult
	Version string
	Missing bool // node 或 playwright 不可用
	Elapsed time.Duration
	Err     error
	Log     string
}

// ReflectedOnly counts PoCs that appear in the DOM without executing — the
// concrete false-positive population dalfox's single channel would have kept.
func (r BrowserXSSRun) ReflectedOnly() int {
	n := 0
	for _, res := range r.Results {
		if res.Reflected && !res.Executed {
			n++
		}
	}
	return n
}

// ExecutedCount counts PoCs a browser actually ran.
func (r BrowserXSSRun) ExecutedCount() int {
	n := 0
	for _, res := range r.Results {
		if res.Executed {
			n++
		}
	}
	return n
}

var (
	browserXSSOnce   sync.Once
	browserXSSNode   string
	browserXSSModule string
	browserXSSErr    error
)

// browserXSSResolve locates node and a resolvable playwright module. Resolution
// is done once: a missing browser stack is an environment fact, not something
// that changes between targets.
func browserXSSResolve() (node, module string, err error) {
	browserXSSOnce.Do(func() {
		browserXSSNode, browserXSSModule, browserXSSErr = resolveBrowserXSS()
	})
	return browserXSSNode, browserXSSModule, browserXSSErr
}

func resolveBrowserXSS() (string, string, error) {
	node, err := exec.LookPath("node")
	if err != nil {
		return "", "", errors.New("node 不可用，无法做浏览器验证")
	}
	module := strings.TrimSpace(os.Getenv("JW_PLAYWRIGHT_MODULE"))
	candidates := []string{module}
	if module == "" {
		if out, rerr := exec.Command(node, "-e", "process.stdout.write(require('path').dirname(require.resolve('playwright')))").Output(); rerr == nil {
			candidates = append(candidates, strings.TrimSpace(string(out)))
		}
		if root, rerr := exec.Command("npm", "root", "-g").Output(); rerr == nil {
			candidates = append(candidates, strings.TrimSpace(string(root)))
		}
	}
	for _, c := range candidates {
		if c == "" {
			continue
		}
		// 用 node 自己解析，避免猜测目录结构。
		probe := fmt.Sprintf("require.resolve('playwright',{paths:[%q]})", c)
		if rerr := exec.Command(node, "-e", probe).Run(); rerr == nil {
			return node, c, nil
		}
	}
	return node, "", errors.New("playwright 模块不可用（需在镜像内安装 playwright 或设置 JW_PLAYWRIGHT_MODULE）")
}

// BrowserXSSAvailable reports whether a real browser check can run here.
func BrowserXSSAvailable() bool {
	_, _, err := browserXSSResolve()
	return err == nil
}

// RunBrowserXSS loads every target in a headless Chromium and reports whether the
// payload actually executed. A missing browser stack is reported as Missing so
// callers can keep the tool-only verdict instead of silently claiming a check.
func RunBrowserXSS(ctx context.Context, opts BrowserXSSOptions) BrowserXSSRun {
	start := time.Now()
	run := BrowserXSSRun{}
	node, module, err := browserXSSResolve()
	if err != nil {
		run.Missing = true
		run.Err = err
		return run
	}
	maxTargets := opts.MaxTargets
	if maxTargets <= 0 {
		maxTargets = 5
	}
	if maxTargets > 20 {
		maxTargets = 20
	}
	targets := make([]BrowserXSSTarget, 0, maxTargets)
	for _, t := range opts.Targets {
		if len(targets) >= maxTargets {
			break
		}
		if strings.TrimSpace(t.URL) == "" {
			continue
		}
		targets = append(targets, t)
	}
	if len(targets) == 0 {
		run.Err = errors.New("没有可验证的 XSS PoC URL")
		return run
	}
	timeout := opts.TimeoutSeconds
	if timeout <= 0 {
		timeout = 15
	}
	if timeout > 60 {
		timeout = 60
	}

	dir, err := os.MkdirTemp("", "jw-xss-browser-")
	if err != nil {
		run.Err = err
		return run
	}
	defer os.RemoveAll(dir)
	scriptPath := filepath.Join(dir, "verify.cjs")
	if err := os.WriteFile(scriptPath, xssBrowserScript, 0o600); err != nil {
		run.Err = err
		return run
	}
	input := map[string]any{"timeout_ms": timeout * 1000, "targets": targets}
	raw, err := json.Marshal(input)
	if err != nil {
		run.Err = err
		return run
	}
	inputPath := filepath.Join(dir, "input.json")
	if err := os.WriteFile(inputPath, raw, 0o600); err != nil {
		run.Err = err
		return run
	}

	runCtx, cancel := context.WithTimeout(ctx, time.Duration(timeout*len(targets)+45)*time.Second)
	defer cancel()
	cmd := exec.CommandContext(runCtx, node, scriptPath, inputPath)
	if module != "" {
		cmd.Env = append(os.Environ(), "JW_PLAYWRIGHT_MODULE="+module)
	}
	out, err := cmd.CombinedOutput()
	run.Elapsed = time.Since(start)
	run.Log = truncateBytes(string(out), 4000)
	if runCtx.Err() != nil {
		run.Err = errors.New("浏览器验证超时")
		return run
	}
	if err != nil && len(out) == 0 {
		run.Err = err
		return run
	}
	var parsed struct {
		Version string             `json:"version"`
		Missing bool               `json:"missing"`
		Error   string             `json:"error"`
		Results []BrowserXSSResult `json:"results"`
	}
	if jerr := json.Unmarshal([]byte(lastJSONLine(string(out))), &parsed); jerr != nil {
		run.Err = fmt.Errorf("浏览器验证输出无法解析: %v（%s）", jerr, truncateBytes(string(out), 300))
		return run
	}
	if parsed.Missing {
		run.Missing = true
		run.Err = errors.New(parsed.Error)
		return run
	}
	if parsed.Error != "" {
		run.Err = errors.New(parsed.Error)
	}
	run.Version = parsed.Version
	run.Results = parsed.Results
	return run
}

// lastJSONLine returns the final non-empty line: node may print deprecation
// warnings on stdout before the JSON result.
func lastJSONLine(out string) string {
	lines := strings.Split(strings.TrimSpace(out), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if strings.HasPrefix(line, "{") {
			return line
		}
	}
	return strings.TrimSpace(out)
}

func truncateBytes(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	return s[:limit] + "…"
}
