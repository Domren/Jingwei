package scanner

import (
	"context"
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

// SQLMapOptions bounds one sqlmap detection run. Only detection is enabled:
// no --dump/--dbms enumeration flag is ever passed, so a run cannot extract or
// modify table data.
type SQLMapOptions struct {
	RawRequest     string   // load the request from a file (-r) instead of --url
	Level          int      // 1-5
	Risk           int      // 1-3
	Threads        int      // 1-10
	TimeoutSeconds int      // per request
	DelaySeconds   int      // between requests
	Retries        int      // 0-3
	Techniques     string   // subset of BEUSQT
	DBMS           string   // hint, e.g. "mysql"
	Cookie         string   // session cookie for authenticated endpoints
	Headers        []string // extra "Name: value" headers
	Params         []string // test only these parameters (-p); keeps the run on point
	Proxy          string   // recording proxy, so the run's own traffic is captured
	TimeSeconds    int      // --time-sec: how long one time-based payload keeps the DBMS busy
	WallSeconds    int      // total budget for one point
}

// SQLMapInjection is one injection point sqlmap proved, with the exact payload
// it used so the request can be replayed by hand.
type SQLMapInjection struct {
	Param   string // "name"
	Where   string // "GET", "POST", "Cookie", "User-Agent" ...
	Type    string // "boolean-based blind"
	Title   string // "AND boolean-based blind - WHERE or HAVING clause"
	Payload string // full parameter payload as printed by sqlmap
}

// SQLMapRun is the outcome of one sqlmap invocation.
type SQLMapRun struct {
	Injections []SQLMapInjection
	DBMS       string
	Tech       string
	OS         string
	Target     string
	Version    string
	Log        string
	Elapsed    time.Duration
	TimedOut   bool
	Missing    bool
	Err        error
}

// Found reports whether sqlmap proved at least one injection point.
func (r SQLMapRun) Found() bool { return len(r.Injections) > 0 }

// SQLMapEscalation is the outcome of the post-verification metadata query. It
// only carries what the injected DB account revealed about itself; no table
// data is ever read.
type SQLMapEscalation struct {
	Banner      string
	CurrentUser string
	CurrentDB   string
	Hostname    string
	DBAText     string
	IsDBA       bool
	Version     string
	Log         string
	Elapsed     time.Duration
	TimedOut    bool
	Missing     bool
	Err         error
}

// HasFindings reports whether the escalation returned anything worth showing.
func (e SQLMapEscalation) HasFindings() bool {
	return e.Banner != "" || e.CurrentUser != "" || e.CurrentDB != "" || e.Hostname != "" || e.IsDBA
}

// Summary renders the one-line impact statement used in evidence and records.
func (e SQLMapEscalation) Summary() string {
	parts := []string{}
	if e.CurrentUser != "" {
		parts = append(parts, "DB 用户 "+e.CurrentUser)
	}
	if e.CurrentDB != "" {
		parts = append(parts, "当前库 "+e.CurrentDB)
	}
	if e.Hostname != "" {
		parts = append(parts, "主机 "+e.Hostname)
	}
	if e.Banner != "" {
		parts = append(parts, "版本 "+e.Banner)
	}
	if e.DBAText != "" {
		parts = append(parts, "DBA="+e.DBAText)
	}
	return strings.Join(parts, " · ")
}

const (
	maxSQLMapOutput = 4 << 20
	sqlmapBanner    = "sqlmap identified the following injection point"
)

var (
	sqlmapLookOnce sync.Once
	sqlmapPath     string
	sqlmapLookErr  error

	sqlmapVersionOnce sync.Once
	sqlmapVersionText string

	reSQLMapParam   = regexp.MustCompile(`^Parameter:\s+(\S+)\s+\(([^)]+)\)\s*$`)
	reSQLMapType    = regexp.MustCompile(`^\s*Type:\s+(.*)$`)
	reSQLMapTitle   = regexp.MustCompile(`^\s*Title:\s+(.*)$`)
	reSQLMapPayload = regexp.MustCompile(`^\s*Payload:\s+(.*)$`)
	reSQLMapDBMS    = regexp.MustCompile(`(?m)^back-end DBMS:\s*(.+)$`)
	reSQLMapTech    = regexp.MustCompile(`(?m)^web application technology:\s*(.+)$`)
	reSQLMapOS      = regexp.MustCompile(`(?m)^web server operating system:\s*(.+)$`)
	reSQLMapHexEsc  = regexp.MustCompile(`\\x([0-9a-fA-F]{2})`)
	reSQLMapNotInj  = regexp.MustCompile(`does not seem to be injectable|do not appear to be injectable`)
	sqlmapVersionRE = regexp.MustCompile(`[0-9]+\.[0-9]+(\.[0-9]+)?[0-9a-zA-Z#.\-]*`)
)

// SQLMapAvailable reports whether the sqlmap binary can be executed.
func SQLMapAvailable() bool {
	_, err := sqlmapBinary()
	return err == nil
}

func sqlmapBinary() (string, error) {
	sqlmapLookOnce.Do(func() {
		sqlmapPath, sqlmapLookErr = exec.LookPath("sqlmap")
		if sqlmapLookErr != nil {
			if alt, err := exec.LookPath("sqlmap.py"); err == nil {
				sqlmapPath, sqlmapLookErr = alt, nil
			}
		}
	})
	return sqlmapPath, sqlmapLookErr
}

// SQLMapVersion returns the installed sqlmap version, or "" when unavailable.
func SQLMapVersion() string {
	sqlmapVersionOnce.Do(func() {
		bin, err := sqlmapBinary()
		if err != nil {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		var out limitedBuffer
		out.limit = 64 << 10
		cmd := exec.CommandContext(ctx, bin, "--version")
		cmd.Stdout, cmd.Stderr = &out, &out
		_ = cmd.Run()
		if m := sqlmapVersionRE.FindString(out.String()); m != "" {
			sqlmapVersionText = m
		}
	})
	return sqlmapVersionText
}

// RunSQLMap executes sqlmap against one injection point in detection-only mode.
// target must already be scope-checked by the caller.
func RunSQLMap(ctx context.Context, target string, opts SQLMapOptions) SQLMapRun {
	run := SQLMapRun{Target: target, Version: SQLMapVersion()}
	bin, err := sqlmapBinary()
	if err != nil {
		run.Missing = true
		run.Err = errors.New("sqlmap 未安装")
		return run
	}
	tmp, err := os.MkdirTemp("", "jingwei-sqlmap-*")
	if err != nil {
		run.Err = err
		return run
	}
	defer os.RemoveAll(tmp)

	args := []string{
		"--batch", "--flush-session",
		"--level", clampRangeStr(opts.Level, 1, 5, 3),
		"--risk", clampRangeStr(opts.Risk, 1, 3, 2),
		"--threads", clampRangeStr(opts.Threads, 1, 10, 2),
		"--timeout", clampRangeStr(opts.TimeoutSeconds, 1, 120, 15),
		"--retries", clampOptionalStr(opts.Retries, 0, 3),
		// A time-based payload outlives its own client: sqlmap abandons the request
		// at --timeout while the DBMS keeps sleeping row after row, and on a
		// table-locked engine every later request to that table queues behind it.
		"--time-sec", clampRangeStr(opts.TimeSeconds, 1, 10, 3),
		"--output-dir", filepath.Join(tmp, "out"),
	}
	targetArgs, err := sqlmapTargetArgs(target, opts, tmp)
	if err != nil {
		run.Err = err
		return run
	}
	args = append(args, targetArgs...)

	runCtx := ctx
	var cancel context.CancelFunc
	if opts.WallSeconds > 0 {
		runCtx, cancel = context.WithTimeout(ctx, time.Duration(opts.WallSeconds)*time.Second)
		defer cancel()
	}
	var out limitedBuffer
	out.limit = maxSQLMapOutput
	started := time.Now()
	cmd := exec.CommandContext(runCtx, bin, args...)
	cmd.Stdout, cmd.Stderr = &out, &out
	err = cmd.Run()
	run.Elapsed = time.Since(started)
	run.TimedOut = errors.Is(runCtx.Err(), context.DeadlineExceeded)
	run.Log = tailText(out.String(), 24_000)
	run.Injections, run.DBMS, run.Tech, run.OS = ParseSQLMapOutput(out.String())
	if err != nil && !run.Found() && !reSQLMapNotInj.MatchString(out.String()) && run.Version == "" {
		run.Err = fmt.Errorf("sqlmap 执行失败: %v", err)
	}
	return run
}

// sqlmapTargetArgs builds the flags that locate the request to test and carry
// its session. Both the detection and the escalation run need exactly the same
// view of the point, so the two command lines cannot drift apart.
func sqlmapTargetArgs(target string, opts SQLMapOptions, tmp string) ([]string, error) {
	args := []string{}
	if opts.RawRequest != "" {
		reqFile := filepath.Join(tmp, "request.txt")
		if err := os.WriteFile(reqFile, []byte(normalizeRawRequestForTool(opts.RawRequest)), 0o600); err != nil {
			return nil, fmt.Errorf("写入请求文件失败: %w", err)
		}
		args = append(args, "-r", reqFile)
	} else {
		args = append(args, "--url", target)
	}
	if tech := sanitizeTechniques(opts.Techniques); tech != "" {
		args = append(args, "--technique", tech)
	}
	if dbms := sanitizeWord(opts.DBMS); dbms != "" {
		args = append(args, "--dbms", dbms)
	}
	if d := clampOptional(opts.DelaySeconds, 0, 30); d > 0 {
		args = append(args, "--delay", strconv.Itoa(d))
	}
	if c := strings.TrimSpace(opts.Cookie); c != "" {
		args = append(args, "--cookie", c)
	}
	for _, h := range opts.Headers {
		if h = strings.TrimSpace(h); h != "" && !strings.Contains(h, "\n") {
			args = append(args, "-H", h)
		}
	}
	if names := sanitizeParamList(opts.Params); names != "" {
		args = append(args, "-p", names)
	}
	if p := strings.TrimSpace(opts.Proxy); p != "" {
		args = append(args, "--proxy", p)
	}
	return args, nil
}

// RunSQLMapEscalation queries what the injected DB account can see once a point
// has been proven injectable. It asks for metadata only (banner, current user,
// current database, DBA flag, hostname): no table is read, no file is written
// and no OS shell is opened. target and opts must describe the same point the
// detection run proved, with opts.Params pinned to the proven parameter.
func RunSQLMapEscalation(ctx context.Context, target string, opts SQLMapOptions) SQLMapEscalation {
	esc := SQLMapEscalation{Version: SQLMapVersion()}
	bin, err := sqlmapBinary()
	if err != nil {
		esc.Missing = true
		esc.Err = errors.New("sqlmap 未安装")
		return esc
	}
	tmp, err := os.MkdirTemp("", "jingwei-sqlmap-escalate-*")
	if err != nil {
		esc.Err = err
		return esc
	}
	defer os.RemoveAll(tmp)

	args := []string{
		"--batch", "--flush-session",
		"--level", clampRangeStr(opts.Level, 1, 5, 3),
		"--risk", clampRangeStr(opts.Risk, 1, 3, 2),
		// One worker: the point is already known, and a metadata query should not
		// multiply load on a database that just showed a time-based behaviour.
		"--threads", "1",
		"--timeout", clampRangeStr(opts.TimeoutSeconds, 1, 120, 15),
		"--retries", clampOptionalStr(opts.Retries, 0, 3),
		"--time-sec", clampRangeStr(opts.TimeSeconds, 1, 10, 3),
		"--output-dir", filepath.Join(tmp, "out"),
		"--banner", "--current-user", "--current-db", "--is-dba", "--hostname",
	}
	targetArgs, err := sqlmapTargetArgs(target, opts, tmp)
	if err != nil {
		esc.Err = err
		return esc
	}
	args = append(args, targetArgs...)

	runCtx := ctx
	var cancel context.CancelFunc
	if opts.WallSeconds > 0 {
		runCtx, cancel = context.WithTimeout(ctx, time.Duration(opts.WallSeconds)*time.Second)
		defer cancel()
	}
	var out limitedBuffer
	out.limit = maxSQLMapOutput
	started := time.Now()
	cmd := exec.CommandContext(runCtx, bin, args...)
	cmd.Stdout, cmd.Stderr = &out, &out
	err = cmd.Run()
	esc.Elapsed = time.Since(started)
	esc.TimedOut = errors.Is(runCtx.Err(), context.DeadlineExceeded)
	esc.Log = tailText(out.String(), 12_000)
	esc.Banner, esc.CurrentUser, esc.CurrentDB, esc.Hostname, esc.DBAText, esc.IsDBA = ParseSQLMapEscalation(out.String())
	if err != nil && !esc.TimedOut && !esc.HasFindings() {
		esc.Err = fmt.Errorf("sqlmap 影响评估执行失败: %v", err)
	}
	return esc
}

var (
	reSQLMapEscBanner = regexp.MustCompile(`(?m)^banner:\s*'?([^'\r\n]*)'?\s*$`)
	reSQLMapEscUser   = regexp.MustCompile(`(?m)^current user:\s*'?([^'\r\n]*)'?\s*$`)
	reSQLMapEscDB     = regexp.MustCompile(`(?m)^current database:\s*'?([^'\r\n]*)'?\s*$`)
	reSQLMapEscHost   = regexp.MustCompile(`(?m)^hostname:\s*'?([^'\r\n]*)'?\s*$`)
	reSQLMapEscDBA    = regexp.MustCompile(`(?m)^current user is DBA:\s*(True|False)\s*$`)
)

// ParseSQLMapEscalation reads the metadata lines sqlmap prints for the
// --banner/--current-user/--current-db/--is-dba/--hostname run.
func ParseSQLMapEscalation(text string) (banner, currentUser, currentDB, hostname, dbaText string, isDBA bool) {
	banner = sqlmapMetaValue(reSQLMapEscBanner, text)
	currentUser = sqlmapMetaValue(reSQLMapEscUser, text)
	currentDB = sqlmapMetaValue(reSQLMapEscDB, text)
	hostname = sqlmapMetaValue(reSQLMapEscHost, text)
	if m := reSQLMapEscDBA.FindStringSubmatch(text); m != nil {
		dbaText = strings.TrimSpace(m[1])
		isDBA = strings.EqualFold(dbaText, "True")
	}
	return banner, currentUser, currentDB, hostname, dbaText, isDBA
}

func sqlmapMetaValue(re *regexp.Regexp, text string) string {
	m := re.FindStringSubmatch(text)
	if m == nil {
		return ""
	}
	return strings.TrimSpace(m[1])
}

// ParseSQLMapOutput reads the injection-point block sqlmap prints when it proves
// a parameter injectable, plus the fingerprint lines that follow it.
func ParseSQLMapOutput(text string) (injections []SQLMapInjection, dbms, tech, osName string) {
	section := text
	if i := strings.Index(text, sqlmapBanner); i >= 0 {
		section = text[i:]
	} else {
		return nil, "", "", ""
	}
	var cur *SQLMapInjection
	flush := func() {
		if cur != nil && cur.Payload != "" {
			injections = append(injections, *cur)
		}
		cur = nil
	}
	for _, line := range strings.Split(section, "\n") {
		if m := reSQLMapParam.FindStringSubmatch(line); m != nil {
			flush()
			cur = &SQLMapInjection{Param: strings.TrimSpace(m[1]), Where: strings.TrimSpace(m[2])}
			continue
		}
		if cur == nil {
			continue
		}
		if m := reSQLMapType.FindStringSubmatch(line); m != nil {
			if cur.Type != "" {
				// One parameter can carry several techniques; flush() drops cur,
				// so the point identity has to be captured before it runs.
				param, where := cur.Param, cur.Where
				flush()
				cur = &SQLMapInjection{Param: param, Where: where}
			}
			cur.Type = strings.TrimSpace(m[1])
			continue
		}
		if m := reSQLMapTitle.FindStringSubmatch(line); m != nil {
			cur.Title = strings.TrimSpace(m[1])
			continue
		}
		if m := reSQLMapPayload.FindStringSubmatch(line); m != nil {
			cur.Payload = decodeSQLMapEscapes(strings.TrimSpace(m[1]))
		}
	}
	flush()
	if m := reSQLMapDBMS.FindStringSubmatch(text); m != nil {
		dbms = strings.TrimSpace(m[1])
	}
	if m := reSQLMapTech.FindStringSubmatch(text); m != nil {
		tech = strings.TrimSpace(m[1])
	}
	if m := reSQLMapOS.FindStringSubmatch(text); m != nil {
		osName = strings.TrimSpace(m[1])
	}
	return injections, dbms, tech, osName
}

// decodeSQLMapEscapes turns sqlmap's display form of non-ASCII bytes back into
// percent encoding, so the replayed request matches what sqlmap actually sent.
func decodeSQLMapEscapes(payload string) string {
	return reSQLMapHexEsc.ReplaceAllStringFunc(payload, func(m string) string {
		b, err := strconv.ParseUint(m[2:], 16, 8)
		if err != nil {
			return m
		}
		return "%" + strings.ToUpper(strconv.FormatUint(b, 16))
	})
}

// normalizeRawRequestForTool rewrites CRLF noise so sqlmap's -r parser accepts
// the request the platform captured.
func normalizeRawRequestForTool(raw string) string {
	raw = strings.ReplaceAll(raw, "\r\n", "\n")
	raw = strings.TrimLeft(raw, "\n")
	if !strings.HasSuffix(raw, "\n\n") && !strings.Contains(raw, "\n\n") {
		raw += "\n\n"
	}
	return strings.ReplaceAll(raw, "\n", "\r\n")
}

var unsafeToolWord = regexp.MustCompile(`[^a-zA-Z0-9_.\-]+`)

func sanitizeWord(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	out := unsafeToolWord.ReplaceAllString(s, "")
	if len(out) > 40 {
		out = out[:40]
	}
	return out
}

// sanitizeParamList keeps parameter names to the character set a sqlmap -p list
// accepts and caps the list so one point cannot expand into the whole app.
func sanitizeParamList(params []string) string {
	out := make([]string, 0, len(params))
	for _, p := range params {
		if p = sanitizeWord(p); p != "" {
			out = append(out, p)
		}
		if len(out) >= 10 {
			break
		}
	}
	return strings.Join(out, ",")
}

// sanitizeTechniques keeps only the technique letters sqlmap understands.
func sanitizeTechniques(s string) string {
	seen := map[byte]bool{}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := byte(s[i])
		switch c {
		case 'B', 'E', 'U', 'S', 'T', 'Q':
		case 'b', 'e', 'u', 's', 't', 'q':
			c -= 32
		default:
			continue
		}
		if seen[c] {
			continue
		}
		seen[c] = true
		b.WriteByte(c)
	}
	return b.String()
}

func tailText(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	return "…（前 " + strconv.Itoa(len(s)-limit) + " 字节已省略）\n" + s[len(s)-limit:]
}
