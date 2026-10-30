package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

// NucleiTemplate is one nuclei YAML template to execute.
type NucleiTemplate struct {
	ID      string
	Content string
}

// NucleiOptions controls a nuclei run.
type NucleiOptions struct {
	RateLimit      int
	Concurrency    int
	TimeoutSeconds int
}

// NucleiResult is one parsed nuclei JSONL match.
type NucleiResult struct {
	TemplateID string `json:"template_id"`
	Name       string `json:"name"`
	Severity   string `json:"severity"`
	Host       string `json:"host"`
	MatchedAt  string `json:"matched_at"`
	Type       string `json:"type"`
	Timestamp  string `json:"timestamp"`
	Curl       string `json:"curl_command,omitempty"`
	Request    string `json:"request,omitempty"`
	Response   string `json:"response,omitempty"`
	// Exchanges is the full reproduction sequence nuclei stored for this hit,
	// in wire order; Request/Response remain the matched (proof) exchange.
	Exchanges []RawExchange `json:"-"`
	Extracted []string      `json:"extracted"`
	// Tags is the template's info.tags, used to route a hit to sqlmap/dalfox.
	Tags []string       `json:"-"`
	Raw  map[string]any `json:"raw,omitempty"`
}

// RawExchange is one unredacted request/response pair captured by -store-resp.
type RawExchange struct {
	Request  string
	Response string
}

// NucleiRun is the outcome of one nuclei invocation.
type NucleiRun struct {
	Results       []NucleiResult
	Stdout        string
	Stderr        string
	Err           error
	TimedOut      bool
	Elapsed       time.Duration
	TemplateCount int
	TargetCount   int
	// Chains / Singles count the templates executed in each concurrency group;
	// they are reported so a scan log explains why a run took longer.
	Chains  int
	Singles int
	// RawTargets / RawTemplates report the non-HTTP-port split: how many
	// host:port targets were probed only with raw-protocol POCs and how many
	// templates that left for them.
	RawTargets   int
	RawTemplates int
}

// maxNucleiOutput caps the raw JSONL stdout retained per scan. 8 MiB was enough
// for small template sets but truncates when dozens of templates each attach a
// full request/response, silently dropping hits at the tail (e.g. a high-severity
// SSTI hit lost behind many info-level banner hits). Raised to 64 MiB so a full
// 334-environment vulhub scan keeps every result; the buffer is in-memory and
// bounded, so the larger cap only costs memory, not disk.
const maxNucleiOutput = 64 << 20

// minNetworkReadSize is the read-size floor applied to network requests before
// a template runs. Upstream network templates often cap at 2048 bytes, which
// cuts banner payloads (a Redis INFO reply is ~2.7 KiB) mid-value, so the saved
// response no longer matches what a manual replay returns.
const minNetworkReadSize = 16 << 10

var networkReadSizeLine = regexp.MustCompile(`^(\s*)read-size:\s*([0-9]+)(.*)$`)

// raiseNetworkReadSize lifts small network read-size caps to floor so captured
// packets are complete. Already larger values are left untouched.
func raiseNetworkReadSize(content string, floor int) string {
	if floor <= 0 || !strings.Contains(content, "read-size:") {
		return content
	}
	lines := strings.Split(content, "\n")
	for i, line := range lines {
		m := networkReadSizeLine.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		value, err := strconv.Atoi(m[2])
		if err != nil || value >= floor {
			continue
		}
		lines[i] = fmt.Sprintf("%sread-size: %d%s", m[1], floor, m[3])
	}
	return strings.Join(lines, "\n")
}

var unsafeFilePart = regexp.MustCompile(`[^a-zA-Z0-9._-]+`)

// RunNuclei writes templates/targets to a temp dir and runs nuclei with the same
// safety flags used by the manual POC runner.
func RunNuclei(ctx context.Context, templates []NucleiTemplate, targets []string, opts NucleiOptions) NucleiRun {
	run := NucleiRun{TemplateCount: len(templates), TargetCount: len(targets), Results: []NucleiResult{}}
	if len(templates) == 0 {
		run.Err = fmt.Errorf("没有可执行的 POC 模板")
		return run
	}
	if len(targets) == 0 {
		run.Err = fmt.Errorf("没有可扫描的目标")
		return run
	}
	nuclei, err := exec.LookPath("nuclei")
	if err != nil {
		run.Err = fmt.Errorf("nuclei 未安装")
		return run
	}
	tmp, err := os.MkdirTemp("", "jingwei-scan-*")
	if err != nil {
		run.Err = err
		return run
	}
	defer os.RemoveAll(tmp)

	rate := opts.RateLimit
	if rate <= 0 {
		rate = 50
	}
	conc := opts.Concurrency
	if conc <= 0 {
		conc = 25
	}
	if conc > 100 {
		conc = 100
	}
	runCtx := ctx
	var cancel context.CancelFunc
	if opts.TimeoutSeconds > 0 {
		runCtx, cancel = context.WithTimeout(ctx, time.Duration(opts.TimeoutSeconds)*time.Second)
		defer cancel()
	}
	rrDir := filepath.Join(tmp, "rr")

	// A multi-request template (login -> act -> verify, or upload -> fetch)
	// changes server state between its own requests. Run enough of those at once
	// and one chain reads a session or an uploaded file that another chain has
	// just overwritten, so the same POC set returns a different hit count on
	// every pass. Chains therefore run at a capped concurrency while single
	// requests keep the configured speed.
	groups := buildNucleiGroups(templates, targets, conc, rate)
	for _, g := range groups {
		if strings.HasSuffix(g.dir, "chains") {
			run.Chains += len(g.templates)
		} else {
			run.Singles += len(g.templates)
		}
		if g.raw {
			run.RawTargets = len(g.targets)
			run.RawTemplates += len(g.templates)
		}
	}

	var stdout, stderr limitedBuffer
	stdout.limit, stderr.limit = maxNucleiOutput, 256<<10
	started := time.Now()
	for _, g := range groups {
		gdir := filepath.Join(tmp, g.dir)
		if err := os.Mkdir(gdir, 0o700); err != nil {
			run.Err = err
			return run
		}
		targetFile := filepath.Join(gdir, "targets.txt")
		if err := os.WriteFile(targetFile, []byte(strings.Join(g.targets, "\n")+"\n"), 0o600); err != nil {
			run.Err = fmt.Errorf("写入目标失败: %w", err)
			return run
		}
		for i, tpl := range g.templates {
			name := fmt.Sprintf("%04d-%s.yaml", i, safeFilePart(tpl.ID))
			content := raiseNetworkReadSize(tpl.Content, minNetworkReadSize)
			if err := os.WriteFile(filepath.Join(gdir, name), []byte(content), 0o600); err != nil {
				run.Err = fmt.Errorf("写入模板失败: %w", err)
				return run
			}
		}
		args := []string{
			"-t", gdir,
			"-l", targetFile,
			"-jsonl", "-irr", "-silent", "-no-color", "-disable-update-check", "-no-interactsh",
			"-rate-limit", strconv.Itoa(g.rateLimit),
			"-concurrency", strconv.Itoa(g.concurrency),
			"-timeout", "10",
			"-retries", "1",
			"-store-resp", "-store-resp-dir", rrDir,
		}
		cmd := exec.CommandContext(runCtx, nuclei, args...)
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		if err := cmd.Run(); err != nil && run.Err == nil {
			run.Err = err
		}
	}
	run.Elapsed = time.Since(started)
	run.TimedOut = errors.Is(runCtx.Err(), context.DeadlineExceeded)
	run.Stdout = stdout.String()
	run.Stderr = stderr.String()
	run.Results = ParseNucleiJSONL(run.Stdout)
	applyStoredExchanges(run.Results, rrDir)
	sanitizeResultTexts(run.Results)
	return run
}

// StatefulChainConcurrency / statefulChainRateLimit keep multi-request chains
// slow enough that they cannot clobber each other's server-side state.
const (
	StatefulChainConcurrency = 4
	statefulChainRateLimit   = 8
)

type nucleiGroup struct {
	templates   []NucleiTemplate
	targets     []string
	concurrency int
	rateLimit   int
	dir         string
	raw         bool // non-HTTP-port targets probed with raw-protocol POCs only
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// buildNucleiGroups splits one scan into the nuclei invocations the engine
// runs, on two axes. By statefulness (multi-request templates need capped
// concurrency so they cannot clobber each other's server-side state), and by
// target kind: a raw host:port that discovery did not fingerprint as HTTP is
// probed only with raw-protocol POCs.
func buildNucleiGroups(templates []NucleiTemplate, targets []string, conc, rate int) []nucleiGroup {
	webTargets, rawTargets := splitNucleiTargets(targets)
	chainConc := conc
	if chainConc > StatefulChainConcurrency {
		chainConc = StatefulChainConcurrency
	}
	chainRate := minInt(rate, statefulChainRateLimit)

	classified := make([]templateClass, len(templates))
	for i, tpl := range templates {
		classified[i] = analyzeTemplate(tpl.Content)
	}
	pickStateful := func(stateful bool) []NucleiTemplate {
		out := []NucleiTemplate{}
		for i, tpl := range templates {
			if classified[i].stateful == stateful {
				out = append(out, tpl)
			}
		}
		return out
	}

	var groups []nucleiGroup
	if len(webTargets) > 0 {
		if chains := pickStateful(true); len(chains) > 0 {
			groups = append(groups, nucleiGroup{templates: chains, targets: webTargets,
				concurrency: chainConc, rateLimit: chainRate, dir: "chains"})
		}
		if singles := pickStateful(false); len(singles) > 0 {
			groups = append(groups, nucleiGroup{templates: singles, targets: webTargets,
				concurrency: conc, rateLimit: rate, dir: "single"})
		}
	}
	if len(rawTargets) > 0 {
		var rawChains, rawSingles []NucleiTemplate
		for i, tpl := range templates {
			if !classified[i].rawOK {
				continue
			}
			if classified[i].stateful {
				rawChains = append(rawChains, tpl)
			} else {
				rawSingles = append(rawSingles, tpl)
			}
		}
		if len(rawChains) > 0 {
			groups = append(groups, nucleiGroup{templates: rawChains, targets: rawTargets,
				concurrency: chainConc, rateLimit: chainRate, dir: "raw-chains", raw: true})
		}
		if len(rawSingles) > 0 {
			groups = append(groups, nucleiGroup{templates: rawSingles, targets: rawTargets,
				concurrency: conc, rateLimit: rate, dir: "raw-single", raw: true})
		}
	}
	return groups
}

// splitNucleiTargets separates web targets — URLs, or host:port on a web port,
// which keeps HTTP coverage when discovery missed the fingerprint — from raw
// host:port targets whose service HTTP POCs would only poison the run.
func splitNucleiTargets(targets []string) (web, raw []string) {
	for _, t := range targets {
		if isWebTarget(t) {
			web = append(web, t)
		} else {
			raw = append(raw, t)
		}
	}
	return web, raw
}

func isWebTarget(t string) bool {
	t = strings.TrimSpace(t)
	if strings.Contains(t, "://") {
		return true
	}
	if _, port, err := net.SplitHostPort(t); err == nil {
		if p, err := strconv.Atoi(port); err == nil && IsWebPort(p) {
			return true
		}
	}
	return false
}

// templateClass is the per-template classification used to build run groups.
type templateClass struct {
	stateful bool // keeps server-side state across its own requests
	rawOK    bool // safe and meaningful against a non-HTTP port
}

// rawProtocolKeyRe / webOnlyProtocolRe classify templates whose YAML is too
// malformed to parse: the raw set needs a raw-protocol section and must not
// carry a protocol whose client would wrap the target in HTTP.
var (
	rawProtocolKeyRe  = regexp.MustCompile(`(?m)^(tcp|network|javascript|ssl|dns)\s*:`)
	webOnlyProtocolRe = regexp.MustCompile(`(?m)^(http|headless|code|file|workflow)\s*:`)
)

// analyzeTemplate reports whether a template keeps server-side state across
// its own requests, and whether it may run against raw non-HTTP ports. Nuclei
// parses YAML, so the check reads the parsed shape: more than one raw request
// or path, a redirect hop, cookie reuse, req-condition chaining, or several
// network writes make a template stateful; a template is raw-capable when it
// speaks a raw protocol (tcp/network/javascript/ssl/dns) and has no HTTP-style
// section whose client would wrap a raw port in http(s)://. Malformed YAML
// falls back to textual markers so a template is never run fast by accident.
func analyzeTemplate(content string) templateClass {
	var top map[string]yaml.Node
	if err := yaml.Unmarshal([]byte(content), &top); err == nil {
		tc := templateClass{rawOK: rawCapable(top)}
		tc.stateful = httpSectionStateful(top["http"]) || inputsStateful(top["network"]) ||
			inputsStateful(top["tcp"])
		return tc
	}
	lower := strings.ToLower(content)
	return templateClass{
		stateful: strings.Contains(lower, "cookie-reuse") || strings.Contains(lower, "req-condition") ||
			strings.Count(lower, "http/1.") > 1,
		rawOK: rawProtocolKeyRe.MatchString(content) && !webOnlyProtocolRe.MatchString(content),
	}
}

func rawCapable(top map[string]yaml.Node) bool {
	for _, key := range []string{"http", "headless", "code", "file", "workflow"} {
		if _, ok := top[key]; ok {
			return false
		}
	}
	for _, key := range []string{"tcp", "network", "javascript", "ssl", "dns"} {
		if _, ok := top[key]; ok {
			return true
		}
	}
	return false
}

func httpSectionStateful(node yaml.Node) bool {
	if node.Kind == 0 {
		return false
	}
	var sections []struct {
		Raw          []string `yaml:"raw"`
		Path         []string `yaml:"path"`
		CookieReuse  bool     `yaml:"cookie-reuse"`
		ReqCondition bool     `yaml:"req-condition"`
		Redirects    bool     `yaml:"redirects"`
	}
	if err := node.Decode(&sections); err != nil {
		return false
	}
	for _, h := range sections {
		if len(h.Raw) > 1 || len(h.Path) > 1 || h.CookieReuse || h.ReqCondition || h.Redirects {
			return true
		}
	}
	return false
}

func inputsStateful(node yaml.Node) bool {
	if node.Kind == 0 {
		return false
	}
	var sections []struct {
		Inputs []map[string]any `yaml:"inputs"`
	}
	if err := node.Decode(&sections); err != nil {
		return false
	}
	for _, s := range sections {
		if len(s.Inputs) > 1 {
			return true
		}
	}
	return false
}

// PacketText renders bytes captured off the wire as text a Postgres text column
// (and a DOCX report) can hold: NUL is dropped and every byte that is not valid
// UTF-8 becomes a \xNN escape. Undecodable bytes are exactly what makes binary
// protocol responses (MySQL, Redis, TLS) and GBK/Shift-JIS pages worth keeping in
// a report, so they are shown as hex instead of being flattened to U+FFFD or
// aborting the write and losing the finding.
func PacketText(s string) string {
	if s == "" || utf8.ValidString(s) {
		return strings.ReplaceAll(s, "\x00", "")
	}
	var b strings.Builder
	b.Grow(len(s) + 16)
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			if s[i] == 0 {
				i++
				continue
			}
			fmt.Fprintf(&b, `\x%02x`, s[i])
			i++
			continue
		}
		b.WriteString(s[i : i+size])
		i += size
	}
	return b.String()
}

// sanitizeResultTexts rewrites every text field of a nuclei hit through
// PacketText, including the reproduction sequence and the raw JSONL map, so no
// caller can persist (or render) a byte Postgres would reject.
func sanitizeResultTexts(results []NucleiResult) {
	for i := range results {
		r := &results[i]
		r.Name = PacketText(r.Name)
		r.MatchedAt = PacketText(r.MatchedAt)
		r.Host = PacketText(r.Host)
		r.Curl = PacketText(r.Curl)
		r.Request = PacketText(r.Request)
		r.Response = PacketText(r.Response)
		for j := range r.Extracted {
			r.Extracted[j] = PacketText(r.Extracted[j])
		}
		for j := range r.Exchanges {
			r.Exchanges[j].Request = PacketText(r.Exchanges[j].Request)
			r.Exchanges[j].Response = PacketText(r.Exchanges[j].Response)
		}
		for k, v := range r.Raw {
			if s, ok := v.(string); ok {
				r.Raw[k] = PacketText(s)
			}
		}
	}
}

// applyStoredExchanges replaces the JSON request/response (where nuclei masks
// Cookie and Authorization values as ***) with the unredacted exchange it wrote
// through -store-resp. Reports and findings then carry replayable packets.
func applyStoredExchanges(results []NucleiResult, rrDir string) {
	store := ParseNucleiStore(rrDir)
	if len(store.ByURL) == 0 && len(store.ByRequest) == 0 {
		return
	}
	for i := range results {
		key := results[i].TemplateID + "|" + results[i].MatchedAt
		pair, ok := store.ByURL[key]
		file := store.urlFile[key]
		if !ok || strings.Contains(pair.Request, "Cookie: ***") {
			// Redirect-following templates report a matched URL whose exchange
			// is stored under the original request path, so fall back to the
			// captured request line.
			if line := firstRequestLine(results[i].Request); line != "" {
				reqKey := results[i].TemplateID + "|" + line
				if fallback, found := store.ByRequest[reqKey]; found {
					pair, ok, file = fallback, true, store.reqFile[reqKey]
				}
			}
		}
		session := store.sessionHeaders(results[i].TemplateID, results[i].MatchedAt)
		if ok {
			if strings.TrimSpace(pair.Request) != "" {
				results[i].Request = pair.Request
			}
			if strings.TrimSpace(pair.Response) != "" {
				results[i].Response = pair.Response
			}
			results[i].Exchanges = reproductionSequence(store.Files[file], pair)
			if len(session) == 0 {
				session = realAuthHeaders(pair.Request)
			}
		}
		applySessionHeaders(&results[i], session)
	}
}

// sessionHeaders returns the unredacted session headers one template sent to one
// host, taken from any exchange it dumped. A template that needs a login carries
// the session on every request after it, so the pair matched to a specific hit
// is not the only place the real value appears: the hit's own JSON request and
// curl command stay masked even when no exchange key lines up.
func (s NucleiStore) sessionHeaders(templateID, matchedAt string) map[string]string {
	return s.AuthByTarget[templateID+"|"+urlHost(matchedAt)]
}

// applySessionHeaders writes the real session values back over the placeholders
// nuclei printed, in every representation of the same request: the raw packet,
// the curl command and the stored raw JSON a later stage may re-read.
func applySessionHeaders(r *NucleiResult, session map[string]string) {
	if len(session) == 0 {
		return
	}
	r.Request = unmaskAuthHeaders(r.Request, session)
	r.Curl = unmaskAuthHeaders(r.Curl, session)
	for _, key := range []string{"request", "curl-command"} {
		if s, ok := r.Raw[key].(string); ok {
			if out := unmaskAuthHeaders(s, session); out != s {
				r.Raw[key] = out
			}
		}
	}
}

// authHeaderNames hold the session material nuclei redacts.
var authHeaderNames = []string{"cookie", "authorization", "proxy-authorization"}

func isAuthHeaderName(name string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	for _, want := range authHeaderNames {
		if name == want {
			return true
		}
	}
	return false
}

// realAuthHeaders reads the session headers of a raw request, skipping the
// request line and any value nuclei already masked.
func realAuthHeaders(raw string) map[string]string {
	out := map[string]string{}
	for i, line := range strings.Split(raw, "\n") {
		if i == 0 {
			continue
		}
		line = strings.TrimRight(line, "\r\n\t ")
		if line == "" || strings.HasPrefix(line, " ") {
			break
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			break
		}
		value = strings.TrimSpace(value)
		if value == "" || strings.Contains(value, "*") || !isAuthHeaderName(name) {
			continue
		}
		out[strings.ToLower(name)] = value
	}
	return out
}

var maskedAuthValue = regexp.MustCompile("(?i)([\\s\"'`])(cookie|authorization|proxy-authorization)([ \\t]*:[ \\t]*)\\*+")

// unmaskAuthHeaders restores the session values nuclei printed as *** in both a
// raw packet and a curl argument. Only a value free of quotes is written back:
// curl wraps its arguments in single quotes, and a session containing one would
// split the command line the report reader copies.
func unmaskAuthHeaders(text string, session map[string]string) string {
	if text == "" || len(session) == 0 || !strings.Contains(text, "*") {
		return text
	}
	return maskedAuthValue.ReplaceAllStringFunc(text, func(match string) string {
		groups := maskedAuthValue.FindStringSubmatch(match)
		value := session[strings.ToLower(groups[2])]
		if value == "" || strings.ContainsAny(value, "'\"") {
			return match
		}
		return groups[1] + groups[2] + groups[3] + value
	})
}

// urlHost returns the host:port a URL points at, or the whole string when it
// cannot be parsed, so store keys built from two different sources still line up.
func urlHost(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return strings.TrimSpace(raw)
	}
	return u.Host
}

// reproductionSequence returns the exchanges nuclei recorded for one hit in
// order, dropping session bootstrap requests (login/sign-in). The matched proof
// exchange is always kept, even when the vulnerable endpoint itself is a login.
func reproductionSequence(all []rawExchange, proof rawExchange) []RawExchange {
	out := make([]RawExchange, 0, len(all))
	seen := map[string]bool{}
	for _, ex := range all {
		isProof := ex.Request == proof.Request && ex.Response == proof.Response
		if !isProof && isAuthBootstrap(ex.Request) {
			continue
		}
		key := ex.Request + "\x00" + ex.Response
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, RawExchange{Request: ex.Request, Response: ex.Response})
	}
	if len(out) == 0 {
		return []RawExchange{{Request: proof.Request, Response: proof.Response}}
	}
	return out
}

func isAuthBootstrap(request string) bool {
	line := firstRequestLine(request)
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return false
	}
	target := strings.ToLower(fields[1])
	if i := strings.IndexAny(target, "?#"); i >= 0 {
		target = target[:i]
	}
	return strings.Contains(target, "/login") || strings.Contains(target, "/signin") || strings.Contains(target, "/sign-in")
}

type rawExchange struct {
	Request  string
	Response string
}

// NucleiStore indexes raw -store-resp dumps both by the URL nuclei printed in
// the dump marker and by the actual request line, which differ when the
// template follows a redirect.
type NucleiStore struct {
	ByURL     map[string]rawExchange
	ByRequest map[string]rawExchange
	// Files keeps every exchange of one dump file in wire order; nuclei writes
	// one file per template/target, so this is the reproduction sequence.
	Files map[string][]rawExchange
	// AuthByTarget keeps the unredacted session headers per "template-id|host",
	// in the order the dumps were read so a later authenticated request wins.
	AuthByTarget map[string]map[string]string

	urlFile map[string]string
	reqFile map[string]string
}

const (
	dumpRequestMarker  = "] Dumped HTTP request for "
	dumpResponseMarker = "] Dumped HTTP response "
)

type dumpExchange struct {
	templateID string
	url        string
	request    []string
	responses  [][]string
}

// ParseNucleiStore parses the per-template dump files nuclei writes with
// -store-resp. Keys are "template-id|url" and "template-id|METHOD /path".
func ParseNucleiStore(root string) NucleiStore {
	store := NucleiStore{
		ByURL:        map[string]rawExchange{},
		ByRequest:    map[string]rawExchange{},
		Files:        map[string][]rawExchange{},
		AuthByTarget: map[string]map[string]string{},
		urlFile:      map[string]string{},
		reqFile:      map[string]string{},
	}
	files, err := filepath.Glob(filepath.Join(root, "http", "*.txt"))
	if err != nil {
		return store
	}
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil || len(data) > 32<<20 {
			continue
		}
		for _, ex := range parseDumpFile(string(data)) {
			req := trimBlankLines(ex.request)
			resp := lastNonEmptyResponse(ex.responses)
			if req == "" || resp == "" {
				continue
			}
			pair := rawExchange{Request: req, Response: resp}
			store.Files[file] = append(store.Files[file], pair)
			urlKey := ex.templateID + "|" + ex.url
			store.ByURL[urlKey] = pair
			store.urlFile[urlKey] = file
			if auth := realAuthHeaders(req); len(auth) > 0 {
				key := ex.templateID + "|" + urlHost(ex.url)
				if store.AuthByTarget[key] == nil {
					store.AuthByTarget[key] = map[string]string{}
				}
				for name, value := range auth {
					store.AuthByTarget[key][name] = value
				}
			}
			if line := firstRequestLine(req); line != "" {
				reqKey := ex.templateID + "|" + line
				store.ByRequest[reqKey] = pair
				store.reqFile[reqKey] = file
			}
		}
	}
	return store
}

func parseDumpFile(text string) []dumpExchange {
	lines := strings.Split(text, "\n")
	var out []dumpExchange
	var cur *dumpExchange
	var target *[]string
	for _, line := range lines {
		if strings.HasPrefix(line, "[") {
			if idx := strings.Index(line, dumpRequestMarker); idx > 0 {
				if cur != nil {
					out = append(out, *cur)
				}
				cur = &dumpExchange{
					templateID: strings.TrimSpace(line[1:idx]),
					url:        strings.TrimSpace(line[idx+len(dumpRequestMarker):]),
				}
				target = &cur.request
				continue
			}
			if idx := strings.Index(line, dumpResponseMarker); idx > 0 && cur != nil {
				cur.responses = append(cur.responses, nil)
				target = &cur.responses[len(cur.responses)-1]
				continue
			}
		}
		if target != nil {
			*target = append(*target, line)
		}
	}
	if cur != nil {
		out = append(out, *cur)
	}
	return out
}

func lastNonEmptyResponse(responses [][]string) string {
	for i := len(responses) - 1; i >= 0; i-- {
		if resp := trimBlankLines(responses[i]); resp != "" {
			return resp
		}
	}
	return ""
}

func firstRequestLine(raw string) string {
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			return line
		}
	}
	return ""
}

func trimBlankLines(lines []string) string {
	start, end := 0, len(lines)
	for start < end && strings.TrimSpace(lines[start]) == "" {
		start++
	}
	for end > start && strings.TrimSpace(lines[end-1]) == "" {
		end--
	}
	if start == end {
		return ""
	}
	return strings.Join(lines[start:end], "\n")
}

// ParseNucleiJSONL parses nuclei's -jsonl output, skipping malformed lines.
func ParseNucleiJSONL(raw string) []NucleiResult {
	out := []NucleiResult{}
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}
		var m map[string]any
		if json.Unmarshal([]byte(line), &m) != nil {
			continue
		}
		r := NucleiResult{
			TemplateID: asString(m["template-id"]),
			Host:       asString(m["host"]),
			MatchedAt:  asString(m["matched-at"]),
			Type:       asString(m["type"]),
			Timestamp:  asString(m["timestamp"]),
			Curl:       asString(m["curl-command"]),
			Request:    asText(m["request"]),
			Response:   asText(m["response"]),
			Raw:        m,
		}
		if info, ok := m["info"].(map[string]any); ok {
			r.Name = asString(info["name"])
			r.Severity = strings.ToLower(asString(info["severity"]))
			r.Tags = tagsFromInfo(info["tags"])
		}
		if extracted, ok := m["extracted-results"].([]any); ok {
			for _, v := range extracted {
				r.Extracted = append(r.Extracted, asString(v))
			}
		}
		if r.Extracted == nil {
			r.Extracted = []string{}
		}
		out = append(out, r)
	}
	return out
}

// tagsFromInfo reads a template's tags in whatever shape nuclei printed them:
// the JSONL event carries an array, hand-written output a comma string. Routing
// a hit to sqlmap or dalfox depends on them, and treating the array as a string
// yielded nothing, so every template was classified by its name alone.
func tagsFromInfo(v any) []string {
	var items []string
	switch t := v.(type) {
	case []any:
		for _, item := range t {
			items = append(items, asString(item))
		}
	case string:
		items = strings.Split(t, ",")
	default:
		return nil
	}
	out := make([]string, 0, len(items))
	for _, s := range items {
		if s = strings.ToLower(strings.TrimSpace(s)); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func asString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case json.Number:
		return t.String()
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	default:
		return ""
	}
}

// asText accepts the scalar or list forms nuclei uses for request/response.
func asText(v any) string {
	switch t := v.(type) {
	case []any:
		parts := make([]string, 0, len(t))
		for _, item := range t {
			parts = append(parts, asString(item))
		}
		return strings.Join(parts, "\n")
	default:
		return asString(v)
	}
}

func safeFilePart(s string) string {
	s = unsafeFilePart.ReplaceAllString(strings.TrimSpace(s), "-")
	s = strings.Trim(s, ".-")
	if s == "" {
		s = "template"
	}
	if len(s) > 80 {
		s = s[:80]
	}
	return s
}

type limitedBuffer struct {
	bytes.Buffer
	limit int
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if b.limit <= 0 {
		return b.Buffer.Write(p)
	}
	remaining := b.limit - b.Buffer.Len()
	if remaining <= 0 {
		return len(p), nil
	}
	if len(p) > remaining {
		_, _ = b.Buffer.Write(p[:remaining])
		return len(p), nil
	}
	return b.Buffer.Write(p)
}
