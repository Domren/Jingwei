package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/url"
	"regexp"
	"strings"
)

// 结构化复现过程（P0/P1）。
//
// 背景：报告里的「验证步骤」如果靠事后从 evidence 文本、报文字段去猜，遇到多步
// 利用链就会拼不全，甚至被模型补写成一段看似合理其实没发生过的过程。这里改成
// 让 agent 在 report_finding 落库的那一刻就把过程写下来：它刚执行完，最清楚哪一步
// 发了什么、目标回了什么。request/response 要求逐字取自真实收发，不做改写。
//
// P1 在此基础上再加一层：每条步骤按 method+path 顺序对到本漏洞已绑定的流量快照
// （finding_traffic_bindings），报告就能把「第 3 步」和它自己的那条报文放在一起，
// 而不是笼统地把所有报文堆在末尾。

// ReproStep is one ordered reproduction step. Request is the verbatim request the
// agent actually sent (raw HTTP packet, or the curl/shell command it ran);
// Response is the verbatim bytes the target returned, trimmed to the part that
// proves the point. Expected/Proves are one-line conclusions.
type ReproStep struct {
	Request    string `json:"request"`
	Response   string `json:"response,omitempty"`
	Expected   string `json:"expected,omitempty"`
	Proves     string `json:"proves,omitempty"`
	SnapshotID string `json:"snapshot_id,omitempty"` // 解析出的真实流量快照 ID
	Match      string `json:"match,omitempty"`       // request=按请求匹配 position=按顺序匹配
}

// Reproduction is the whole recipe: where the vuln is entered, what has to be
// true first, the ordered steps, and where the attack chain came from.
type Reproduction struct {
	EntryPoint    string      `json:"entry_point,omitempty"`
	Prerequisites []string    `json:"prerequisites,omitempty"`
	Steps         []ReproStep `json:"steps,omitempty"`
	Provenance    string      `json:"provenance,omitempty"`
}

// Empty reports whether the reproduction carries nothing worth rendering.
func (r *Reproduction) Empty() bool {
	if r == nil {
		return true
	}
	if len(r.Steps) > 0 || strings.TrimSpace(r.EntryPoint) != "" {
		return false
	}
	if strings.TrimSpace(r.Provenance) != "" {
		return false
	}
	for _, p := range r.Prerequisites {
		if strings.TrimSpace(p) != "" {
			return false
		}
	}
	return true
}

// Normalize trims every field and drops steps that ended up carrying nothing.
func (r *Reproduction) Normalize() {
	if r == nil {
		return
	}
	r.EntryPoint = strings.TrimSpace(r.EntryPoint)
	r.Provenance = strings.TrimSpace(r.Provenance)
	var pre []string
	for _, p := range r.Prerequisites {
		if p = strings.TrimSpace(p); p != "" {
			pre = append(pre, p)
		}
	}
	r.Prerequisites = pre
	steps := make([]ReproStep, 0, len(r.Steps))
	for _, st := range r.Steps {
		st.Request = strings.TrimSpace(st.Request)
		st.Response = strings.TrimSpace(st.Response)
		st.Expected = strings.TrimSpace(st.Expected)
		st.Proves = strings.TrimSpace(st.Proves)
		if st.Request == "" && st.Response == "" && st.Expected == "" && st.Proves == "" {
			continue
		}
		steps = append(steps, st)
	}
	r.Steps = steps
}

// ParseReproduction decodes a findings.reproduction column value. Empty input,
// "null" and "{}" all mean "not recorded" and return nil so callers fall back to
// the legacy reconstructed verification steps.
func ParseReproduction(raw string) *Reproduction {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "null" || raw == "{}" {
		return nil
	}
	var r Reproduction
	if err := json.Unmarshal([]byte(raw), &r); err != nil {
		return nil
	}
	r.Normalize()
	if r.Empty() {
		return nil
	}
	return &r
}

// JSON marshals the reproduction for storage, returning nil when it is empty so
// the caller can store SQL NULL instead of an empty object.
func (r *Reproduction) JSON() []byte {
	if r.Empty() {
		return nil
	}
	r.Normalize()
	raw, err := json.Marshal(r)
	if err != nil {
		return nil
	}
	return raw
}

// StepCount returns the number of usable steps.
func (r *Reproduction) StepCount() int {
	if r == nil {
		return 0
	}
	return len(r.Steps)
}

// ResolveReproSteps links each reproduction step to one of the finding's already
// bound traffic snapshots, and reports whether anything changed.
//
// Matching is deliberately conservative — a wrong link is worse than no link,
// because the report would then show a packet that does not belong to the step:
//
//  1. Parse the step's request into method+path (works for both a raw HTTP
//     request packet and a curl/shell command).
//  2. Walk the bindings in their recorded order from a moving cursor, so step 2
//     can never bind to a snapshot that sits before step 1. Agents list steps
//     chronologically, and bindings are stored in the order they were submitted,
//     so this is the same timeline.
//  3. Assign the first unused snapshot at-or-after the cursor whose method and
//     path both match.
//  4. If the request cannot be parsed (or nothing matches), fall back to plain
//     positional binding ONLY when the two lists are the same length — that is
//     the one case where "Nth step = Nth binding" is safe to assume.
func ResolveReproSteps(r *Reproduction, bindings []FindingTrafficBinding) bool {
	if r == nil || len(r.Steps) == 0 || len(bindings) == 0 {
		return false
	}
	ordered := append([]FindingTrafficBinding(nil), bindings...)
	sortBindingsByPosition(ordered)

	used := map[string]bool{}
	cursor := 0
	changed := false
	positionalOK := len(ordered) == len(r.Steps)

	for i := range r.Steps {
		st := &r.Steps[i]
		if st.SnapshotID != "" {
			for j, b := range ordered {
				if b.SnapshotID == st.SnapshotID {
					used[b.SnapshotID] = true
					if j >= cursor {
						cursor = j + 1
					}
					break
				}
			}
			continue
		}
		method, path := ParseStepRequest(st.Request)
		if method != "" && path != "" {
			for j := cursor; j < len(ordered); j++ {
				b := ordered[j]
				if used[b.SnapshotID] {
					continue
				}
				if !strings.EqualFold(strings.TrimSpace(b.Snapshot.Method), method) {
					continue
				}
				if !sameRequestPath(path, b.Snapshot.URL) {
					continue
				}
				st.SnapshotID, st.Match = b.SnapshotID, "request"
				used[b.SnapshotID] = true
				cursor = j + 1
				changed = true
				break
			}
			if st.SnapshotID != "" {
				continue
			}
		}
		if positionalOK && cursor < len(ordered) && !used[ordered[cursor].SnapshotID] {
			st.SnapshotID, st.Match = ordered[cursor].SnapshotID, "position"
			used[ordered[cursor].SnapshotID] = true
			cursor++
			changed = true
		}
	}
	return changed
}

func sortBindingsByPosition(bs []FindingTrafficBinding) {
	for i := 1; i < len(bs); i++ {
		for j := i; j > 0; j-- {
			if bs[j-1].Position < bs[j].Position ||
				(bs[j-1].Position == bs[j].Position && bs[j-1].ID <= bs[j].ID) {
				break
			}
			bs[j-1], bs[j] = bs[j], bs[j-1]
		}
	}
}

var (
	reHTTPRequestLine = regexp.MustCompile(`^([A-Z]+)\s+(\S+)\s+HTTP/\d`)
	reURLInCommand    = regexp.MustCompile("https?://[^\\s\"'`;|)<>]+")
	reCurlMethod      = regexp.MustCompile(`(?:-X|--request)\s+([A-Za-z]+)`)
	reCurlWithBody    = regexp.MustCompile(`(?:^|\s)(?:-d|--data|--data-raw|--data-binary|-F|--form)(?:\s|=)`)
)

// ParseStepRequest extracts the method and the URL path from a step's request
// text. The text is either a raw HTTP request packet ("GET /a?b=1 HTTP/1.1") or
// the curl/shell command the agent ran ("curl -X POST http://h/upload.php -F ...").
// Returns empty strings when nothing usable can be parsed, so the caller knows
// not to guess.
func ParseStepRequest(text string) (method, path string) {
	text = strings.TrimSpace(text)
	if text == "" {
		return "", ""
	}
	// 1) Raw HTTP request packet.
	if line := firstNonEmptyLine(text); line != "" {
		if m := reHTTPRequestLine.FindStringSubmatch(line); m != nil {
			return strings.ToUpper(m[1]), pathOf(m[2])
		}
	}
	// 2) curl / shell command carrying a URL.
	m := reURLInCommand.FindString(text)
	if m == "" {
		return "", ""
	}
	method = "GET"
	if mm := reCurlMethod.FindStringSubmatch(text); mm != nil {
		method = strings.ToUpper(mm[1])
	} else if reCurlWithBody.MatchString(text) {
		method = "POST"
	}
	return method, pathOf(m)
}

// pathOf normalizes a request target or absolute URL down to its path, so
// "/upload.php" and "http://lab/upload.php" compare equal.
func pathOf(target string) string {
	target = strings.TrimSpace(target)
	if target == "" {
		return ""
	}
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		u, err := url.Parse(target)
		if err != nil {
			return ""
		}
		return cleanPath(u.Path)
	}
	if i := strings.IndexAny(target, "?#"); i >= 0 {
		target = target[:i]
	}
	return cleanPath(target)
}

func cleanPath(p string) string {
	if p == "" {
		return "/"
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	if len(p) > 1 {
		p = strings.TrimRight(p, "/")
		if p == "" {
			p = "/"
		}
	}
	return p
}

// sameRequestPath compares a step's path against a snapshot's URL path.
func sameRequestPath(stepPath, snapshotURL string) bool {
	sp := cleanPath(stepPath)
	snapPath := pathOf(snapshotURL)
	if snapPath == "" {
		return false
	}
	if strings.EqualFold(sp, snapPath) {
		return true
	}
	// Snapshot URLs sometimes carry a trailing slash or an extra prefix
	// (http://host:8080/pikachu/vul/x.php); accept a suffix match on segment
	// boundaries so the real endpoint still resolves.
	return strings.HasSuffix(strings.ToLower(snapPath), strings.ToLower(sp)) &&
		len(snapPath) > len(sp) &&
		snapPath[len(snapPath)-len(sp)-1] == '/'
}

func firstNonEmptyLine(s string) string {
	for _, line := range strings.Split(s, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			return line
		}
	}
	return ""
}

// storeReproductionTx persists the structured reproduction inside the finding's
// own transaction, resolving every step onto the snapshots bound in that same
// transaction first. An empty reproduction leaves the column untouched: a later
// re-report that omits the recipe must not wipe a good one.
func storeReproductionTx(tx *sql.Tx, findingID int64, repro *Reproduction, bindings []FindingTrafficBinding) (bool, error) {
	if findingID <= 0 || repro.Empty() {
		return false, nil
	}
	ResolveReproSteps(repro, bindings)
	raw := repro.JSON()
	if len(raw) == 0 {
		return false, nil
	}
	res, err := tx.Exec(`UPDATE findings SET reproduction = $2::jsonb WHERE id = $1`, findingID, string(raw))
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// GetFindingReproduction loads a finding's structured reproduction (nil when it
// was never recorded).
func (d *DB) GetFindingReproduction(ctx context.Context, findingID int64) (*Reproduction, error) {
	var raw string
	err := d.QueryRowContext(ctx, `SELECT COALESCE(reproduction::text, '') FROM findings WHERE id=$1`, findingID).Scan(&raw)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return ParseReproduction(raw), nil
}

// ReResolveFindingReproduction re-links a stored reproduction to the finding's
// current bindings. Used after traffic is bound later (bind_finding_traffic,
// manual link in the UI): the steps were recorded before those packets existed,
// so their snapshot links have to be filled in now.
func (d *DB) ReResolveFindingReproduction(ctx context.Context, findingID int64) error {
	repro, err := d.GetFindingReproduction(ctx, findingID)
	if err != nil || repro == nil || len(repro.Steps) == 0 {
		return err
	}
	traffic, err := d.GetFindingTraffic(ctx, findingID)
	if err != nil || traffic == nil || len(traffic.Bindings) == 0 {
		return err
	}
	if !ResolveReproSteps(repro, traffic.Bindings) {
		return nil
	}
	raw := repro.JSON()
	if len(raw) == 0 {
		return nil
	}
	_, err = d.ExecContext(ctx, `UPDATE findings SET reproduction = $2::jsonb WHERE id = $1`, findingID, string(raw))
	return err
}
