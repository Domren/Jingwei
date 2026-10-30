package server

import (
	"archive/zip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/jingwei/db"
	"github.com/Autumn-27/jingwei/evidence"
	"github.com/Autumn-27/jingwei/report"
)

const maxHydratedPacketBytes = 512 << 10

// maxEvidencePacketsPerFinding bounds the reproduction sequence rendered per
// finding. Findings dedupe across scan rounds while every round re-binds its own
// capture of the same steps, so an unbounded list buries the proof under 20+
// repeats. The evidence ZIP still carries every binding.
const maxEvidencePacketsPerFinding = 8

// hydrateFindingRawHTTP fills a finding's missing HTTPRequest/HTTPResponse from
// its bound traffic and hydrates the bindings into EvidencePackets so the report
// can show the complete reproduction sequence. Bytes come from the captured wire
// data (head + body) copied into the export stage; nothing is synthesized.
// Repeated captures of the same step are folded into one entry, so the report
// says what it merged instead of quietly growing every round. Findings without a
// binding or without a stored body are left empty so the report can state
// explicitly that no raw packet was captured.
func hydrateFindingRawHTTP(findings []*db.DBFinding, stage string) {
	store := evidence.New(nil, nil, stage)
	for _, f := range findings {
		f.EvidencePackets = nil
		f.EvidencePacketOmitted = 0
		if len(f.TrafficBindings) == 0 {
			continue
		}
		packets := make([]db.FindingEvidencePacket, 0, len(f.TrafficBindings))
		byStep := map[string]int{}
		for _, binding := range f.TrafficBindings {
			packet := db.FindingEvidencePacket{
				BindingID:    binding.ID,
				Role:         binding.Role,
				Note:         binding.Note,
				Snapshot:     binding.Snapshot,
				HTTPRequest:  readRawPacket(store, binding.Snapshot, "request", binding.Snapshot.ReqHead),
				HTTPResponse: readRawPacket(store, binding.Snapshot, "response", binding.Snapshot.RespHead),
			}
			if packet.HTTPRequest == "" && packet.HTTPResponse == "" {
				continue
			}
			key := evidenceExchangeKey(binding)
			if i, merged := byStep[key]; merged {
				// Same step captured again by a later round: show the newest bytes
				// and state how many repeats were folded into this entry.
				packet.Repeated = packets[i].Repeated + 1
				packets[i] = packet
				continue
			}
			byStep[key] = len(packets)
			packets = append(packets, packet)
		}
		if len(packets) == 0 {
			continue
		}
		var omitted int
		packets, omitted = selectEvidencePackets(packets, f.VulnClass, f.Name)
		f.EvidencePacketOmitted = omitted
		best := 0
		bestScore := evidencePacketScore(packets[0], f.VulnClass, f.Name)
		for i := 1; i < len(packets); i++ {
			if score := evidencePacketScore(packets[i], f.VulnClass, f.Name); score > bestScore {
				best, bestScore = i, score
			}
		}
		packets[best].Primary = true
		if strings.TrimSpace(f.HTTPRequest) == "" {
			f.HTTPRequest = packets[best].HTTPRequest
		}
		if strings.TrimSpace(f.HTTPResponse) == "" {
			f.HTTPResponse = packets[best].HTTPResponse
		}
		f.EvidencePackets = packets
	}
}

// evidenceExchangeKey identifies one reproduction step. Later rounds re-send the
// same request with a fresh session cookie, so the request bytes are never
// byte-identical; role + endpoint + status + response signature is what proves
// the step replayed the same way, and request length still separates distinct
// payloads sent to the same endpoint.
func evidenceExchangeKey(binding db.FindingTrafficBinding) string {
	snap := binding.Snapshot
	if snap.URL == "" && snap.RespHash == "" {
		return "snapshot:" + snap.ID
	}
	return strings.Join([]string{binding.Role, snap.Method, snap.URL, strconv.Itoa(snap.Status),
		snap.RespHash, strconv.FormatInt(snap.ReqLen, 10), strconv.FormatInt(snap.RespLen, 10)}, "\x00")
}

// selectEvidencePackets keeps the most decisive exchanges for the report while
// preserving wire order, and returns how many captured exchanges are not shown.
func selectEvidencePackets(packets []db.FindingEvidencePacket, vulnClass, name string) ([]db.FindingEvidencePacket, int) {
	if len(packets) <= maxEvidencePacketsPerFinding {
		return packets, 0
	}
	ranked := make([]int, len(packets))
	for i := range packets {
		ranked[i] = i
	}
	sort.SliceStable(ranked, func(a, b int) bool {
		return evidencePacketScore(packets[ranked[a]], vulnClass, name) >
			evidencePacketScore(packets[ranked[b]], vulnClass, name)
	})
	keep := make([]bool, len(packets))
	for _, idx := range ranked[:maxEvidencePacketsPerFinding] {
		keep[idx] = true
	}
	kept := make([]db.FindingEvidencePacket, 0, maxEvidencePacketsPerFinding)
	omitted := 0
	for i, packet := range packets {
		if keep[i] {
			kept = append(kept, packet)
			continue
		}
		omitted += packet.Repeated + 1
	}
	return kept, omitted
}

var (
	evidenceRoleRank = map[string]int{"proof": 40, "verification": 30, "supporting": 20, "baseline": 0}
	sqlHashPacketRE  = regexp.MustCompile(`(?i)surname\s*:\s*[0-9a-f]{32}`)
)

// evidencePacketScore ranks hydrated exchanges by how directly their recorded
// bytes demonstrate the finding. Reproduction sequences legitimately contain
// failed attempts before the proof and cleanup requests after it, so success and
// failure markers outweigh the binding role.
func evidencePacketScore(packet db.FindingEvidencePacket, vulnClass, name string) int {
	score, ok := evidenceRoleRank[packet.Role]
	if !ok {
		score = 10
	}
	class := strings.ToLower(vulnClass + " " + name)
	resp := strings.ToLower(packet.HTTPResponse)
	switch {
	case strings.Contains(resp, "password changed"):
		score += 60
	case strings.Contains(resp, "passwords do not match"):
		score -= 20
	}
	if strings.Contains(resp, "welcome to the password protected area") || strings.Contains(resp, "you have logged in as") {
		score += 50
	}
	if strings.Contains(resp, "incorrect") && strings.Contains(resp, "password") {
		score -= 40
	}
	if strings.Contains(resp, "successfully uploaded") || strings.Contains(resp, "succesfully uploaded") {
		score += 50
	}
	if strings.Contains(resp, "root:x:0:0:") {
		score += 50
	}
	if strings.Contains(resp, "uid=") && strings.Contains(resp, "gid=") {
		score += 50
	}
	if strings.Contains(resp, "user id exists in the database") || strings.Contains(resp, "user id is missing from the database") {
		score += 40
	}
	if strings.Contains(resp, "sql syntax") || strings.Contains(resp, "sqlstate[") || strings.Contains(resp, "surname:") {
		score += 30
	}
	if sqlHashPacketRE.MatchString(resp) {
		score += 20
	}
	if strings.Contains(class, "session") || strings.Contains(class, "会话") || strings.Contains(class, "cookie") {
		if strings.Contains(resp, "set-cookie:") {
			score += 30
		}
	}
	if isXSSFinding(class) {
		if requestReflected(packet.HTTPRequest, packet.HTTPResponse) {
			score += 30
		}
	}
	return score
}

// isXSSFinding keeps CSRF findings out of the reflection bonus: their names are
// built from 跨站请求伪造, and generic values such as "password" are echoed by
// ordinary forms, which would otherwise rank a cleanup request above the exploit.
func isXSSFinding(class string) bool {
	if strings.Contains(class, "csrf") || strings.Contains(class, "跨站请求伪造") || strings.Contains(class, "请求伪造") {
		return false
	}
	return strings.Contains(class, "xss") || strings.Contains(class, "跨站脚本") ||
		strings.Contains(class, "cross-site scripting")
}

// requestReflected reports whether a request parameter value is echoed back in
// the recorded response, the decisive signal for reflected/stored XSS packets.
func requestReflected(reqRaw, respRaw string) bool {
	req := strings.ReplaceAll(reqRaw, "\r\n", "\n")
	head, body := req, ""
	if i := strings.Index(req, "\n\n"); i >= 0 {
		head, body = req[:i], req[i+2:]
	}
	var values []string
	if fields := strings.Fields(head); len(fields) > 1 {
		if u, err := url.Parse(fields[1]); err == nil {
			for _, vs := range u.Query() {
				values = append(values, vs...)
			}
		}
	}
	for _, pair := range strings.Split(body, "&") {
		if _, v, ok := strings.Cut(pair, "="); ok {
			if dec, err := url.QueryUnescape(v); err == nil {
				values = append(values, dec)
			}
		}
	}
	for _, v := range values {
		v = strings.TrimSpace(v)
		if len(v) >= 8 && strings.Contains(respRaw, v) {
			return true
		}
	}
	return false
}

func readRawPacket(store *evidence.Store, snap db.TrafficEvidenceSnapshot, side, head string) string {
	head = strings.TrimRight(strings.ReplaceAll(head, "\r\n", "\n"), "\n")
	body := ""
	if file, _, err := store.OpenBody(snap, side); err == nil {
		defer file.Close()
		if data, readErr := io.ReadAll(io.LimitReader(file, maxHydratedPacketBytes+1)); readErr == nil {
			body = string(data)
		}
	}
	if head == "" && body == "" {
		return ""
	}
	return head + "\r\n\r\n" + body
}

func writeFindingsEvidenceZip(out io.Writer, findings []*db.DBFinding, stage string, now time.Time) error {
	zw := zip.NewWriter(out)
	if err := writeFindingsZipEntries(zw, findings, stage, now); err != nil {
		zw.Close()
		return err
	}
	return zw.Close()
}

func writeFindingsZipEntries(zw *zip.Writer, findings []*db.DBFinding, stage string, now time.Time) error {
	store := evidence.New(nil, nil, stage) // private export copy; not subject to GC
	used := map[string]int{}
	evidencePaths := map[string]bool{}
	for _, f := range findings {
		base := report.FindingFilename(f)
		name := base
		if n := used[base]; n > 0 {
			name = fmt.Sprintf("%s-%d.md", strings.TrimSuffix(base, ".md"), n+1)
		}
		used[base]++
		w, err := zw.Create(name)
		if err != nil {
			return err
		}
		if _, err = io.WriteString(w, report.SingleFindingMarkdown(f, now)); err != nil {
			return err
		}
		for _, b := range f.TrafficBindings {
			prefix := fmt.Sprintf("evidence/%d/%d/", f.ID, b.ID)
			if evidencePaths[prefix] {
				continue
			}
			evidencePaths[prefix] = true
			w, err := zw.Create(prefix + "manifest.json")
			if err != nil {
				return err
			}
			if err = json.NewEncoder(w).Encode(b); err != nil {
				return err
			}
			for _, side := range []string{"request", "response"} {
				if err := func() error {
					body, _, err := store.OpenBody(b.Snapshot, side)
					if err != nil {
						return err
					}
					defer body.Close()
					w, err := zw.Create(prefix + side + ".http")
					if err != nil {
						return err
					}
					head := b.Snapshot.ReqHead
					if side == "response" {
						head = b.Snapshot.RespHead
					}
					if _, err = io.WriteString(w, strings.TrimRight(head, "\r\n")+"\n\n"); err != nil {
						return err
					}
					if _, err = io.Copy(w, body); err != nil {
						return err
					}
					if _, err = body.Seek(0, io.SeekStart); err != nil {
						return err
					}
					w, err = zw.Create(prefix + side + ".bin")
					if err != nil {
						return err
					}
					_, err = io.Copy(w, body)
					return err
				}(); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func buildFindingsEvidenceZip(path string, findings []*db.DBFinding, stage string, now time.Time) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	writeErr := writeFindingsEvidenceZip(f, findings, stage, now)
	syncErr := f.Sync()
	closeErr := f.Close()
	if err := errors.Join(writeErr, syncErr, closeErr); err != nil {
		return err
	}
	// Re-read every compressed entry to validate the finished ZIP, including CRCs,
	// before the caller starts an HTTP download response.
	archive, err := zip.OpenReader(path)
	if err != nil {
		return err
	}
	defer archive.Close()
	for _, entry := range archive.File {
		r, err := entry.Open()
		if err != nil {
			return err
		}
		_, readErr := io.Copy(io.Discard, r)
		if err := errors.Join(readErr, r.Close()); err != nil {
			return err
		}
	}
	return nil
}
