// Package evidence preserves finding evidence independently of disposable traffic.
package evidence

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/jingwei/db"
	"github.com/Autumn-27/jingwei/report"
	"github.com/Autumn-27/jingwei/traffic"
)

type Store struct {
	DB      *db.DB
	Traffic *traffic.Traffic
	Dir     string
}

func New(pg *db.DB, tr *traffic.Traffic, dir string) *Store {
	return &Store{DB: pg, Traffic: tr, Dir: dir}
}

// RawExchange is an unredacted request/response pair captured by a scanner
// outside the traffic store. SaveRawExchanges splits, hashes and persists the
// wire bytes so the finding keeps a replayable reproduction sequence.
type RawExchange struct {
	Request  string
	Response string
	Role     string
	Note     string
}

func splitRawPacket(raw string) (head, body string) {
	raw = strings.ReplaceAll(raw, "\r\n", "\n")
	raw = strings.TrimLeft(raw, "\n")
	if i := strings.Index(raw, "\n\n"); i >= 0 {
		head, body = raw[:i], raw[i+2:]
	} else {
		head = raw
	}
	return strings.TrimRight(head, "\n"), body
}

func packetFirstLine(head string) string {
	for _, line := range strings.Split(head, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			return line
		}
	}
	return ""
}

func packetHeader(head, name string) string {
	name = strings.ToLower(name) + ":"
	for _, line := range strings.Split(head, "\n") {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(line)), name) {
			return strings.TrimSpace(strings.TrimSpace(line)[len(name):])
		}
	}
	return ""
}

// SaveRawExchanges appends a scanner's reproduction sequence to a finding.
// Snapshots are content addressed, so re-running the same scan is idempotent.
func (s *Store) SaveRawExchanges(ctx context.Context, findingID int64, exchanges []RawExchange) error {
	if findingID <= 0 || len(exchanges) == 0 {
		return nil
	}
	prepared := make([]db.PreparedTrafficEvidence, 0, len(exchanges))
	for _, ex := range exchanges {
		reqHead, reqBody := splitRawPacket(ex.Request)
		respHead, respBody := splitRawPacket(ex.Response)
		if reqHead == "" {
			continue
		}
		reqHash, err := s.writeBody(bytes.NewReader([]byte(reqBody)), int64(len(reqBody)), "")
		if err != nil {
			return err
		}
		respHash, err := s.writeBody(bytes.NewReader([]byte(respBody)), int64(len(respBody)), "")
		if err != nil {
			return err
		}
		method, target := "GET", ""
		if fields := strings.Fields(packetFirstLine(reqHead)); len(fields) >= 2 {
			method, target = fields[0], fields[1]
		}
		u := target
		if strings.HasPrefix(target, "/") {
			if host := packetHeader(reqHead, "host"); host != "" {
				u = "http://" + host + target
			}
		}
		status := 0
		if fields := strings.Fields(packetFirstLine(respHead)); len(fields) >= 2 {
			status, _ = strconv.Atoi(fields[1])
		}
		role := strings.TrimSpace(ex.Role)
		if role == "" {
			role = "supporting"
		}
		snap := db.TrafficEvidenceSnapshot{
			CapturedAt:  time.Now().Unix(),
			URL:         u,
			Method:      method,
			Status:      status,
			ContentType: packetHeader(respHead, "content-type"),
			ReqHead:     reqHead,
			RespHead:    respHead,
			ReqHash:     reqHash,
			RespHash:    respHash,
			ReqLen:      int64(len(reqBody)),
			RespLen:     int64(len(respBody)),
		}.Normalize()
		snap.ID = db.TrafficSnapshotID(snap)
		prepared = append(prepared, db.PreparedTrafficEvidence{
			Ref:      db.TrafficRef{Role: role, Note: strings.TrimSpace(ex.Note)},
			Snapshot: snap,
		})
	}
	if len(prepared) == 0 {
		return nil
	}
	return s.DB.WithEvidenceTx(ctx, func(tx *sql.Tx) error {
		if err := db.LockFindingEvidenceTx(tx, findingID, nil); err != nil {
			return err
		}
		return db.AddFindingTrafficTx(tx, findingID, prepared)
	})
}

func hashPath(dir, hash string) (string, error) {
	if len(hash) != 64 {
		return "", errors.New("invalid evidence hash")
	}
	if _, err := hex.DecodeString(hash); err != nil || strings.ToLower(hash) != hash {
		return "", errors.New("invalid evidence hash")
	}
	return filepath.Join(dir, "blobs", hash[:2], hash+".bin"), nil
}

func verifyFile(path, hash string, length int64) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return err
	}
	if n != length || hex.EncodeToString(h.Sum(nil)) != hash {
		return fmt.Errorf("证据正文校验失败: %s", hash)
	}
	return nil
}

// A new body becomes visible only after a durable write. Failed SQL commits may
// leave unreferenced files; GC reaps those after a full day's grace period.
func (s *Store) writeBody(r io.Reader, expectedLength int64, expectedHash string) (hash string, err error) {
	stage := filepath.Join(s.Dir, ".staging")
	if err = os.MkdirAll(stage, 0o700); err != nil {
		return
	}
	f, err := os.CreateTemp(stage, "body-")
	if err != nil {
		return "", err
	}
	defer func() { f.Close(); os.Remove(f.Name()) }()
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), r)
	if err != nil {
		return "", err
	}
	hash = hex.EncodeToString(h.Sum(nil))
	if n != expectedLength {
		return "", fmt.Errorf("正文不完整: 预期 %d 字节，读取 %d 字节", expectedLength, n)
	}
	if expectedHash != "" && expectedHash != hash {
		return "", errors.New("原始流量正文哈希不匹配")
	}
	if err = f.Sync(); err != nil {
		return "", err
	}
	if err = f.Close(); err != nil {
		return "", err
	}
	path, err := hashPath(s.Dir, hash)
	if err != nil {
		return "", err
	}
	if _, err = os.Stat(path); err == nil {
		if err = verifyFile(path, hash, n); err != nil {
			return "", err
		}
		// Refresh the grace period for a restored but not-yet-committed body.
		now := time.Now()
		return hash, os.Chtimes(path, now, now)
	} else if !os.IsNotExist(err) {
		return "", err
	}
	if err = os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}
	if err = os.Rename(f.Name(), path); err != nil {
		return "", err
	}
	d, err := os.Open(filepath.Dir(path))
	if err != nil {
		return "", err
	}
	defer d.Close()
	return hash, d.Sync()
}

// StageFindingsExport freezes bindings/report versions and makes private body
// copies before the HTTP response is started. The caller owns and removes dest.
func (s *Store) StageFindingsExport(ctx context.Context, findings []*db.DBFinding, dest string, copyBodies bool) error {
	return s.DB.WithEvidenceTx(ctx, func(tx *sql.Tx) error {
		var snapshots []db.TrafficEvidenceSnapshot
		for _, f := range findings {
			list, err := db.FindingTrafficTx(tx, f.ID)
			if err != nil {
				return err
			}
			f.TrafficBindings = list.Bindings
			f.TrafficCount = len(list.Bindings)
			f.EvidenceVersion = list.Version
			f.ReportEvidenceVersion = list.ReportVersion
			if err = tx.QueryRow(`SELECT report FROM findings WHERE id=$1`, f.ID).Scan(&f.Report); err != nil {
				return err
			}
			for _, b := range list.Bindings {
				snapshots = append(snapshots, b.Snapshot)
			}
		}
		if copyBodies {
			return s.copySnapshots(snapshots, dest)
		}
		return nil
	})
}

func (s *Store) prepare(ctx context.Context, refs []db.TrafficRef) ([]db.PreparedTrafficEvidence, error) {
	refs, err := db.NormalizeTrafficRefs(refs)
	if err != nil {
		return nil, err
	}
	out := make([]db.PreparedTrafficEvidence, 0, len(refs))
	if len(refs) == 0 {
		return out, nil
	}
	ids := make([]string, len(refs))
	byID := map[string]db.TrafficRef{}
	for i, ref := range refs {
		ids[i] = ref.TrafficID
		byID[ref.TrafficID] = ref
	}
	err = s.Traffic.ReadEvidence(ctx, ids, func(e traffic.EvidenceExchange) error {
		rh, err := s.writeBody(e.Request, e.ReqLen, e.ReqHash)
		if err != nil {
			return err
		}
		ph, err := s.writeBody(e.Response, e.RespLen, e.RespHash)
		if err != nil {
			return err
		}
		v := db.TrafficEvidenceSnapshot{SourceTrafficID: e.ID, CapturedAt: e.TS, URL: e.URL, Method: e.Method, Status: e.Status, ContentType: e.ContentType,
			ReqHead: e.ReqHead, RespHead: e.RespHead, ReqHash: rh, RespHash: ph, ReqLen: e.ReqLen, RespLen: e.RespLen}
		// Raw wire bytes: normalize once here so the ID, the stored row and every
		// downstream consumer (archive, API responses) all see the same text.
		v = v.Normalize()
		v.ID = db.TrafficSnapshotID(v)
		out = append(out, db.PreparedTrafficEvidence{Ref: byID[e.ID], Snapshot: v})
		return nil
	})
	return out, err
}

func (s *Store) Record(ctx context.Context, in db.RecordFindingInput, refs []db.TrafficRef) (out *db.RecordedFinding, err error) {
	err = s.DB.WithEvidenceTx(ctx, func(tx *sql.Tx) error {
		if err := db.LockTaskEvidenceTx(tx, in.TaskID); err != nil {
			return err
		}
		prepared, err := s.prepare(ctx, refs)
		if err != nil {
			return err
		}
		out, err = db.RecordFindingTx(ctx, tx, in, prepared)
		return err
	})
	if err == nil && out != nil {
		// 先落一份无 LLM 的确定性报告；报告 Agent 若启用，会在随后用更完整的
		// 证据覆盖它。写入失败不影响漏洞本身。
		auto := report.BuildFindingReport(report.FindingReportInput{
			FindingID:   out.FindingID,
			Name:        in.Name,
			VulnClass:   in.VulnClass,
			Severity:    in.Severity,
			Status:      db.FindingPending,
			Summary:     in.Summary,
			Evidence:    in.Evidence,
			Source:      "Agent 上报（" + in.Worker + "）",
			GeneratedAt: time.Now(),
		})
		if reportErr := s.DB.SetFindingAutoReport(out.FindingID, auto); reportErr != nil {
			log.Printf("[evidence] 生成自动报告失败 finding=%d: %v", out.FindingID, reportErr)
		}
	}
	return
}

func (s *Store) Bind(ctx context.Context, findingID int64, refs []db.TrafficRef) (out *db.FindingTraffic, err error) {
	err = s.DB.WithEvidenceTx(ctx, func(tx *sql.Tx) error {
		if err := db.LockFindingEvidenceTx(tx, findingID, nil); err != nil {
			return err
		}
		prepared, err := s.prepare(ctx, refs)
		if err != nil {
			return err
		}
		if err = db.AddFindingTrafficTx(tx, findingID, prepared); err != nil {
			return err
		}
		out, err = db.FindingTrafficTx(tx, findingID)
		return err
	})
	if err == nil {
		// 后补流量：把已记录的复现步骤重新对到刚绑定的报文上。失败只影响报告里
		// 「步骤↔报文」的跳转，不影响绑定本身，所以不向上报错。
		if relinkErr := s.DB.ReResolveFindingReproduction(ctx, findingID); relinkErr != nil {
			log.Printf("[evidence] 复现步骤重新关联流量失败 finding=%d: %v", findingID, relinkErr)
		}
	}
	return
}

func (s *Store) WithBinding(ctx context.Context, findingID, bindingID int64, fn func(db.FindingTrafficBinding) error) error {
	return s.DB.WithEvidenceTx(ctx, func(tx *sql.Tx) error {
		list, err := db.FindingTrafficTx(tx, findingID)
		if err != nil {
			return err
		}
		for _, b := range list.Bindings {
			if b.ID == bindingID {
				return fn(b)
			}
		}
		return db.ErrEvidenceNotFound
	})
}

// Binding resolves one binding's metadata under the evidence lock and releases
// the lock before returning. Callers that then stream a body to a client must
// use this instead of WithBinding: verifyFile+io.Copy is O(body size), so a
// large download (or a slow client) holding WithEvidenceTx would block every
// evidence write process-wide. Reading the blob afterwards is safe — blobs are
// content-addressed and GC only reaps unreferenced files after a 24h grace
// period, and an already-open fd survives an unlink regardless.
func (s *Store) Binding(ctx context.Context, findingID, bindingID int64) (db.FindingTrafficBinding, error) {
	var out db.FindingTrafficBinding
	err := s.WithBinding(ctx, findingID, bindingID, func(b db.FindingTrafficBinding) error {
		out = b
		return nil
	})
	return out, err
}

// OpenBody may be called without holding the evidence lock; see Binding.
func (s *Store) OpenBody(snapshot db.TrafficEvidenceSnapshot, side string) (*os.File, int64, error) {
	hash, length := snapshot.ReqHash, snapshot.ReqLen
	if side == "response" {
		hash, length = snapshot.RespHash, snapshot.RespLen
	} else if side != "request" {
		return nil, 0, errors.New("side 必须为 request 或 response")
	}
	path, err := hashPath(s.Dir, hash)
	if err != nil {
		return nil, 0, err
	}
	if err = verifyFile(path, hash, length); err != nil {
		return nil, 0, err
	}
	f, err := os.Open(path)
	return f, length, err
}

// CopySnapshots is used by both report downloads and portable task archives.
// The destination owns real copies, never links into either disposable store.
func (s *Store) CopySnapshots(ctx context.Context, snapshots []db.TrafficEvidenceSnapshot, dest string) error {
	return s.DB.WithEvidenceTx(ctx, func(*sql.Tx) error { return s.copySnapshots(snapshots, dest) })
}

func (s *Store) copySnapshots(snapshots []db.TrafficEvidenceSnapshot, dest string) error {
	for _, v := range snapshots {
		for _, side := range []string{"request", "response"} {
			if err := func() error {
				f, length, err := s.OpenBody(v, side)
				if err != nil {
					return err
				}
				defer f.Close()
				hash := v.ReqHash
				if side == "response" {
					hash = v.RespHash
				}
				target, err := hashPath(dest, hash)
				if err != nil {
					return err
				}
				if err = os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
					return err
				}
				out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
				if os.IsExist(err) {
					return verifyFile(target, hash, length)
				}
				if err != nil {
					return err
				}
				_, copyErr := io.Copy(out, f)
				syncErr := out.Sync()
				closeErr := out.Close()
				return errors.Join(copyErr, syncErr, closeErr)
			}(); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *Store) InstallSnapshots(ctx context.Context, snapshots []db.TrafficEvidenceSnapshot, source string) error {
	return s.WithInstalledSnapshots(ctx, snapshots, source, func() error { return nil })
}

// WithInstalledSnapshots pins installed bodies until the metadata restore finishes.
// The callback must not acquire another evidence advisory lock.
func (s *Store) WithInstalledSnapshots(ctx context.Context, snapshots []db.TrafficEvidenceSnapshot, source string, restore func() error) error {
	return s.DB.WithEvidenceTx(ctx, func(*sql.Tx) error {
		for _, v := range snapshots {
			if v.ID != db.TrafficSnapshotID(v) {
				return errors.New("归档证据快照元数据哈希不匹配")
			}
			for _, body := range []struct {
				hash   string
				length int64
			}{{v.ReqHash, v.ReqLen}, {v.RespHash, v.RespLen}} {
				if err := func() error {
					path, err := hashPath(source, body.hash)
					if err != nil {
						return err
					}
					f, err := os.Open(path)
					if err != nil {
						return err
					}
					defer f.Close()
					_, err = s.writeBody(f, body.length, body.hash)
					return err
				}(); err != nil {
					return err
				}
			}
		}
		return restore()
	})
}

func (s *Store) Collect(ctx context.Context, now time.Time) error {
	return s.DB.WithEvidenceTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.Exec(`UPDATE traffic_evidence_snapshots s SET unreferenced_at=$1
WHERE unreferenced_at IS NULL AND NOT EXISTS(SELECT 1 FROM finding_traffic_bindings b WHERE b.snapshot_id=s.id)`, now); err != nil {
			return err
		}
		if _, err := tx.Exec(`DELETE FROM traffic_evidence_snapshots s WHERE unreferenced_at<$1
AND NOT EXISTS(SELECT 1 FROM finding_traffic_bindings b WHERE b.snapshot_id=s.id)`, now.Add(-24*time.Hour)); err != nil {
			return err
		}
		rows, err := tx.Query(`SELECT req_hash FROM traffic_evidence_snapshots UNION SELECT resp_hash FROM traffic_evidence_snapshots`)
		if err != nil {
			return err
		}
		refs := map[string]bool{}
		for rows.Next() {
			var hash string
			if err := rows.Scan(&hash); err != nil {
				rows.Close()
				return err
			}
			refs[hash] = true
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		for _, root := range []string{filepath.Join(s.Dir, "blobs"), filepath.Join(s.Dir, ".staging")} {
			err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
				if os.IsNotExist(err) {
					return nil
				}
				if err != nil {
					return err
				}
				if entry.IsDir() {
					return nil
				}
				if refs[strings.TrimSuffix(entry.Name(), ".bin")] {
					return nil
				}
				info, err := entry.Info()
				if err != nil {
					return err
				}
				if now.Sub(info.ModTime()) < 24*time.Hour {
					return nil
				}
				return os.Remove(path)
			})
			if err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *Store) RunGC(ctx context.Context) {
	timer := time.NewTicker(time.Hour)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-timer.C:
			if err := s.Collect(ctx, now); err != nil && !errors.Is(err, context.Canceled) {
				log.Printf("[evidence] cleanup failed: %v", err)
			}
		}
	}
}
