package db

import (
	"context"
	"database/sql"
	"strings"
	"testing"
)

// Agent-reported non-HTTP findings must keep byte-exact payloads (trailing CRLF
// included) because the report tells the reader to resend them verbatim.
func TestRecordFindingStoresRawProtocolPackets(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	task, err := d.CreateTask("raw protocol packets", "fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	var ids []int64
	defer func() { purgeTaskNow(t, d, task.ID, ids...) }()

	record := func(name, req, resp string) int64 {
		t.Helper()
		var out *RecordedFinding
		err := d.WithEvidenceTx(context.Background(), func(tx *sql.Tx) error {
			var e error
			out, e = RecordFindingTx(context.Background(), tx, RecordFindingInput{
				TaskID: task.ID, ExplorationID: task.ExplorationID,
				VulnClass: "敏感信息泄露", Name: name, Severity: "high",
				Summary: "Redis 未授权访问", Evidence: "类型: redis\n" + name, Worker: "work#1",
				Protocol: "redis", RawRequest: req, RawResponse: resp,
			}, nil)
			return e
		})
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, out.FindingID)
		return out.FindingID
	}

	const name = "Redis 未授权访问读取配置"
	req := "info\r\nquit\r\n"
	resp := "+RESP:21\r\nredis_version:4.0.14\r\n\x00\xff\n"
	id := record(name, req, resp)
	var gotReq, gotResp string
	if err := d.QueryRow(`SELECT http_request, http_response FROM findings WHERE id=$1`, id).Scan(&gotReq, &gotResp); err != nil {
		t.Fatal(err)
	}
	if gotReq != req {
		t.Fatalf("raw request changed: %q want %q", gotReq, req)
	}
	if strings.ContainsRune(gotResp, 0) {
		t.Fatalf("raw response kept a NUL byte: %q", gotResp)
	}
	if !strings.HasPrefix(gotResp, "+RESP:21\r\n") {
		t.Fatalf("raw response lost its wire framing: %q", gotResp)
	}

	// A repeat report of the same sink with no payloads merges and must keep the
	// captured bytes.
	if again := record(name, "", ""); again != id {
		t.Fatalf("repeat report created a new finding: %d vs %d", again, id)
	}
	if err := d.QueryRow(`SELECT http_request FROM findings WHERE id=$1`, id).Scan(&gotReq); err != nil {
		t.Fatal(err)
	}
	if gotReq != req {
		t.Fatalf("packets wiped by a payloadless repeat: %q", gotReq)
	}

	other := record("Redis CONFIG REWRITE 写文件", "", "")
	if other == id {
		t.Fatal("distinct sink merged into the first finding")
	}
	var empty string
	if err := d.QueryRow(`SELECT http_request FROM findings WHERE id=$1`, other).Scan(&empty); err != nil {
		t.Fatal(err)
	}
	if empty != "" {
		t.Fatalf("payloadless finding inherited packets: %q", empty)
	}

	big := record("Redis 超长响应", "get big\r\n", strings.Repeat("A", maxRawPacketResponse+10))
	if err := d.QueryRow(`SELECT http_response FROM findings WHERE id=$1`, big).Scan(&gotResp); err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(gotResp, "[报文过长，已截断]") || len(gotResp) > maxRawPacketResponse+200 {
		t.Fatalf("oversized response not capped: len=%d", len(gotResp))
	}
}
