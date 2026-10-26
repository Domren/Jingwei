package db

import (
	"fmt"
	"strconv"
	"testing"
	"time"
)

// TestFindingSystemGroups covers the「按任务 → 系统」classification: a finding's
// primary system is its most specific linked asset (endpoint/service over ip),
// host:port keys collapse http/https default ports, and findings whose assets are
// gone land in the unassigned bucket.
func TestFindingSystemGroups(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	t.Cleanup(func() { _ = d.Close() })

	vc := fmt.Sprintf("__test_finding_systems_%d__", time.Now().UnixNano())
	task, err := d.CreateTask("system groups", "goal", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer purgeTaskNow(t, d, task.ID)
	defer d.Exec(`DELETE FROM findings WHERE vulnclass=$1`, vc) //nolint:errcheck

	svcA := seedTreeAsset(t, d, "service", map[string]any{
		"ip": "10.99.0.1", "port": 8080, "service_type": "http", "url": "http://10.99.0.1:8080/",
	})
	svcB := seedTreeAsset(t, d, "service", map[string]any{
		"domain": "app.example.test", "port": 443, "service_type": "http",
		"url": "https://app.example.test/",
	})
	// An endpoint on the same host:port must resolve to the same system as svcB.
	epB := seedTreeAsset(t, d, "endpoint", map[string]any{
		"domain": "app.example.test", "port": 443, "url": "https://app.example.test/admin", "method": "GET",
	})
	defer d.Exec(`DELETE FROM assets WHERE id = ANY($1::bigint[])`, []int64{svcA, svcB, epB}) //nolint:errcheck

	mk := func(sev string, assets []int64) int64 {
		id, err := d.AddFinding(task.ID, 0, vc, "", sev, "summary", "", "test", assets)
		if err != nil {
			t.Fatalf("AddFinding: %v", err)
		}
		return id
	}
	f1 := mk(SeverityCritical, []int64{svcA})
	f2 := mk(SeverityHigh, []int64{epB, svcB})
	f3 := mk(SeverityLow, []int64{999999999})

	groups, total, findingTotal, err := d.ListFindingSystemGroups(FindingFilter{VulnClass: vc, TaskID: strconv.FormatInt(task.ID, 10)}, 1, 10)
	if err != nil {
		t.Fatal(err)
	}
	if total != 3 || findingTotal != 3 || len(groups) != 3 {
		t.Fatalf("totals: systems=%d findings=%d items=%d (%+v)", total, findingTotal, len(groups), groups)
	}
	byKey := map[string]FindingSystemGroup{}
	for _, g := range groups {
		byKey[g.System] = g
	}
	if g, ok := byKey["svc:10.99.0.1:8080"]; !ok || g.Count != 1 || g.Critical != 1 || g.Label != "10.99.0.1:8080" {
		t.Fatalf("system A mismatch: %+v", byKey)
	}
	if g, ok := byKey["svc:app.example.test:443"]; !ok || g.Count != 1 || g.High != 1 {
		t.Fatalf("system B mismatch: %+v", byKey)
	}
	if g, ok := byKey[FindingUnassignedSystem]; !ok || g.Count != 1 || g.Low != 1 {
		t.Fatalf("unassigned system mismatch: %+v", byKey)
	}

	// System filter narrows the findings list to exactly the bucket's findings.
	page, count, err := d.ListFindingsPage(FindingFilter{VulnClass: vc, System: "svc:10.99.0.1:8080"}, 1, 10)
	if err != nil || count != 1 || len(page) != 1 || page[0].ID != f1 {
		t.Fatalf("system filter: count=%d page=%+v err=%v", count, page, err)
	}
	// Two differently-typed assets on the same host:port count once.
	page, count, err = d.ListFindingsPage(FindingFilter{VulnClass: vc, System: "svc:app.example.test:443"}, 1, 10)
	if err != nil || count != 1 || len(page) != 1 || page[0].ID != f2 {
		t.Fatalf("endpoint/service collapse: count=%d page=%+v err=%v", count, page, err)
	}
	if _, count, err = d.ListFindingsPage(FindingFilter{VulnClass: vc, System: "svc:no.such:1"}, 1, 10); err != nil || count != 0 {
		t.Fatalf("unknown system must match nothing: count=%d err=%v", count, err)
	}
	// The unassigned bucket is filterable too.
	if page, count, err = d.ListFindingsPage(FindingFilter{VulnClass: vc, System: FindingUnassignedSystem}, 1, 10); err != nil || count != 1 || page[0].ID != f3 {
		t.Fatalf("unassigned filter: count=%d page=%+v err=%v", count, page, err)
	}
}
