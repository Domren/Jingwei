package db

import (
	"strings"
	"testing"
	"time"
)

// P13：TTL 到期撤销的结果必须能被区分——平台验证通过的，和失败转人工的，
// 不能混成同一个 status，否则撤离报告就会替平台担保它没担保的清除。
func TestIntranetArtifactTTLRevokeAndManualFallback(t *testing.T) {
	d, _, _ := testSetup(t)
	t.Cleanup(func() { _ = d.Close() })
	const host = "10.88.7.7"
	const taskID = int64(990877)
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM intranet_artifacts WHERE host=$1`, host) })
	expired := time.Now().Add(-time.Minute)

	ok, err := d.AddIntranetArtifact(IntranetArtifactInput{
		TaskID: taskID, Host: host, Kind: IntranetArtifactCron, Name: "ttl-verified",
		RevokeCommand: "true", VerifyCommand: "echo JW_ARTIFACT_GONE", ExpiresAt: &expired,
	})
	if err != nil {
		t.Fatal(err)
	}
	verified, err := d.MarkIntranetArtifactTTLRevoked(ok.ID, "TTL 验证输出：痕迹已消失")
	if err != nil {
		t.Fatal(err)
	}
	if verified.Status != IntranetArtifactRevoked ||
		verified.TTLRevokeStatus != TTLRevokeStatusVerified ||
		verified.TTLRevokedAt == nil ||
		!strings.Contains(verified.TTLVerifyEvidence, "痕迹已消失") {
		t.Fatalf("TTL 撤销结果未落库：%+v", verified)
	}
	expiredRows, err := d.ListExpiredIntranetArtifacts(time.Now(), 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range expiredRows {
		if a.ID == ok.ID {
			t.Fatal("已 TTL 撤销的条目仍在到期列表")
		}
	}

	failed, err := d.AddIntranetArtifact(IntranetArtifactInput{
		TaskID: taskID, Host: host, Kind: IntranetArtifactSystemd, Name: "ttl-failed",
		RevokeCommand: "systemctl disable x", ExpiresAt: &expired,
	})
	if err != nil {
		t.Fatal(err)
	}
	manual, err := d.MarkIntranetArtifactTTLFailedManual(failed.ID, "权限不足", "ttl-worker")
	if err != nil {
		t.Fatal(err)
	}
	if manual.TTLRevokeStatus != TTLRevokeStatusFailedManual ||
		manual.Status != IntranetArtifactRevoked ||
		manual.Metadata["manual_revoke"] == nil || manual.Metadata["ttl_revoke"] == nil {
		t.Fatalf("失败转人工未落库：%+v", manual)
	}

	// 沿用 manual_revoked 口径：失败项进人工队列，不算「平台已验证清除」。
	allManual, err := d.ListManualRevokedIntranetArtifacts(taskID)
	if err != nil {
		t.Fatal(err)
	}
	if len(allManual) != 1 || allManual[0].ID != failed.ID {
		t.Fatalf("失败项应进人工队列：%+v", allManual)
	}
	// 单列视图只含 TTL 失败项，验证通过的那条不能混进来。
	ttlManual, err := d.ListTTLManualRevokedIntranetArtifacts(taskID)
	if err != nil {
		t.Fatal(err)
	}
	if len(ttlManual) != 1 || ttlManual[0].ID != failed.ID {
		t.Fatalf("TTL 失败单列视图不对：%+v", ttlManual)
	}
}
