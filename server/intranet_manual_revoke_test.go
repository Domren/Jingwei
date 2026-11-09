package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Autumn-27/jingwei/db"
)

// 人工处置路径的账目要求：状态变成 revoked，但证据必须能区分「平台验证」与「人说的」。
// 这一条测三件事：
//  1. 原部署证据保留，人工说明追加在后面（不是覆盖）；
//  2. metadata.manual_revoke 落 by/at/note，界面与报告据此标「人工声明」；
//  3. 撤离报告的 artifacts 计数不把它算进去，而是单列 manual_revoked。
func TestIntranetManualRevokeRecordedAsUnverified(t *testing.T) {
	pg := prescanTestDB(t)
	s, sess, task, home := newIntranetEvacuationFixture(t, pg)
	ctx := context.Background()

	target := filepath.Join(home, "manual-drop.sh")
	if _, err := s.intranetUpload(ctx, pg, sess, target, []byte("#!/bin/sh\necho jw-manual\n")); err != nil {
		t.Fatalf("upload: %v", err)
	}
	arts, _, err := pg.ListIntranetArtifacts(db.IntranetArtifactFilter{
		TaskID: task.ID, Status: db.IntranetArtifactActive,
	})
	if err != nil || len(arts) != 1 {
		t.Fatalf("active artifacts = %+v err=%v", arts, err)
	}
	art := arts[0]
	deployEvidence := art.Evidence
	if strings.TrimSpace(deployEvidence) == "" {
		t.Fatal("上传登记的落地物应当带部署证据，否则这条用例证明不了「追加而非覆盖」")
	}

	note := "【人工确认清理】" + authUsername + "：SSH 上去 rm -f " + target + "，ls 确认不存在"
	updated, err := pg.MarkIntranetArtifactManualRevoked(art.ID, note, authUsername)
	if err != nil {
		t.Fatalf("manual revoke: %v", err)
	}
	if updated.Status != db.IntranetArtifactRevoked || updated.RevokedAt == nil {
		t.Fatalf("状态 = %q revoked_at=%v，want revoked + 时间戳", updated.Status, updated.RevokedAt)
	}
	if !strings.Contains(updated.Evidence, deployEvidence) {
		t.Fatalf("原部署证据被覆盖了：\n%q\n应当仍包含：\n%q", updated.Evidence, deployEvidence)
	}
	if !strings.Contains(updated.Evidence, "人工确认清理") {
		t.Fatalf("证据里没有人工说明：%q", updated.Evidence)
	}
	m, ok := updated.Metadata["manual_revoke"].(map[string]any)
	if !ok {
		t.Fatalf("metadata 里没有 manual_revoke：%+v", updated.Metadata)
	}
	if m["by"] != authUsername {
		t.Fatalf("manual_revoke.by = %v，want %q", m["by"], authUsername)
	}
	if got, _ := m["note"].(string); !strings.Contains(got, "rm -f") {
		t.Fatalf("manual_revoke.note = %q，说明没落库", got)
	}

	// 台账里查得到，且带得出说明。
	listed, err := pg.ListManualRevokedIntranetArtifacts(task.ID)
	if err != nil || len(listed) != 1 || listed[0].ID != art.ID {
		t.Fatalf("manual revoked list = %+v err=%v", listed, err)
	}

	// 撤离预览：这条已 revoked，不进 artifacts 计数，但要单列在 manual_revoked。
	rep := s.intranetEvacuate(ctx, pg, intranetEvacuationOptions{TaskID: task.ID, DryRun: true})
	if rep.Artifacts.Total != 0 {
		t.Fatalf("已人工撤销的落地物不该再进撤销循环：artifacts.total=%d items=%+v", rep.Artifacts.Total, rep.Items)
	}
	if len(rep.ManualRevoked) != 1 || !strings.Contains(rep.ManualRevoked[0], "人工声明已清理") {
		t.Fatalf("manual_revoked = %+v，want 一条带「人工声明已清理」的说明", rep.ManualRevoked)
	}
	if !strings.Contains(rep.Summary, "未经平台验证") {
		t.Fatalf("summary 没提人工声明不计入验证：%q", rep.Summary)
	}
}

// 说明太短就不许记账：这条记录之后会被当成已清理，报告读者看不到目标，
// 只写「已处理」等于让人替他担保。
func TestManualRevokeHandlerRequiresNote(t *testing.T) {
	s := &Server{}
	req := httptest.NewRequest(http.MethodPost, "/api/intranet/artifacts/1/manual-revoke",
		strings.NewReader(`{"note":"已处理"}`))
	req.SetPathValue("id", "1")
	rec := httptest.NewRecorder()
	s.manualRevokeIntranetArtifact(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d body=%s，want 400", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "至少 8 个字") {
		t.Fatalf("错误信息没有说清要求：%s", rec.Body.String())
	}
}
