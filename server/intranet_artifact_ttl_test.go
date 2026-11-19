package server

import (
	"context"
	"testing"
	"time"

	"github.com/Domren/jingwei/db"
)

func TestSettingIntranetTTLAutoRevokeDefaultsOff(t *testing.T) {
	pg := prescanTestDB(t)
	old, had, err := pg.GetSetting(SettingIntranetTTLAutoRevoke)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if had {
			_ = pg.SetSetting(SettingIntranetTTLAutoRevoke, old)
		} else {
			_, _ = pg.Exec(`DELETE FROM settings WHERE key=$1`, SettingIntranetTTLAutoRevoke)
		}
	})
	if _, err := pg.Exec(`DELETE FROM settings WHERE key=$1`, SettingIntranetTTLAutoRevoke); err != nil {
		t.Fatal(err)
	}
	if pg.GetBool(SettingIntranetTTLAutoRevoke, false) {
		t.Fatal("TTL 到期自动回收必须默认关：设置缺失时不得启用")
	}
}

// 到期任务真撤销并验证；验证失败的转人工队列并单列，不混进平台已验证清除。
func TestIntranetArtifactExpirySweepTTLResultAndManualFallback(t *testing.T) {
	pg := prescanTestDB(t)
	s, sess, task, _ := newIntranetEvacuationFixture(t, pg)
	ctx := context.Background()
	expired := time.Now().Add(-time.Minute)

	ok, err := pg.AddIntranetArtifact(db.IntranetArtifactInput{
		TaskID: task.ID, SessionID: sess.ID, Host: "10.88.9.9",
		Kind: db.IntranetArtifactCron, Name: "ttl-sweep-ok",
		RevokeCommand: "true", VerifyCommand: "echo " + intranetArtifactGone, ExpiresAt: &expired,
	})
	if err != nil {
		t.Fatal(err)
	}
	bad, err := pg.AddIntranetArtifact(db.IntranetArtifactInput{
		TaskID: task.ID, SessionID: sess.ID, Host: "10.88.9.9",
		Kind: db.IntranetArtifactCron, Name: "ttl-sweep-bad",
		RevokeCommand: "true", VerifyCommand: "echo NOT_GONE", ExpiresAt: &expired,
	})
	if err != nil {
		t.Fatal(err)
	}

	s.intranetArtifactExpirySweep(ctx, map[int64]time.Time{}, map[int64]bool{})

	verified, err := pg.GetIntranetArtifact(ok.ID)
	if err != nil {
		t.Fatal(err)
	}
	if verified.Status != db.IntranetArtifactRevoked ||
		verified.TTLRevokeStatus != db.TTLRevokeStatusVerified || verified.TTLRevokedAt == nil {
		t.Fatalf("到期撤销并验证的结果未落库：%+v", verified)
	}
	manual, err := pg.GetIntranetArtifact(bad.ID)
	if err != nil {
		t.Fatal(err)
	}
	if manual.Status != db.IntranetArtifactRevoked ||
		manual.TTLRevokeStatus != db.TTLRevokeStatusFailedManual ||
		manual.Metadata["manual_revoke"] == nil {
		t.Fatalf("撤销验证失败必须转人工队列：%+v", manual)
	}
	list, err := pg.ListTTLManualRevokedIntranetArtifacts(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].ID != bad.ID {
		t.Fatalf("单列人工队列只应含失败项：%+v", list)
	}
}
