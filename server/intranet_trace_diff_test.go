package server

import (
	"strings"
	"testing"

	"github.com/Domren/jingwei/db"
)

func TestDiffTraceAgainstProfile(t *testing.T) {
	covered := []string{"jw:", "crontab", "authorized_keys"}
	observed := []string{
		"cron: */5 * * * * echo hi # jw:ab12", // 命中 jw: 标记，档案已覆盖
		"systemd: jingwei-unknown.service",   // 档案外
		"recent-file: /tmp/.hidden/payload",   // 档案外
	}
	diff := diffTraceAgainstProfile(covered, observed)
	if len(diff) != 2 {
		t.Fatalf("档案外痕迹应当是 2 条：%+v", diff)
	}
	joined := strings.Join(diff, "|")
	if strings.Contains(joined, "jw:ab12") || !strings.Contains(joined, "jingwei-unknown.service") ||
		!strings.Contains(joined, "payload") {
		t.Fatalf("差异判定不对：%+v", diff)
	}
}

// 差异不只是函数算对，还要真的进到撤离报告的 Markdown 里。
func TestIntranetBuildTraceMatrixIncludesProfileDiff(t *testing.T) {
	rep := &intranetEvacuationReport{
		Items: []intranetEvacuationItem{{
			Type: "artifact", ID: 1, Kind: db.IntranetArtifactCron,
			Name: "x", Host: "10.0.0.1", Status: "revoked",
		}},
		TraceObserved: []string{"cron: something"},
		TraceDiff:     []string{"cron: 档案外的真实痕迹 /etc/cron.d/evil"},
	}
	intranetBuildTraceMatrix(rep, map[int64]bool{1: true})
	if !strings.Contains(rep.TraceMatrix, "档案外痕迹") ||
		!strings.Contains(rep.TraceMatrix, "/etc/cron.d/evil") {
		t.Fatalf("档案外痕迹没进报告：\n%s", rep.TraceMatrix)
	}
}
