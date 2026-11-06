package server

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Autumn-27/jingwei/db"
	"github.com/Autumn-27/jingwei/report"
)

// 矩阵是撤离报告的一部分，所以这里的重点是：结论必须由「有没有独立验证命令」决定，
// 而不是由撤销命令跑没跑成功决定；同一手段多条时不能被一条好结果盖掉一条坏结果。
func TestIntranetBuildTraceMatrixVerdicts(t *testing.T) {
	rep := &intranetEvacuationReport{
		Items: []intranetEvacuationItem{
			{Type: "artifact", ID: 1, Kind: db.IntranetArtifactCron, Name: "crontab:+a1b2", Host: "10.99.0.10",
				Status: "revoked", Detail: "JW_ARTIFACT_GONE"},
			// 同一种手段的第二条：没有验证命令，只跑了撤销命令。
			{Type: "artifact", ID: 2, Kind: db.IntranetArtifactCron, Name: "crontab:+c3d4", Host: "10.99.0.10",
				Status: "revoked", Detail: "crontab 已重写"},
			{Type: "artifact", ID: 3, Kind: db.IntranetArtifactSSHKey, Name: "/root/.ssh/authorized_keys",
				Host: "10.99.0.10", Status: "failed", Detail: "权限不足"},
			{Type: "tunnel", ID: 4, Kind: "socks5", Name: "chisel 反向 SOCKS", Host: "10.99.0.11", Status: "stopped"},
			{Type: "memshell", ID: 5, Kind: "filter", Name: "/static/ab12cd34.js", Host: "10.99.0.12", Status: "revoked"},
			{Type: "webshell", ID: 6, Kind: "php", Name: "", Host: "10.99.0.10", Status: "skipped",
				Detail: "本轮未开启自动删除 webshell"},
			// 会话与受管资源不是目标上的维持手段，不进矩阵。
			{Type: "session", ID: 7, Kind: "ssh", Name: "会话", Host: "10.99.0.10", Status: "closed"},
		},
		Residual:       []string{"落地物 #9（file）未配置验证命令，无法复核"},
		LedgerExternal: []string{"systemctl list-unit-files: jingwei-leftover.service"},
	}
	verifyKnown := map[int64]bool{1: true, 2: false, 3: true}
	intranetBuildTraceMatrix(rep, verifyKnown)

	byKind := map[string]report.TraceMatrixRow{}
	for _, r := range rep.Traces {
		byKind[r.Kind+"@"+r.Host] = r
	}
	if len(rep.Traces) != 5 {
		t.Fatalf("矩阵应当有 5 行（会话/资源不进矩阵）：%+v", rep.Traces)
	}
	cron := byKind[db.IntranetArtifactCron+"@10.99.0.10"]
	if cron.Verdict != report.TraceVerdictUnverified {
		t.Fatalf("同一手段里有一条没验证命令，结论不能被另一条好结果盖掉：%+v", cron)
	}
	if len(cron.Landed) != 2 || !strings.Contains(strings.Join(cron.Landed, "|"), "crontab:+c3d4") {
		t.Fatalf("同一手段的多条落地点应当合并成一行：%+v", cron.Landed)
	}
	if !strings.Contains(cron.Verify, "token") {
		t.Fatalf("验证方式应当来自痕迹档案：%q", cron.Verify)
	}
	ssh := byKind[db.IntranetArtifactSSHKey+"@10.99.0.10"]
	if ssh.Verdict != report.TraceVerdictFailed || !strings.Contains(ssh.Detail, "权限不足") {
		t.Fatalf("撤销失败要如实写：%+v", ssh)
	}
	if !strings.Contains(rep.TraceMatrix, "认证日志") {
		t.Fatal("矩阵没有列出 SSH 公钥撤销后仍存在的认证日志")
	}
	tun := byKind[db.ArtifactTraceTunnel+"@10.99.0.11"]
	if tun.Verdict != report.TraceVerdictCleared || !strings.Contains(tun.Name, "隧道") {
		t.Fatalf("隧道拆除结论不对：%+v", tun)
	}
	mem := byKind[db.ArtifactTraceMemshell+"@10.99.0.12"]
	if !strings.Contains(mem.Verify, "探针") {
		t.Fatalf("内存马的验证方式应当是探针+URL 复核：%q", mem.Verify)
	}
	file := byKind[db.IntranetArtifactFile+"@10.99.0.10"]
	if file.Verdict != report.TraceVerdictActive || !strings.Contains(file.Detail, "未开启自动删除") {
		t.Fatalf("未删除的 webshell 要写成仍在维持中：%+v", file)
	}
	if !strings.Contains(rep.TraceMatrix, "jingwei-leftover.service") ||
		!strings.Contains(rep.TraceMatrix, "未能复核：落地物 #9") {
		t.Fatalf("矩阵文本没有带上账外残留与未能复核项：\n%s", rep.TraceMatrix)
	}
	// 未知 kind 不能悄悄留白。
	rep2 := &intranetEvacuationReport{Items: []intranetEvacuationItem{
		{Type: "artifact", ID: 10, Kind: "brand_new_kind", Name: "x", Host: "h", Status: "revoked"},
	}}
	intranetBuildTraceMatrix(rep2, map[int64]bool{10: true})
	if len(rep2.Traces) != 1 || !strings.Contains(rep2.Traces[0].Verify, "没有痕迹档案") {
		t.Fatalf("未登记痕迹档案的 kind 必须暴露出来：%+v", rep2.Traces)
	}
}

// 端到端：在桩 webshell 通道上真的部署两种维持手段、真的撤销、真的复核，然后看矩阵
// 有没有把「验证过的清除」和「只跑了撤销命令」分开写。矩阵如果只在单测里对，而撤离
// 报告里不带这一节，就等于没进报告。
func TestIntranetEvacuationTraceMatrixEndToEnd(t *testing.T) {
	pg := prescanTestDB(t)
	s, sess, home := newIntranetPersistFixture(t, pg)
	ctx := context.Background()
	const taskID = int64(990001)

	cronArt, _, _, _, err := s.intranetPersist(ctx, pg, intranetPersistInput{
		SessionID: sess.ID, Kind: db.IntranetArtifactCron,
		Schedule: "*/5 * * * *", Command: "echo jw-beacon", Name: "g4-cron",
	})
	if err != nil {
		t.Fatalf("部署 cron 失败：%v", err)
	}
	keyArt, _, _, _, err := s.intranetPersist(ctx, pg, intranetPersistInput{
		SessionID: sess.ID, Kind: db.IntranetArtifactSSHKey,
		PublicKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl g4@test",
		Name:      "g4-key",
	})
	if err != nil {
		t.Fatalf("部署公钥失败：%v", err)
	}
	// 台账归到同一个任务下，撤离才会按逆序处理它们；公钥那条故意抽掉验证命令，
	// 看矩阵会不会把「只跑了撤销命令」写成已清除。
	if _, err := pg.Exec(`UPDATE intranet_artifacts SET task_id=$1 WHERE id IN ($2,$3)`,
		taskID, cronArt.ID, keyArt.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := pg.Exec(`UPDATE intranet_artifacts SET verify_command='' WHERE id=$1`, keyArt.ID); err != nil {
		t.Fatal(err)
	}

	rep := s.intranetEvacuate(ctx, pg, intranetEvacuationOptions{TaskID: taskID, CloseSessions: true})
	if rep.Artifacts.Total != 2 || rep.Artifacts.Failed > 0 {
		t.Fatalf("两条落地物都该走完撤销：%+v", rep.Artifacts)
	}
	if len(rep.Traces) == 0 || rep.TraceMatrix == "" {
		t.Fatalf("撤离报告没有带上痕迹矩阵：%+v", rep.Traces)
	}
	byKind := map[string]report.TraceMatrixRow{}
	for _, r := range rep.Traces {
		byKind[r.Kind] = r
	}
	cron := byKind[db.IntranetArtifactCron]
	if cron.Verdict != report.TraceVerdictCleared {
		t.Fatalf("cron 有独立验证命令且痕迹确实消失，结论应当是已验证清除：%+v", cron)
	}
	key := byKind[db.IntranetArtifactSSHKey]
	if key.Verdict != report.TraceVerdictUnverified {
		t.Fatalf("抽掉验证命令后不能写「已验证清除」：%+v", key)
	}
	// 矩阵不是文案：撤销真的在目标上生效了。
	crontab, err := os.ReadFile(filepath.Join(home, ".crontab"))
	if err != nil {
		t.Fatalf("读桩 crontab 失败：%v", err)
	}
	if strings.Contains(string(crontab), "jw-beacon") {
		t.Fatalf("撤销后桩 crontab 里仍留着信使行：%q", crontab)
	}
	for _, want := range []string{
		"## 维持痕迹矩阵", "cron 计划任务", "SSH 授权公钥",
		"撤销之后仍然存在的痕迹", "认证日志",
	} {
		if !strings.Contains(rep.TraceMatrix, want) {
			t.Errorf("撤离报告的矩阵文本缺少 %q：\n%s", want, rep.TraceMatrix)
		}
	}
	// 预览模式不能把结论写成已清除。
	preview := s.intranetEvacuate(ctx, pg, intranetEvacuationOptions{TaskID: taskID, DryRun: true})
	for _, r := range preview.Traces {
		if r.Verdict == report.TraceVerdictCleared {
			t.Errorf("dry-run 里出现了「已验证清除」：%+v", r)
		}
	}
}
