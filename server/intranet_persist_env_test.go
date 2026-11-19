package server

import (
	"strings"
	"testing"

	"github.com/Domren/jingwei/db"
)

// 5 类环境夹具：systemd 可用、容器无 systemd、crontab 只读、EDR 拦截、探测不到（未知）。
// 这是 P12 的验收核心——判定必须稳定，且不依赖真实目标。
func TestPersistKindApplicableFiveEnvironments(t *testing.T) {
	healthy := func() intranetPersistEnv {
		return intranetPersistEnv{
			Probed: true, ProbeOK: true, OSKind: intranetOSPosix,
			Container: persistProbeNo, Systemd: persistProbeYes,
			Crontab: persistProbeYes, HomeWritable: persistProbeYes, EDR: persistEDRNone,
		}
	}

	container := healthy()
	container.Container, container.Systemd = persistProbeYes, persistProbeNo
	readonly := healthy()
	readonly.Crontab = persistProbeRO
	edr := healthy()
	edr.EDR = persistEDRBlocked
	unknown := healthy()
	unknown.ProbeOK = false

	cases := []struct {
		name   string
		kind   string
		env    intranetPersistEnv
		wantOK bool
		reason string
	}{
		{"systemd 可用", db.IntranetArtifactSystemd, healthy(), true, ""},
		{"cron 正常环境", db.IntranetArtifactCron, healthy(), true, ""},
		{"容器无 systemd", db.IntranetArtifactSystemd, container, false, "容器"},
		{"crontab 只读", db.IntranetArtifactCron, readonly, false, "只读"},
		{"EDR 拦截", db.IntranetArtifactSystemd, edr, false, "EDR"},
		{"探测不到标不适用", db.IntranetArtifactCron, unknown, false, "探测"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ok, reason := persistKindApplicable(tc.kind, tc.env)
			if ok != tc.wantOK {
				t.Fatalf("%s: 适用判定 = %v (%q)，期望 %v", tc.name, ok, reason, tc.wantOK)
			}
			if !ok && !strings.Contains(reason, tc.reason) {
				t.Fatalf("%s: 不适用原因 %q 应包含 %q", tc.name, reason, tc.reason)
			}
		})
	}
}

// 不适用时不但判定要拒绝，build 层还必须根本不生成部署命令。
func TestBuildIntranetPersistPlanNotApplicableNoDeploy(t *testing.T) {
	base := func() intranetPersistEnv {
		return intranetPersistEnv{
			Probed: true, ProbeOK: true, OSKind: intranetOSPosix,
			Container: persistProbeNo, Systemd: persistProbeYes,
			Crontab: persistProbeYes, HomeWritable: persistProbeYes, EDR: persistEDRNone,
		}
	}

	// 对照：没有探测结果（Probed=false）时照常生成命令，兼容既有调用路径。
	plain := intranetPersistInput{Kind: db.IntranetArtifactCron, Schedule: "*/5 * * * *", Command: "echo jw"}
	plan, err := buildIntranetPersistPlan(plain)
	if err != nil || plan.Deploy == "" || plan.NotApplicable != "" {
		t.Fatalf("未探测时应正常生成命令：plan=%+v err=%v", plan, err)
	}

	bad := base()
	bad.Crontab = persistProbeRO
	in := plain
	in.Env = bad
	blocked, err := buildIntranetPersistPlan(in)
	if err != nil {
		t.Fatal(err)
	}
	if blocked.NotApplicable == "" || blocked.Deploy != "" || blocked.Revoke != "" || blocked.Verify != "" {
		t.Fatalf("crontab 只读时必须不生成任何命令：%+v", blocked)
	}

	container := base()
	container.Container, container.Systemd = persistProbeYes, persistProbeNo
	in = intranetPersistInput{Kind: db.IntranetArtifactSystemd, Command: "echo jw", Env: container}
	blocked, err = buildIntranetPersistPlan(in)
	if err != nil || blocked.Deploy != "" || blocked.NotApplicable == "" {
		t.Fatalf("容器无 systemd 时必须不生成部署命令：plan=%+v err=%v", blocked, err)
	}
}

func TestParsePersistEnvProbe(t *testing.T) {
	env := parsePersistEnvProbe(strings.Join([]string{
		"JW_PROBE_CONTAINER=yes",
		"JW_PROBE_SYSTEMD=no",
		"JW_PROBE_CRONTAB=readonly",
		"JW_PROBE_HOME=no",
		"JW_PROBE_EDR=none",
		"other noise",
	}, "\n"))
	if !env.Probed || !env.ProbeOK {
		t.Fatalf("探测应成功：%+v", env)
	}
	if env.Container != persistProbeYes || env.Systemd != persistProbeNo ||
		env.Crontab != persistProbeRO || env.HomeWritable != persistProbeNo || env.EDR != persistEDRNone {
		t.Fatalf("marker 解析不对：%+v", env)
	}

	// 没有 marker 输出=探测不到，ProbeOK=false，调用方据此判不适用。
	missing := parsePersistEnvProbe("no markers here")
	if missing.ProbeOK || missing.Container != persistProbeUnknown {
		t.Fatalf("探测不到应标未知：%+v", missing)
	}
}
