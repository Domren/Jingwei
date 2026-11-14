package server

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/Autumn-27/jingwei/db"
)

func TestNormalizeCronSchedule(t *testing.T) {
	ok := map[string]string{
		"*/5 * * * *":     "*/5 * * * *",
		" 0  2\t* * 1-5 ": "0 2 * * 1-5",
		"@reboot":         "@reboot",
		"@daily":          "@daily",
	}
	for raw, want := range ok {
		got, err := normalizeCronSchedule(raw)
		if err != nil || got != want {
			t.Errorf("normalizeCronSchedule(%q)=%q err=%v want %q", raw, got, err, want)
		}
	}
	for _, raw := range []string{"", "* * * *", "* * * * * *", "@sometimes", "*/5 * * * *\nreboot"} {
		if _, err := normalizeCronSchedule(raw); err == nil {
			t.Errorf("schedule %q should be rejected", raw)
		}
	}
}

func TestBuildCronPersistPlan(t *testing.T) {
	plan, err := buildCronPersistPlan(intranetPersistInput{
		Schedule: "*/5 * * * *", Command: "date +%s", Name: "beacon",
	})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Kind != db.IntranetArtifactCron || plan.Name != "beacon" || !strings.HasPrefix(plan.Path, "crontab:") {
		t.Fatalf("plan = %+v", plan)
	}
	marker, _ := plan.Metadata["marker"].(string)
	if marker == "" && plan.Metadata["token"] != nil {
		marker = "# jw:" + plan.Metadata["token"].(string)
	}
	if marker == "" {
		t.Fatalf("metadata = %+v", plan.Metadata)
	}
	for name, cmd := range map[string]string{"deploy": plan.Deploy, "revoke": plan.Revoke, "verify": plan.Verify} {
		if !strings.Contains(cmd, marker) {
			t.Errorf("%s command lacks marker: %q", name, cmd)
		}
	}
	if !strings.Contains(plan.Deploy, `date +\%s`) {
		t.Errorf("cron %% not escaped: %q", plan.Deploy)
	}
	if !strings.Contains(plan.Deploy, "crontab -") || !strings.Contains(plan.Revoke, "grep -vF") {
		t.Errorf("cron commands = %q / %q", plan.Deploy, plan.Revoke)
	}
	if _, err := buildCronPersistPlan(intranetPersistInput{Schedule: "* * * * *", Command: "id\nreboot"}); err == nil {
		t.Fatal("multi-line cron command must be rejected")
	}
}

func TestBuildSystemdPersistPlan(t *testing.T) {
	plan, err := buildSystemdPersistPlan(intranetPersistInput{Command: "sleep 1000", Name: "keeper"})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Kind != db.IntranetArtifactSystemd || !strings.HasPrefix(plan.Path, "/etc/systemd/system/jingwei-") ||
		!strings.HasSuffix(plan.Path, ".service") {
		t.Fatalf("plan = %+v", plan)
	}
	for name, cmd := range map[string]string{"deploy": plan.Deploy, "revoke": plan.Revoke, "verify": plan.Verify} {
		if !strings.Contains(cmd, plan.Path) {
			t.Errorf("%s command lacks unit path: %q", name, cmd)
		}
	}
	if !strings.Contains(plan.Deploy, "systemctl enable --now") || !strings.Contains(plan.Deploy, "base64 -d") {
		t.Errorf("deploy = %q", plan.Deploy)
	}
	scriptPath, _ := plan.Metadata["script_path"].(string)
	if scriptPath == "" || !strings.Contains(plan.Revoke, scriptPath) {
		t.Fatalf("script path = %q metadata=%+v revoke=%q", scriptPath, plan.Metadata, plan.Revoke)
	}
	if _, err := buildSystemdPersistPlan(intranetPersistInput{}); err == nil {
		t.Fatal("missing command must be rejected")
	}
}

func TestBuildSSHKeyPersistPlan(t *testing.T) {
	const key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl tester@example"
	plan, err := buildSSHKeyPersistPlan(intranetPersistInput{PublicKey: key})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Kind != db.IntranetArtifactSSHKey || !strings.HasPrefix(plan.Path, "authorized_keys:current:") {
		t.Fatalf("plan = %+v", plan)
	}
	marker, _ := plan.Metadata["marker"].(string)
	if marker == "" || !strings.Contains(plan.Deploy, marker) || !strings.Contains(plan.Revoke, marker) || !strings.Contains(plan.Verify, marker) {
		t.Fatalf("marker %q missing: %+v", marker, plan)
	}
	if strings.Contains(plan.Deploy, "tester@example") {
		t.Errorf("original key comment must be dropped: %q", plan.Deploy)
	}
	if strings.Contains(plan.Deploy, "mkdir -p") == false || strings.Contains(plan.Revoke, "grep -vF") == false {
		t.Errorf("deploy/revoke = %q / %q", plan.Deploy, plan.Revoke)
	}

	if _, err := buildSSHKeyPersistPlan(intranetPersistInput{PublicKey: key + "\nreboot"}); err == nil {
		t.Fatal("multi-line public key must be rejected")
	}
	if _, err := buildSSHKeyPersistPlan(intranetPersistInput{PublicKey: "not-a-key AAAA"}); err == nil {
		t.Fatal("unknown key type must be rejected")
	}
	if _, err := buildSSHKeyPersistPlan(intranetPersistInput{PublicKey: key, User: "bad user"}); err == nil {
		t.Fatal("invalid user must be rejected")
	}

	named, err := buildSSHKeyPersistPlan(intranetPersistInput{PublicKey: key, User: "deploy"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(named.Deploy, "getent passwd 'deploy'") {
		t.Errorf("named user home not resolved: %q", named.Deploy)
	}
	// www-data 之类的账号即便装上公钥也登不进来，部署成功不等于拿到了立足点。
	if !strings.Contains(named.Deploy, intranetWarnNoLoginShell) {
		t.Errorf("login-shell warning missing: %q", named.Deploy)
	}
	if strings.Contains(named.Verify, intranetWarnNoLoginShell) {
		t.Errorf("verify must stay marker-only: %q", named.Verify)
	}
}

func TestBuildSchtasksPersistPlan(t *testing.T) {
	plan, err := buildSchtasksPersistPlan(intranetPersistInput{Command: "echo jw-beacon", Name: "beacon"})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Kind != db.IntranetArtifactSchtasks || !strings.HasPrefix(plan.Path, "schtasks:beacon-") {
		t.Fatalf("plan = %+v", plan)
	}
	task, _ := plan.Metadata["task_name"].(string)
	deploy := decodeWindowsPSScript(t, plan.Deploy)
	revoke := decodeWindowsPSScript(t, plan.Revoke)
	verify := decodeWindowsPSScript(t, plan.Verify)
	if task == "" || !strings.Contains(deploy, task) || !strings.Contains(verify, task) || !strings.Contains(revoke, task) {
		t.Fatalf("task %q missing from scripts: %+v", task, plan)
	}
	for part, script := range map[string]string{
		"Register-ScheduledTask": deploy, "New-ScheduledTaskAction": deploy,
		"New-ScheduledTaskTrigger -AtLogOn": deploy, "'/c echo jw-beacon'": deploy,
		intranetArtifactOK: deploy,
		"Unregister-ScheduledTask": revoke,
		"Get-ScheduledTask": verify, intranetArtifactPresent: verify, intranetArtifactGone: verify,
	} {
		if !strings.Contains(script, part) {
			t.Errorf("schtasks script lacks %q:\n%s", part, script)
		}
	}
	if !strings.Contains(revoke, intranetArtifactOK) {
		t.Errorf("schtasks revoke lacks OK:\n%s", revoke)
	}
	// 反向：旧 cmd 语法不得残留——PS 5.1 没有 && 管道链，>nul 是 PS 语法错误，
	// 这正是三模块在 PS 会话整链废掉的根因（R3 批 B 收口）。
	for label, script := range map[string]string{"deploy": deploy, "revoke": revoke, "verify": verify} {
		for _, bad := range []string{"schtasks /create", "schtasks /delete", "schtasks /query", ">nul", "cmd /c exit 0", "&& echo"} {
			if strings.Contains(script, bad) {
				t.Errorf("%s script still contains cmd syntax %q:\n%s", label, bad, script)
			}
		}
	}
	// 双会话形态：命令本体必须是单行 powershell -EncodedCommand 调用——
	// cmd wrapper 的 `( ... ) &` 与 PS wrapper 的 `& { ... }` 都吃得下。
	for label, cmd := range map[string]string{"deploy": plan.Deploy, "revoke": plan.Revoke, "verify": plan.Verify} {
		if !strings.Contains(cmd, "-EncodedCommand ") || strings.ContainsAny(cmd, "\n") {
			t.Errorf("%s command must be a single-line -EncodedCommand invocation: %q", label, cmd)
		}
	}

	minute, err := buildSchtasksPersistPlan(intranetPersistInput{Command: "echo hi", Schedule: "minute:15"})
	if err != nil {
		t.Fatal(err)
	}
	minuteDeploy := decodeWindowsPSScript(t, minute.Deploy)
	if !strings.Contains(minuteDeploy, "New-ScheduledTaskTrigger -Once") ||
		!strings.Contains(minuteDeploy, "RepetitionInterval (New-TimeSpan -Minutes 15)") {
		t.Errorf("minute deploy script = %s", minuteDeploy)
	}
	if _, err := buildSchtasksPersistPlan(intranetPersistInput{Command: "echo hi", Schedule: "everyday"}); err == nil {
		t.Fatal("invalid schedule must be rejected")
	}
	if _, err := buildSchtasksPersistPlan(intranetPersistInput{Command: "echo hi", Schedule: "minute:0"}); err == nil {
		t.Fatal("minute:0 must be rejected")
	}
	for _, bad := range []string{"", "echo \"x\"", "echo 100%", "echo a\necho b"} {
		if _, err := buildSchtasksPersistPlan(intranetPersistInput{Command: bad}); err == nil {
			t.Fatalf("command %q must be rejected", bad)
		}
	}
	if _, err := buildSchtasksPersistPlan(intranetPersistInput{Command: "echo hi", Name: "bad name"}); err == nil {
		t.Fatal("invalid name must be rejected")
	}
}

func TestBuildRegistryPersistPlan(t *testing.T) {
	plan, err := buildRegistryPersistPlan(intranetPersistInput{Command: "echo jw-run", Name: "runkey"})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Kind != db.IntranetArtifactRegistry || !strings.HasPrefix(plan.Path, intranetWindowsRunKey+`\runkey-`) {
		t.Fatalf("plan = %+v", plan)
	}
	value, _ := plan.Metadata["value"].(string)
	deploy := decodeWindowsPSScript(t, plan.Deploy)
	revoke := decodeWindowsPSScript(t, plan.Revoke)
	verify := decodeWindowsPSScript(t, plan.Verify)
	if value == "" || !strings.Contains(deploy, value) || !strings.Contains(verify, value) || !strings.Contains(revoke, value) {
		t.Fatalf("value %q missing from scripts: %+v", value, plan)
	}
	for part, script := range map[string]string{
		"New-ItemProperty": deploy, `HKCU:\Software\Microsoft\Windows\CurrentVersion\Run`: deploy,
		"-PropertyType String": deploy, "'cmd.exe /c echo jw-run'": deploy, intranetArtifactOK: deploy,
		"Remove-ItemProperty": revoke,
		"Get-ItemProperty": verify, intranetArtifactPresent: verify, intranetArtifactGone: verify,
	} {
		if !strings.Contains(script, part) {
			t.Errorf("registry script lacks %q:\n%s", part, script)
		}
	}
	if !strings.Contains(revoke, intranetArtifactOK) {
		t.Errorf("registry revoke lacks OK:\n%s", revoke)
	}
	for label, script := range map[string]string{"deploy": deploy, "revoke": revoke, "verify": verify} {
		for _, bad := range []string{"reg add", "reg delete", "reg query", "/t REG_SZ", ">nul", "cmd /c exit 0", "&& echo"} {
			if strings.Contains(script, bad) {
				t.Errorf("%s script still contains cmd syntax %q:\n%s", label, bad, script)
			}
		}
	}
	if _, err := buildRegistryPersistPlan(intranetPersistInput{Command: "echo hi", Name: "bad/name"}); err == nil {
		t.Fatal("invalid name must be rejected")
	}
}

func TestBuildAdvancedPOSIXPersistPlans(t *testing.T) {
	userSvc, err := buildUserSystemdPersistPlan(intranetPersistInput{Command: "sleep 600", Name: "user-keeper"})
	if err != nil {
		t.Fatal(err)
	}
	if userSvc.Kind != db.IntranetArtifactUserSystemd || !strings.HasPrefix(userSvc.Path, "user-systemd:current:jingwei-") {
		t.Fatalf("user systemd plan = %+v", userSvc)
	}
	svcScript, _ := userSvc.Metadata["script_path"].(string)
	svcScriptRel := strings.TrimPrefix(svcScript, "~/")
	if !strings.Contains(userSvc.Deploy, "systemctl --user enable --now") ||
		!strings.Contains(userSvc.Deploy, "$home/"+svcScriptRel) ||
		!strings.Contains(userSvc.Revoke, "systemctl --user disable --now") {
		t.Errorf("user systemd deploy/revoke = %q / %q", userSvc.Deploy, userSvc.Revoke)
	}

	atPlan, err := buildAtPersistPlan(intranetPersistInput{
		Command: "echo jw-at", Schedule: "now + 10 minutes", Name: "at-keeper",
	})
	if err != nil {
		t.Fatal(err)
	}
	queue, _ := atPlan.Metadata["queue"].(string)
	if atPlan.Kind != db.IntranetArtifactAt || len(queue) != 1 ||
		!strings.Contains(atPlan.Deploy, "at -q "+queue) || !strings.Contains(atPlan.Deploy, "atq -q "+queue) ||
		!strings.Contains(atPlan.Revoke, "atrm") {
		t.Fatalf("at plan = %+v", atPlan)
	}
	for _, bad := range []string{"", "-f /tmp/x", "now; reboot", "tomorrow\nreboot"} {
		if _, err := buildAtPersistPlan(intranetPersistInput{Command: "id", Schedule: bad}); err == nil {
			t.Errorf("at schedule %q must be rejected", bad)
		}
	}

	profile, err := buildProfilePersistPlan(intranetPersistInput{Command: "echo jw-profile", Name: "prof"})
	if err != nil {
		t.Fatal(err)
	}
	marker, _ := profile.Metadata["marker"].(string)
	if profile.Kind != db.IntranetArtifactProfile || !strings.HasPrefix(profile.Path, "profile:current:.profile:") {
		t.Fatalf("profile plan = %+v", profile)
	}
	for name, cmd := range map[string]string{"deploy": profile.Deploy, "revoke": profile.Revoke, "verify": profile.Verify} {
		if !strings.Contains(cmd, marker) {
			t.Errorf("profile %s lacks marker: %q", name, cmd)
		}
	}
	if custom, err := buildProfilePersistPlan(intranetPersistInput{Command: "id", Schedule: ".bashrc"}); err != nil ||
		!strings.Contains(custom.Path, ":.bashrc:") {
		t.Fatalf("custom profile = %+v err=%v", custom, err)
	}
	for _, bad := range []string{"../x", ".config/foo", "profile", ".."} {
		if _, err := buildProfilePersistPlan(intranetPersistInput{Command: "id", Schedule: bad}); err == nil {
			t.Errorf("profile file %q must be rejected", bad)
		}
	}

	for _, c := range []intranetPersistInput{
		{Kind: db.IntranetArtifactUserSystemd, Command: "id"},
		{Kind: db.IntranetArtifactAt, Command: "id", Schedule: "now + 1 minute"},
		{Kind: db.IntranetArtifactProfile, Command: "id"},
	} {
		plan, err := buildIntranetPersistPlan(c)
		if err != nil {
			t.Errorf("dispatch %s: %v", c.Kind, err)
			continue
		}
		if plan.Kind != c.Kind {
			t.Errorf("dispatch %s -> %s", c.Kind, plan.Kind)
		}
	}
}

func decodeWindowsPSScript(t *testing.T, command string) string {
	t.Helper()
	const marker = "-EncodedCommand "
	i := strings.Index(command, marker)
	if i < 0 {
		t.Fatalf("command is not an encoded PowerShell script: %q", command)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(command[i+len(marker):]))
	if err != nil || len(raw)%2 != 0 {
		t.Fatalf("invalid encoded script: %v", err)
	}
	units := make([]uint16, len(raw)/2)
	for j := range units {
		units[j] = uint16(raw[2*j]) | uint16(raw[2*j+1])<<8
	}
	return string(utf16.Decode(units))
}

func TestBuildAdvancedWindowsPersistPlans(t *testing.T) {
	svc, err := buildServicePersistPlan(intranetPersistInput{Command: "echo jw-svc", Name: "keeper"})
	if err != nil {
		t.Fatal(err)
	}
	serviceName, _ := svc.Metadata["service_name"].(string)
	if svc.Kind != db.IntranetArtifactService || !strings.HasPrefix(svc.Path, "service:keeper-") {
		t.Fatalf("service plan = %+v", svc)
	}
	svcDeploy := decodeWindowsPSScript(t, svc.Deploy)
	svcRevoke := decodeWindowsPSScript(t, svc.Revoke)
	svcVerify := decodeWindowsPSScript(t, svc.Verify)
	if serviceName == "" || !strings.Contains(svcDeploy, serviceName) ||
		!strings.Contains(svcVerify, serviceName) || !strings.Contains(svcRevoke, serviceName) {
		t.Errorf("service name %q missing from scripts", serviceName)
	}
	for part, script := range map[string]string{
		"New-Service": svcDeploy, "BinaryPathName": svcDeploy, "-StartupType Automatic": svcDeploy,
		"Start-Service": svcDeploy, "'cmd.exe /c echo jw-svc'": svcDeploy, intranetArtifactOK: svcDeploy,
		"Stop-Service": svcRevoke, ".Delete()": svcRevoke,
		"Get-Service": svcVerify, intranetArtifactPresent: svcVerify, intranetArtifactGone: svcVerify,
	} {
		if !strings.Contains(script, part) {
			t.Errorf("service script lacks %q:\n%s", part, script)
		}
	}
	if !strings.Contains(svcRevoke, intranetArtifactOK) {
		t.Errorf("service revoke lacks OK:\n%s", svcRevoke)
	}
	// 反向：sc.exe 语法与 cmd 尾部归零不得残留（PS 5.1 没有 Remove-Service，
	// 撤销走 ServiceController.Delete()）。
	for label, script := range map[string]string{"deploy": svcDeploy, "revoke": svcRevoke, "verify": svcVerify} {
		for _, bad := range []string{"sc create", "sc start", "sc delete", "sc query", ">nul", "cmd /c exit 0"} {
			if strings.Contains(script, bad) {
				t.Errorf("service %s script still contains cmd syntax %q:\n%s", label, bad, script)
			}
		}
	}

	wmi, err := buildWMIPersistPlan(intranetPersistInput{Command: "echo jw-wmi", Name: "wmi-keeper"})
	if err != nil {
		t.Fatal(err)
	}
	wmiName, _ := wmi.Metadata["consumer_name"].(string)
	wmiDeploy := decodeWindowsPSScript(t, wmi.Deploy)
	wmiRevoke := decodeWindowsPSScript(t, wmi.Revoke)
	wmiVerify := decodeWindowsPSScript(t, wmi.Verify)
	for part, script := range map[string]string{
		"__EventFilter": wmiDeploy, "CommandLineEventConsumer": wmiDeploy,
		"__FilterToConsumerBinding": wmiDeploy, "cmd.exe /c echo jw-wmi": wmiDeploy,
		intranetArtifactOK: wmiDeploy, "Remove-WmiObject": wmiRevoke,
		intranetArtifactPresent: wmiVerify, intranetArtifactGone: wmiVerify,
	} {
		if !strings.Contains(script, part) {
			t.Errorf("wmi script lacks %q:\n%s", part, script)
		}
	}
	if wmiName == "" || !strings.Contains(wmiDeploy, wmiName) {
		t.Errorf("wmi name %q missing", wmiName)
	}

	startup, err := buildStartupPersistPlan(intranetPersistInput{Command: "echo jw-startup", Name: "boot"})
	if err != nil {
		t.Fatal(err)
	}
	startupDeploy := decodeWindowsPSScript(t, startup.Deploy)
	startupRevoke := decodeWindowsPSScript(t, startup.Revoke)
	startupVerify := decodeWindowsPSScript(t, startup.Verify)
	if startup.Kind != db.IntranetArtifactStartup || !strings.HasPrefix(startup.Path, "startup:boot-") {
		t.Fatalf("startup plan = %+v", startup)
	}
	for part, script := range map[string]string{
		"Startup": startupDeploy, "Set-Content": startupDeploy, "echo jw-startup": startupDeploy,
		"Remove-Item": startupRevoke, "Test-Path": startupVerify,
	} {
		if !strings.Contains(script, part) {
			t.Errorf("startup script lacks %q:\n%s", part, script)
		}
	}

	if _, err := buildServicePersistPlan(intranetPersistInput{Command: `echo "bad"`}); err == nil {
		t.Fatal("quoted windows command must be rejected")
	}
	if _, err := buildStartupPersistPlan(intranetPersistInput{Command: "echo %PATH%"}); err == nil {
		t.Fatal("windows command with % must be rejected")
	}
}

func TestIntranetArtifactFingerprintAndTTL(t *testing.T) {
	base := intranetArtifactFingerprint("cron", "10.0.0.5", "beacon", "@daily", "echo hi", "", "")
	if again := intranetArtifactFingerprint("CRON", "10.0.0.5", " beacon ", "@daily", "echo hi", "", ""); again != base {
		t.Fatalf("fingerprint is not canonical: %q vs %q", base, again)
	}
	if other := intranetArtifactFingerprint("cron", "10.0.0.5", "beacon", "@daily", "echo bye", "", ""); other == base {
		t.Fatal("different command must change fingerprint")
	}
	if other := intranetArtifactFingerprint("cron", "10.0.0.6", "beacon", "@daily", "echo hi", "", ""); other == base {
		t.Fatal("different host must change fingerprint")
	}
	if expires, err := intranetArtifactExpiry(0); err != nil || expires != nil {
		t.Fatalf("zero ttl = %v/%v", expires, err)
	}
	expires, err := intranetArtifactExpiry(3600)
	if err != nil || expires == nil || time.Until(*expires) < 50*time.Minute {
		t.Fatalf("ttl expiry = %v/%v", expires, err)
	}
	for _, bad := range []int64{30, int64((31 * 24 * time.Hour).Seconds())} {
		if _, err := intranetArtifactExpiry(bad); err == nil {
			t.Errorf("ttl %d must be rejected", bad)
		}
	}
}

func TestIntranetPersistProfileIdempotentAndTTL(t *testing.T) {
	pg := prescanTestDB(t)
	s, sess, home := newIntranetPersistFixture(t, pg)
	in := intranetPersistInput{
		SessionID: sess.ID, Kind: db.IntranetArtifactProfile, Command: "echo jw-profile",
		Name: "profile-idem", TTLSeconds: 3600,
	}
	art, _, verify, reused, err := s.intranetPersist(context.Background(), pg, in)
	if err != nil {
		t.Fatalf("profile persist: %v verify=%+v", err, verify)
	}
	if reused || art == nil || art.ExpiresAt == nil || art.Fingerprint == "" {
		t.Fatalf("profile artifact = %+v reused=%v", art, reused)
	}
	profilePath := filepath.Join(home, ".profile")
	data, err := os.ReadFile(profilePath)
	if err != nil || !strings.Contains(string(data), "echo jw-profile # jw:") {
		t.Fatalf("profile = %q err=%v", data, err)
	}

	again, _, _, reusedAgain, err := s.intranetPersist(context.Background(), pg, in)
	if err != nil || !reusedAgain || again.ID != art.ID {
		t.Fatalf("idempotent redeploy = %+v reused=%v err=%v", again, reusedAgain, err)
	}
	data, _ = os.ReadFile(profilePath)
	if strings.Count(string(data), "echo jw-profile") != 1 {
		t.Fatalf("profile command duplicated: %q", data)
	}

	if _, _, vout, ok, err := s.intranetRevokeArtifact(context.Background(), pg, art.ID, 0); err != nil || !ok {
		t.Fatalf("profile revoke ok=%v err=%v verify=%+v", ok, err, vout)
	}
	data, _ = os.ReadFile(profilePath)
	if strings.Contains(string(data), "jw-profile") {
		t.Fatalf("profile command survived revoke: %q", data)
	}
}

// Apache 不给 www-data 设置 HOME：只认 "$HOME" 的维持脚本会把 .profile 拼成
// /.profile，落地物落到根目录然后报「部署未通过验证」。这里只跑家目录解析片段。
func TestSSHHomeScriptResolvesWhenEnvHomeEmpty(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("posix shell fragment")
	}
	frag, err := intranetSSHHomeScript("")
	if err != nil {
		t.Fatalf("home script: %v", err)
	}
	env := make([]string, 0, len(os.Environ()))
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "HOME=") {
			env = append(env, kv)
		}
	}
	cmd := exec.Command("/bin/sh", "-c", frag+"\nprintf '%s' \"$home\"")
	cmd.Env = append(env, "HOME=")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("home resolution failed with empty HOME: %v (%q)", err, out)
	}
	home := strings.TrimSpace(string(out))
	if home == "" || home == "/" {
		t.Fatalf("resolved home = %q, want the account home directory", home)
	}
	if fi, serr := os.Stat(home); serr != nil || !fi.IsDir() {
		t.Fatalf("resolved home %q is not a directory: %v", home, serr)
	}
}

func TestBuildProfilePersistPlanWarnsUnusableShell(t *testing.T) {
	plan, err := buildProfilePersistPlan(intranetPersistInput{Command: "echo jw", User: "www-data"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(plan.Deploy, intranetWarnNoLoginShell) || !strings.Contains(plan.Deploy, "getent passwd 'www-data'") {
		t.Errorf("profile deploy = %q", plan.Deploy)
	}
}

func TestIntranetPersistFailureReasonQuotesTarget(t *testing.T) {
	run := intranetExecOutcome{Output: "mkdir: cannot create directory '/var/www/.ssh': Permission denied", ExitCode: 1, IsError: true}
	got := intranetPersistFailureReason(run, intranetExecOutcome{ExitCode: -1})
	if !strings.Contains(got, "Permission denied") {
		t.Fatalf("reason = %q, must carry the target-side error", got)
	}
	if got2 := intranetPersistFailureReason(intranetExecOutcome{ExitCode: 3, IsError: true}, intranetExecOutcome{ExitCode: -1}); !strings.Contains(got2, "退出码 3") {
		t.Fatalf("silent failure reason = %q", got2)
	}
	if got3 := intranetPersistFailureReason(intranetExecOutcome{}, intranetExecOutcome{Output: "JW_ARTIFACT_GONE"}); !strings.Contains(got3, "JW_ARTIFACT_GONE") {
		t.Fatalf("verify output must win over an empty deploy: %q", got3)
	}
}

func TestBuildIntranetPersistPlanKindValidation(t *testing.T) {
	if _, err := buildIntranetPersistPlan(intranetPersistInput{Kind: "file"}); err == nil {
		t.Fatal("file is not a standard persistence module")
	}
	if _, err := buildIntranetPersistPlan(intranetPersistInput{Kind: db.IntranetArtifactSchtasks, Command: "echo hi"}); err != nil {
		t.Fatalf("schtasks dispatch: %v", err)
	}
	if _, err := buildIntranetPersistPlan(intranetPersistInput{Kind: db.IntranetArtifactRegistry, Command: "echo hi"}); err != nil {
		t.Fatalf("registry dispatch: %v", err)
	}
}

func TestIntranetPersistKindForOS(t *testing.T) {
	for _, kind := range []string{
		db.IntranetArtifactCron, db.IntranetArtifactSystemd, db.IntranetArtifactUserSystemd,
		db.IntranetArtifactAt, db.IntranetArtifactProfile, db.IntranetArtifactSSHKey,
	} {
		if err := intranetPersistKindForOS(kind, intranetOSPosix); err != nil {
			t.Errorf("posix kind %s rejected: %v", kind, err)
		}
		if err := intranetPersistKindForOS(kind, intranetOSWindows); err == nil {
			t.Errorf("posix kind %s must be rejected on Windows", kind)
		}
	}
	for _, kind := range []string{
		db.IntranetArtifactSchtasks, db.IntranetArtifactRegistry,
		db.IntranetArtifactService, db.IntranetArtifactWMI, db.IntranetArtifactStartup,
	} {
		if err := intranetPersistKindForOS(kind, intranetOSWindows); err != nil {
			t.Errorf("windows kind %s rejected: %v", kind, err)
		}
		if err := intranetPersistKindForOS(kind, intranetOSPosix); err == nil {
			t.Errorf("windows kind %s must be rejected on POSIX", kind)
		}
	}
	if err := intranetPersistKindForOS("file", intranetOSPosix); err == nil {
		t.Fatal("unknown kind must be rejected")
	}
}

// newIntranetPersistFixture wires a fake PHP webshell that runs the delivered
// script locally under a temp HOME and a stub crontab. It lets the generated
// deploy/revoke commands execute for real without touching the host.
func newIntranetPersistFixture(t *testing.T, pg *db.DB) (*Server, *db.IntranetSession, string) {
	t.Helper()
	home := t.TempDir()
	binDir := t.TempDir()
	crontabStub := `#!/bin/sh
f="$HOME/.crontab"
case "$1" in
  -l) [ -f "$f" ] && cat "$f" || exit 1 ;;
  -) cat > "$f" ;;
  *) exit 2 ;;
esac
`
	if err := os.WriteFile(filepath.Join(binDir, "crontab"), []byte(crontabStub), 0o755); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		raw := r.FormValue("jingwei")
		const prefix = "@system(base64_decode('"
		const suffix = "'));"
		if !strings.HasPrefix(raw, prefix) || !strings.HasSuffix(raw, suffix) {
			_, _ = w.Write([]byte("usage"))
			return
		}
		script, err := base64.StdEncoding.DecodeString(strings.TrimSuffix(strings.TrimPrefix(raw, prefix), suffix))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		cmd := exec.Command("/bin/sh", "-c", string(script))
		cmd.Dir = home
		cmd.Env = append(os.Environ(), "HOME="+home, "PATH="+binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
		out, _ := cmd.CombinedOutput()
		_, _ = w.Write(out)
	}))
	t.Cleanup(srv.Close)

	ws, err := pg.CreateWebshell(db.WebshellInput{
		Name: "persist-fixture", URL: srv.URL, ShellType: "php", Password: "jingwei",
		Target: "127.0.0.1", Source: "manual",
	})
	if err != nil {
		t.Fatal(err)
	}
	sess, err := pg.CreateIntranetSession(db.IntranetSessionInput{
		Name: "persist-fixture", WebshellID: ws.ID, Host: "10.250.88.5", Cwd: "/",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pg.Exec(`DELETE FROM intranet_artifacts WHERE session_id=$1`, sess.ID)
		_, _ = pg.Exec(`DELETE FROM intranet_sessions WHERE id=$1`, sess.ID)
		_, _ = pg.Exec(`DELETE FROM webshells WHERE id=$1`, ws.ID)
	})
	return &Server{m: &Manager{pg: pg}}, sess, home
}

func TestIntranetPersistCronDeployAndRevoke(t *testing.T) {
	pg := prescanTestDB(t)
	s, sess, home := newIntranetPersistFixture(t, pg)

	art, out, verify, _, err := s.intranetPersist(context.Background(), pg, intranetPersistInput{
		SessionID: sess.ID, Kind: db.IntranetArtifactCron,
		Schedule: "*/5 * * * *", Command: "echo jw-beacon", Name: "t-cron",
	})
	if err != nil {
		t.Fatalf("persist failed: %v out=%+v verify=%+v", err, out, verify)
	}
	if art == nil || art.Status != db.IntranetArtifactActive || art.Host != "10.250.88.5" {
		t.Fatalf("artifact = %+v", art)
	}
	if art.TaskID != nil {
		t.Fatalf("session without task should not invent one: %+v", art.TaskID)
	}
	crontab, err := os.ReadFile(filepath.Join(home, ".crontab"))
	if err != nil {
		t.Fatalf("stub crontab not written: %v", err)
	}
	if !strings.Contains(string(crontab), "echo jw-beacon") || !strings.Contains(string(crontab), "# jw:") {
		t.Fatalf("crontab = %q", crontab)
	}

	revoked, _, vout, ok, err := s.intranetRevokeArtifact(context.Background(), pg, art.ID, 0)
	if err != nil || !ok {
		t.Fatalf("revoke ok=%v err=%v verify=%+v", ok, err, vout)
	}
	if revoked.Status != db.IntranetArtifactRevoked || revoked.RevokedAt == nil {
		t.Fatalf("revoked artifact = %+v", revoked)
	}
	crontab, _ = os.ReadFile(filepath.Join(home, ".crontab"))
	if strings.Contains(string(crontab), "jw-beacon") {
		t.Fatalf("crontab entry survived revoke: %q", crontab)
	}

	again, _, _, revokedAgain, err := s.intranetRevokeArtifact(context.Background(), pg, art.ID, 0)
	if err != nil || !revokedAgain || again.Status != db.IntranetArtifactRevoked {
		t.Fatalf("second revoke should be a no-op: %+v ok=%v err=%v", again, revokedAgain, err)
	}
}

func TestIntranetPersistSSHKeyDeployAndRevoke(t *testing.T) {
	pg := prescanTestDB(t)
	s, sess, home := newIntranetPersistFixture(t, pg)
	const key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl tester@example"

	art, out, verify, _, err := s.intranetPersist(context.Background(), pg, intranetPersistInput{
		SessionID: sess.ID, Kind: db.IntranetArtifactSSHKey, PublicKey: key,
	})
	if err != nil {
		t.Fatalf("persist failed: %v out=%+v verify=%+v", err, out, verify)
	}
	authFile := filepath.Join(home, ".ssh", "authorized_keys")
	data, err := os.ReadFile(authFile)
	if err != nil {
		t.Fatalf("authorized_keys missing: %v", err)
	}
	if !strings.Contains(string(data), "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl jw:") {
		t.Fatalf("authorized_keys = %q", data)
	}
	if strings.Contains(string(data), "tester@example") {
		t.Fatalf("original comment leaked into authorized_keys: %q", data)
	}

	if _, _, vout, ok, err := s.intranetRevokeArtifact(context.Background(), pg, art.ID, 0); err != nil || !ok {
		t.Fatalf("revoke ok=%v err=%v verify=%+v", ok, err, vout)
	}
	data, err = os.ReadFile(authFile)
	if err != nil {
		t.Fatalf("authorized_keys removed by revoke: %v", err)
	}
	if strings.Contains(string(data), "jw:") {
		t.Fatalf("key survived revoke: %q", data)
	}
}

func TestIntranetRevokeTrustsGoneVerifyOverExitCode(t *testing.T) {
	pg := prescanTestDB(t)
	s, sess, _ := newIntranetPersistFixture(t, pg)

	art, err := s.intranetRegisterArtifact(pg, intranetArtifactRegisterInput{
		SessionID: sess.ID, Kind: db.IntranetArtifactOther, Name: "already-gone",
		RevokeCommand: "false",
		VerifyCommand: "echo " + intranetArtifactGone,
	})
	if err != nil {
		t.Fatal(err)
	}
	revoked, revokeOut, verifyOut, ok, err := s.intranetRevokeArtifact(context.Background(), pg, art.ID, 0)
	if err != nil || !ok {
		t.Fatalf("verify GONE should be enough: ok=%v err=%v revoke=%+v verify=%+v", ok, err, revokeOut, verifyOut)
	}
	if revoked.Status != db.IntranetArtifactRevoked {
		t.Fatalf("artifact = %+v", revoked)
	}
}

func TestIntranetUploadRegistersRevocableArtifact(t *testing.T) {
	pg := prescanTestDB(t)
	s, sess, home := newIntranetPersistFixture(t, pg)
	target := filepath.Join(home, "tool.sh")

	out, err := s.intranetUpload(context.Background(), pg, sess, target, []byte("#!/bin/sh\necho hi\n"))
	if err != nil {
		t.Fatalf("upload failed: %v out=%+v", err, out)
	}
	if !strings.Contains(out.Note, "落地物") {
		t.Fatalf("upload note = %q", out.Note)
	}
	rows, total, err := pg.ListIntranetArtifacts(db.IntranetArtifactFilter{SessionID: sess.ID, Kind: db.IntranetArtifactFile})
	if err != nil || total != 1 || len(rows) != 1 {
		t.Fatalf("artifacts total=%d rows=%+v err=%v", total, rows, err)
	}
	art := rows[0]
	if art.Path != target || art.Status != db.IntranetArtifactActive || art.Name != "tool.sh" {
		t.Fatalf("artifact = %+v", art)
	}

	if _, _, vout, ok, err := s.intranetRevokeArtifact(context.Background(), pg, art.ID, 0); err != nil || !ok {
		t.Fatalf("revoke ok=%v err=%v verify=%+v", ok, err, vout)
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatalf("uploaded file survived revoke: err=%v", err)
	}
}

func TestIntranetUploadSkipsLedgerForExistingFile(t *testing.T) {
	pg := prescanTestDB(t)
	s, sess, home := newIntranetPersistFixture(t, pg)
	target := filepath.Join(home, "existing.conf")
	if err := os.WriteFile(target, []byte("original"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := s.intranetUpload(context.Background(), pg, sess, target, []byte("replaced")); err != nil {
		t.Fatal(err)
	}
	rows, total, err := pg.ListIntranetArtifacts(db.IntranetArtifactFilter{SessionID: sess.ID})
	if err != nil || total != 0 || len(rows) != 0 {
		t.Fatalf("overwritten file must not enter the ledger: total=%d rows=%+v err=%v", total, rows, err)
	}
}

func TestIntranetRegisterArtifactValidation(t *testing.T) {
	pg := prescanTestDB(t)
	s, sess, _ := newIntranetPersistFixture(t, pg)

	if _, err := s.intranetRegisterArtifact(pg, intranetArtifactRegisterInput{SessionID: sess.ID}); err == nil {
		t.Fatal("manual registration without revoke command must be rejected")
	}
	art, err := s.intranetRegisterArtifact(pg, intranetArtifactRegisterInput{
		SessionID: sess.ID, Kind: db.IntranetArtifactOther, Name: "manual",
		Path: "/tmp/manual", RevokeCommand: "rm -f /tmp/manual",
		VerifyCommand: "test -e /tmp/manual && echo JW_ARTIFACT_PRESENT || echo JW_ARTIFACT_GONE",
	})
	if err != nil {
		t.Fatal(err)
	}
	if art.Host != "10.250.88.5" || art.SessionID == nil || *art.SessionID != sess.ID {
		t.Fatalf("artifact = %+v", art)
	}
	revoked, _, _, ok, err := s.intranetRevokeArtifact(context.Background(), pg, art.ID, 0)
	if err != nil || !ok || revoked.Status != db.IntranetArtifactRevoked {
		t.Fatalf("revoke = %+v ok=%v err=%v", revoked, ok, err)
	}
}
