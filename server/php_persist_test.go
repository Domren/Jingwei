package server

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Autumn-27/jingwei/db"
	"github.com/Autumn-27/jingwei/scanner"
)

func phpPersistTestLayout(t *testing.T, mode string, configExisted bool) (phpPersistLayout, func()) {
	t.Helper()
	root := t.TempDir()
	tmp := t.TempDir()
	layout := phpPersistLayout{
		Mode: mode, OSKind: intranetOSPosix, Directory: root,
		PayloadName: ".jwdeadbeef.php", PayloadPath: filepath.Join(root, ".jwdeadbeef.php"),
		ConfigName: ".htaccess", ConfigPath: filepath.Join(root, ".htaccess"),
		BlockPath:  filepath.Join(root, ".jwblkdeadbeef.tmp"),
		TriggerURL: "http://example.test/index.php", Token: "deadbeef",
		TmpDir: tmp, Build: "0123456789abcdef", ConfigExisted: configExisted,
	}
	if mode == db.IntranetArtifactPHPUserINI {
		layout.ConfigName = ".user.ini"
		layout.ConfigPath = filepath.Join(root, ".user.ini")
	}
	layout.BeginMarker = phpPersistMarker(mode, layout.Token, true)
	layout.EndMarker = phpPersistMarker(mode, layout.Token, false)
	layout.ConfigBlock = phpPersistConfigBlock(mode, layout.BeginMarker, layout.EndMarker, layout.PayloadPath)
	if configExisted {
		original := "Options -Indexes\n# existing app rules\n"
		if err := os.WriteFile(layout.ConfigPath, []byte(original), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(layout.PayloadPath, []byte("<?php echo 'payload';"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(layout.BlockPath, []byte(layout.ConfigBlock), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, sidecar := range phpPersistSidecarPaths(layout) {
		if err := os.WriteFile(sidecar, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return layout, func() {}
}

func phpPersistRunSH(t *testing.T, command string) string {
	t.Helper()
	out, err := exec.Command("/bin/sh", "-c", command).CombinedOutput()
	if err != nil {
		t.Fatalf("命令失败: %v\n命令: %s\n输出: %s", err, command, out)
	}
	return string(out)
}

func TestPHPPersistPOSIXRoundTripExistingConfig(t *testing.T) {
	layout, cleanup := phpPersistTestLayout(t, db.IntranetArtifactPHPHtaccess, true)
	defer cleanup()

	appendOut := phpPersistRunSH(t, phpPersistAppendCommand(layout))
	if !strings.Contains(appendOut, phpPersistConfigOK) {
		t.Fatalf("追加配置失败: %s", appendOut)
	}
	content, err := os.ReadFile(layout.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	text := string(content)
	for _, want := range []string{"Options -Indexes", layout.BeginMarker, "php_value auto_prepend_file", layout.EndMarker} {
		if !strings.Contains(text, want) {
			t.Fatalf("配置缺少 %q:\n%s", want, text)
		}
	}
	if out := phpPersistRunSH(t, phpPersistVerifyCommand(layout)); !strings.Contains(out, intranetArtifactPresent) {
		t.Fatalf("验证应为 PRESENT: %s", out)
	}

	revokeOut := phpPersistRunSH(t, phpPersistRevokeCommand(layout))
	if !strings.Contains(revokeOut, intranetArtifactOK) {
		t.Fatalf("撤销未报成功: %s", revokeOut)
	}
	content, err = os.ReadFile(layout.ConfigPath)
	if err != nil {
		t.Fatalf("原本存在的配置不应被删除: %v", err)
	}
	text = string(content)
	if strings.Contains(text, layout.BeginMarker) || strings.Contains(text, "auto_prepend_file") {
		t.Fatalf("撤销后配置仍含标记:\n%s", text)
	}
	if !strings.Contains(text, "Options -Indexes") || !strings.Contains(text, "# existing app rules") {
		t.Fatalf("撤销破坏了原有配置:\n%s", text)
	}
	if _, err := os.Stat(layout.PayloadPath); !os.IsNotExist(err) {
		t.Fatalf("撤销后载荷仍存在")
	}
	for _, sidecar := range phpPersistSidecarPaths(layout) {
		if _, err := os.Stat(sidecar); !os.IsNotExist(err) {
			t.Fatalf("撤销后旁路文件仍存在: %s", sidecar)
		}
	}
	if out := phpPersistRunSH(t, phpPersistVerifyCommand(layout)); !strings.Contains(out, intranetArtifactGone) {
		t.Fatalf("撤销后验证应为 GONE: %s", out)
	}
}

func TestPHPPersistPOSIXRoundTripNewConfig(t *testing.T) {
	layout, cleanup := phpPersistTestLayout(t, db.IntranetArtifactPHPUserINI, false)
	defer cleanup()

	if out := phpPersistRunSH(t, phpPersistAppendCommand(layout)); !strings.Contains(out, phpPersistConfigOK) {
		t.Fatalf("追加配置失败: %s", out)
	}
	content, err := os.ReadFile(layout.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(content), "auto_prepend_file = \"") {
		t.Fatalf("user_ini 配置内容不正确:\n%s", content)
	}
	if out := phpPersistRunSH(t, phpPersistRevokeCommand(layout)); !strings.Contains(out, intranetArtifactOK) {
		t.Fatalf("撤销未报成功: %s", out)
	}
	if _, err := os.Stat(layout.ConfigPath); !os.IsNotExist(err) {
		t.Fatalf("新建的配置在撤销后应被删除")
	}
	if out := phpPersistRunSH(t, phpPersistVerifyCommand(layout)); !strings.Contains(out, intranetArtifactGone) {
		t.Fatalf("撤销后验证应为 GONE: %s", out)
	}
}

func TestPHPPersistAppendRefusesDuplicateMarker(t *testing.T) {
	layout, cleanup := phpPersistTestLayout(t, db.IntranetArtifactPHPHtaccess, true)
	defer cleanup()
	_ = phpPersistRunSH(t, phpPersistAppendCommand(layout))
	// Recreate the block file, then append again: the marker guard must refuse.
	if err := os.WriteFile(layout.BlockPath, []byte(layout.ConfigBlock), 0o644); err != nil {
		t.Fatal(err)
	}
	out := phpPersistRunSH(t, phpPersistAppendCommand(layout))
	if !strings.Contains(out, phpPersistConfigExist) {
		t.Fatalf("重复追加应被拒绝: %s", out)
	}
}

func TestPHPPersistValidation(t *testing.T) {
	if _, err := phpPersistDirectory("/var/www/html", "", intranetOSPosix); err != nil {
		t.Fatalf("正常目录被拒绝: %v", err)
	}
	for _, bad := range []string{"/var/www/';rm -rf /;'", "/var/www/\nhtml", "/", "relative/path", "/var/www/`id`"} {
		if _, err := phpPersistDirectory(bad, "", intranetOSPosix); err == nil {
			t.Fatalf("危险目录未被拒绝: %q", bad)
		}
	}
	if dir, err := phpPersistDirectory(`C:\inetpub\wwwroot`, "", intranetOSWindows); err != nil || dir != `C:\inetpub\wwwroot` {
		t.Fatalf("Windows 目录解析失败: %q %v", dir, err)
	}
	if _, err := phpPersistDirectory(`C:\`, "", intranetOSWindows); err == nil {
		t.Fatalf("盘符根目录应被拒绝")
	}

	if _, err := phpPersistFilename(".jw1a2b3c4d.php", "x"); err != nil {
		t.Fatalf("正常文件名被拒绝: %v", err)
	}
	for _, bad := range []string{"shell.php", ".jw.php/..", ".jw shell.php", ".user.ini"} {
		if _, err := phpPersistFilename(bad, "x"); err == nil {
			t.Fatalf("非法文件名未被拒绝: %q", bad)
		}
	}

	fpm := scanner.ShellInfo{SAPI: "fpm-fcgi", UserINIFilename: ".user.ini", UserINICacheTTL: 300}
	if mode, err := phpPersistMode("", fpm); err != nil || mode != db.IntranetArtifactPHPUserINI {
		t.Fatalf("FPM 自动模式应选择 user_ini: %q %v", mode, err)
	}
	apache := scanner.ShellInfo{SAPI: "apache2handler", ServerSoftware: "Apache/2.4"}
	if mode, err := phpPersistMode("", apache); err != nil || mode != db.IntranetArtifactPHPHtaccess {
		t.Fatalf("Apache 自动模式应选择 htaccess: %q %v", mode, err)
	}
	if _, err := phpPersistMode("htaccess", fpm); err == nil {
		t.Fatalf("FPM 下显式 htaccess 应被拒绝")
	}

	parent := "https://target.test:8443/index.php"
	if got, err := phpPersistTriggerURL("", parent); err != nil || got != parent {
		t.Fatalf("默认 trigger 失败: %q %v", got, err)
	}
	if _, err := phpPersistTriggerURL("https://other.test/x.php", parent); err == nil {
		t.Fatalf("跨主机 trigger 应被拒绝")
	}
	if _, err := phpPersistTriggerURL("http://target.test:8443/x.php", parent); err == nil {
		t.Fatalf("跨协议 trigger 应被拒绝")
	}
}

func TestPHPPersistConfigBlockAndWindowsCommands(t *testing.T) {
	payload := `C:\inetpub\wwwroot\.jw1a2b3c4d.php`
	block := phpPersistConfigBlock(db.IntranetArtifactPHPHtaccess, "# jw:prepend:abcd:begin", "# jw:prepend:abcd:end", payload)
	if !strings.Contains(block, `php_value auto_prepend_file "C:/inetpub/wwwroot/.jw1a2b3c4d.php"`) {
		t.Fatalf("Windows 路径应使用正斜杠: %s", block)
	}
	layout := phpPersistLayout{
		Mode: db.IntranetArtifactPHPHtaccess, OSKind: intranetOSWindows,
		PayloadPath: `C:\inetpub\wwwroot\.jw1a2b3c4d.php`,
		ConfigPath:  `C:\inetpub\wwwroot\.htaccess`,
		BlockPath:   `C:\inetpub\wwwroot\.jwblkabcd.tmp`,
		TmpDir:      `C:\Windows\Temp`, Build: "0123456789abcdef",
		BeginMarker: "# jw:prepend:abcd:begin", EndMarker: "# jw:prepend:abcd:end",
		ConfigExisted: true,
	}
	revoke := phpPersistRevokeCommand(layout)
	if !strings.Contains(revoke, "powershell.exe") || !strings.Contains(revoke, "Remove-Item") {
		t.Fatalf("Windows 撤销命令不正确: %s", revoke)
	}
	verify := phpPersistVerifyCommand(layout)
	if !strings.Contains(verify, intranetArtifactPresent) || !strings.Contains(verify, intranetArtifactGone) {
		t.Fatalf("Windows 验证命令不正确: %s", verify)
	}
	appendCmd := phpPersistAppendCommand(layout)
	if !strings.Contains(appendCmd, "type ") {
		t.Fatalf("Windows 追加命令不正确: %s", appendCmd)
	}
	// 台账命令里不能出现密钥/载体等秘密。
	secret := scanner.EncodeShellKey(make([]byte, 32))
	for _, cmd := range []string{revoke, verify, appendCmd} {
		if strings.Contains(cmd, secret) {
			t.Fatalf("台账命令泄露密钥")
		}
	}
}
