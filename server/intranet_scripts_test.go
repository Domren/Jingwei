package server

import (
	"strings"
	"testing"
)

// F3：脚本输出必须变成结构化条目，而不是原样塞一段 stdout。
func TestParseIntranetScriptOutput(t *testing.T) {
	passwd := "root:x:0:0:root:/root:/bin/bash\n" +
		"daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n" +
		"alice:x:1000:1000::/home/alice:/bin/bash\n"
	out := parseIntranetScriptOutput("passwd", "linux", passwd)
	items := out["items"].([]any)
	if len(items) != 2 {
		t.Fatalf("passwd items = %+v", items)
	}
	first := items[0].(map[string]any)
	if first["user"] != "root" || first["uid"] != 0 {
		t.Fatalf("root 条目 = %+v", first)
	}

	ports := "Netid State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n" +
		"tcp   LISTEN 0      128    0.0.0.0:22       0.0.0.0:*     users:((\"sshd\",pid=1,fd=3))\n" +
		"udp   UNCONN 0      0      127.0.0.53:53    0.0.0.0:*\n"
	out = parseIntranetScriptOutput("ports", "linux", ports)
	items = out["items"].([]any)
	if len(items) != 1 {
		t.Fatalf("ports items = %+v", items)
	}
	p := items[0].(map[string]any)
	if p["port"] != "22" || !strings.Contains(p["process"].(string), "sshd") {
		t.Fatalf("端口条目 = %+v", p)
	}

	sudo := "User alice may run the following commands:\n    (root) NOPASSWD: /usr/bin/systemctl\n    (root) /usr/bin/less\n"
	out = parseIntranetScriptOutput("sudo", "linux", sudo)
	items = out["items"].([]any)
	if len(items) != 2 { // 用户行 + NOPASSWD 一行；普通条目只保留 'may run' 行
		t.Fatalf("sudo items = %+v", items)
	}

	// 脚本按「# <路径>」分段输出，公钥条目要带上来源文件：维持痕迹得指到具体文件。
	keys := "# /root/.ssh/authorized_keys\nssh-ed25519 AAAAC3Nza alice@laptop\nssh-rsa AAAAB3 bob@server\n# /home/jw/.ssh/authorized_keys\necdsa-sha2-nistp256 AAAAE2 carol@pc\n"
	out = parseIntranetScriptOutput("ssh_keys", "linux", keys)
	items = out["items"].([]any)
	if len(items) != 3 {
		t.Fatalf("ssh keys = %+v", items)
	}
	wantFile := []string{"/root/.ssh/authorized_keys", "/root/.ssh/authorized_keys", "/home/jw/.ssh/authorized_keys"}
	for i, want := range wantFile {
		got := items[i].(map[string]any)["file"]
		if got != want {
			t.Fatalf("第 %d 条公钥的来源文件 = %v，期望 %q（全部：%+v）", i, got, want, items)
		}
	}
	if items[2].(map[string]any)["type"] != "ecdsa-sha2-nistp256" {
		t.Fatalf("类型解析不对: %+v", items[2])
	}

	// 补丁这一档换成基线比对（F5）：只列 KB 行等于把「缺不缺」留给人自己看，
	// 而这条脚本的产出应该是结论。
	patches := "OS Name:  Microsoft Windows 10 Pro\nOS Version: 10.0.19044 N/A Build 19044\n" +
		"HotFixID  InstalledOn\nKB5034441  1/9/2024\nKB5034123  1/10/2024\n"
	out = parseIntranetScriptOutput("patches", "windows", patches)
	if out["kind"] != "patches" || out["installed"].(int) != 2 {
		t.Fatalf("patches = %+v", out)
	}
	if out["incomplete"].(bool) {
		t.Fatalf("输入完整却被判为不完整: %+v", out)
	}
	if !strings.Contains(out["summary"].(string), "待确认") {
		t.Fatalf("基线未命中要带待确认口径: %v", out["summary"])
	}

	endpoint := strings.Join([]string{
		`"Image Name","PID"`,
		`"MsMpEng.exe","4120"`,
		`"chrome.exe","9012"`,
	}, "\n")
	out = parseIntranetScriptOutput("endpoint", "windows", endpoint)
	if out["kind"] != "endpoint" || out["products"].(int) != 1 {
		t.Fatalf("endpoint = %+v", out)
	}
	if out["unreadable"].(bool) {
		t.Fatal("读到进程列表却判为不可读")
	}

	// 命令失败/权限不足：不能写成「没有终端防护」。
	out = parseIntranetScriptOutput("endpoint", "windows", "ERROR: Access is denied.")
	if out["unreadable"].(bool) != true || !strings.Contains(out["summary"].(string), "无法判断") {
		t.Fatalf("空输入应落到「无法判断」: %+v", out)
	}
}

func TestScriptCatalogForOS(t *testing.T) {
	linux := scriptCatalogForOS("linux")
	windows := scriptCatalogForOS("windows")
	if len(linux) == 0 || len(windows) == 0 {
		t.Fatalf("linux=%d windows=%d", len(linux), len(windows))
	}
	for _, s := range linux {
		if s.OS != "linux" {
			t.Fatalf("linux 目录混入 %+v", s)
		}
		if strings.TrimSpace(s.Command) == "" {
			t.Fatalf("脚本 %s 没有命令", s.ID)
		}
	}
	for _, s := range windows {
		if s.OS != "windows" {
			t.Fatalf("windows 目录混入 %+v", s)
		}
		if strings.TrimSpace(s.Command) == "" {
			t.Fatalf("脚本 %s 没有命令", s.ID)
		}
		// Windows 脚本走 cmd.exe：/dev/null 是 POSIX 写法，在 cmd 里会被当成
		// 文件路径，stderr 不但没被吞掉还可能往目标上写出一个怪文件。
		if strings.Contains(s.Command, "/dev/null") {
			t.Fatalf("脚本 %s 用了 POSIX 重定向，cmd.exe 不认：%s", s.ID, s.Command)
		}
	}
	if _, ok := intranetScriptByID_("linux-ports"); !ok {
		t.Fatal("按 ID 取不到脚本")
	}
}
