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
	out := parseIntranetScriptOutput("passwd", passwd)
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
	out = parseIntranetScriptOutput("ports", ports)
	items = out["items"].([]any)
	if len(items) != 1 {
		t.Fatalf("ports items = %+v", items)
	}
	p := items[0].(map[string]any)
	if p["port"] != "22" || !strings.Contains(p["process"].(string), "sshd") {
		t.Fatalf("端口条目 = %+v", p)
	}

	sudo := "User alice may run the following commands:\n    (root) NOPASSWD: /usr/bin/systemctl\n    (root) /usr/bin/less\n"
	out = parseIntranetScriptOutput("sudo", sudo)
	items = out["items"].([]any)
	if len(items) != 2 { // 用户行 + NOPASSWD 一行；普通条目只保留 'may run' 行
		t.Fatalf("sudo items = %+v", items)
	}

	keys := "ssh-ed25519 AAAAC3Nza alice@laptop\n# comment\n"
	out = parseIntranetScriptOutput("ssh_keys", keys)
	items = out["items"].([]any)
	if len(items) != 1 || items[0].(map[string]any)["comment"] != "alice@laptop" {
		t.Fatalf("ssh key = %+v", items)
	}

	patches := "HotFixID  InstalledOn\nKB5034441  1/9/2024\nKB5034123  1/10/2024\n"
	out = parseIntranetScriptOutput("windows_patches", patches)
	if out["count"].(int) != 2 {
		t.Fatalf("patches = %+v", out)
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
	if _, ok := intranetScriptByID_("linux-ports"); !ok {
		t.Fatal("按 ID 取不到脚本")
	}
}
