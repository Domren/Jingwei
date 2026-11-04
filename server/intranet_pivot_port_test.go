package server

import (
	"strings"
	"testing"

	"github.com/Autumn-27/jingwei/db"
)

// SSH 变体必须用 JINGWEI_PIVOT_SSH_PORT，而不是 JINGWEI_PIVOT_SERVER 的端口：
// 后者是 chisel server 的端口（默认 8788），拿它去 ssh 等于让目标登录 chisel。
func TestAutoSelectTunnelSSHPortIsSeparate(t *testing.T) {
	t.Setenv("JINGWEI_PIVOT_SERVER", "10.0.0.5:8788")

	sshOnly := intranetProbeInfo{Bins: []string{"ssh"}}
	tun := &db.IntranetTunnel{ID: 1, Kind: db.IntranetTunnelKindSocks5, ListenPort: 1080}

	// 没配 ssh 端口时用 22。
	t.Setenv("JINGWEI_PIVOT_SSH_PORT", "")
	deploy, reason, side := autoSelectTunnelCommand(db.IntranetTunnelKindSocks5, sshOnly, tun)
	if deploy == "" || side != db.IntranetListenSideTarget {
		t.Fatalf("ssh -D 应当生成部署命令且监听在目标侧: deploy=%q side=%q", deploy, side)
	}
	if !strings.Contains(deploy, "-p 22 ") {
		t.Fatalf("未配 JINGWEI_PIVOT_SSH_PORT 时 ssh -D 要用 22，实得: %q", deploy)
	}
	if strings.Contains(deploy, "-p 8788") {
		t.Fatalf("ssh 不能去连 chisel 的 8788: %q", deploy)
	}
	if !strings.Contains(reason, "10.0.0.5:22") {
		t.Fatalf("选型理由要写清回连地址与端口: %q", reason)
	}

	// 配了就用配的。
	t.Setenv("JINGWEI_PIVOT_SSH_PORT", "2201")
	deploy, _, _ = autoSelectTunnelCommand(db.IntranetTunnelKindSocks5, sshOnly, tun)
	if !strings.Contains(deploy, "-p 2201 ") {
		t.Fatalf("ssh -D 应当用配置端口 2201: %q", deploy)
	}

	// 端口转发（ssh -L）同理。
	fwd := &db.IntranetTunnel{ID: 2, Kind: db.IntranetTunnelKindPort, ListenPort: 8473, RemoteHost: "10.99.0.10", RemotePort: 8000}
	deploy, reason, _ = autoSelectTunnelCommand(db.IntranetTunnelKindPort, sshOnly, fwd)
	if !strings.Contains(deploy, "-L 8473:10.99.0.10:8000 -p 2201 ") {
		t.Fatalf("ssh -L 应当用配置端口 2201: %q", deploy)
	}
	if !strings.Contains(reason, "10.0.0.5:2201") {
		t.Fatalf("ssh -L 的理由要写清控制端端口: %q", reason)
	}
}

// 端口配错时必须拒绝生成命令，而不是退回 22 假装成功——目标会连到一个没人听的地方。
func TestAutoSelectTunnelRejectsBadSSHPort(t *testing.T) {
	t.Setenv("JINGWEI_PIVOT_SERVER", "10.0.0.5:8788")
	sshOnly := intranetProbeInfo{Bins: []string{"ssh"}}
	tun := &db.IntranetTunnel{ID: 3, Kind: db.IntranetTunnelKindSocks5, ListenPort: 1080}

	for _, bad := range []string{"0", "65536", "abc", "-2"} {
		t.Setenv("JINGWEI_PIVOT_SSH_PORT", bad)
		deploy, reason, _ := autoSelectTunnelCommand(db.IntranetTunnelKindSocks5, sshOnly, tun)
		if deploy != "" {
			t.Fatalf("端口 %q 非法却生成了命令: %q", bad, deploy)
		}
		if !strings.Contains(reason, "JINGWEI_PIVOT_SSH_PORT") {
			t.Fatalf("端口 %q 的拒绝理由要指向该变量: %q", bad, reason)
		}
	}

	// 前后空白按 TrimSpace 处理（与项目里其它 env 一致），边界值放行。
	t.Setenv("JINGWEI_PIVOT_SSH_PORT", " 65535 ")
	if deploy, _, _ := autoSelectTunnelCommand(db.IntranetTunnelKindSocks5, sshOnly, tun); !strings.Contains(deploy, "-p 65535 ") {
		t.Fatalf("65535 两侧空白应当被裁掉后接受: %q", deploy)
	}
	t.Setenv("JINGWEI_PIVOT_SSH_PORT", "65535")
	if deploy, _, _ := autoSelectTunnelCommand(db.IntranetTunnelKindSocks5, sshOnly, tun); !strings.Contains(deploy, "-p 65535 ") {
		t.Fatalf("65535 是合法端口，应当生成命令: %q", deploy)
	}
}

// chisel 变体不受影响：它拨的还是 JINGWEI_PIVOT_SERVER 自己的端口。
func TestAutoSelectTunnelChiselKeepsPivotPort(t *testing.T) {
	t.Setenv("JINGWEI_PIVOT_SERVER", "10.0.0.5:9443")
	t.Setenv("JINGWEI_PIVOT_SSH_PORT", "2201")
	chiselOnly := intranetProbeInfo{Bins: []string{"chisel"}}
	tun := &db.IntranetTunnel{ID: 4, Kind: db.IntranetTunnelKindSocks5, ListenPort: 1080}

	deploy, _, side := autoSelectTunnelCommand(db.IntranetTunnelKindSocks5, chiselOnly, tun)
	if !strings.Contains(deploy, "10.0.0.5:9443") {
		t.Fatalf("chisel 应当拨控制端自带端口: %q", deploy)
	}
	if strings.Contains(deploy, "9443 2201") || strings.Contains(deploy, "2201:socks") {
		t.Fatalf("chisel 不该掺入 ssh 端口: %q", deploy)
	}
	if side != db.IntranetListenSidePivot {
		t.Fatalf("chisel client 的 SOCKS 监听开在控制端: side=%q", side)
	}
}
