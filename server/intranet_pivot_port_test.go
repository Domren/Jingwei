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
	if deploy == "" || side != db.IntranetListenSidePivot {
		t.Fatalf("ssh -R 应当生成部署命令且监听在控制端: deploy=%q side=%q", deploy, side)
	}
	if !strings.Contains(deploy, "-p 22 ") {
		t.Fatalf("未配 JINGWEI_PIVOT_SSH_PORT 时 ssh -R 要用 22，实得: %q", deploy)
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
		t.Fatalf("ssh -R 应当用配置端口 2201: %q", deploy)
	}

	// 端口转发（ssh -R 带目的地）同理。
	fwd := &db.IntranetTunnel{ID: 2, Kind: db.IntranetTunnelKindPort, ListenPort: 8473, RemoteHost: "10.99.0.10", RemotePort: 8000}
	deploy, reason, side = autoSelectTunnelCommand(db.IntranetTunnelKindPort, sshOnly, fwd)
	if !strings.Contains(deploy, "-R 0.0.0.0:8473:10.99.0.10:8000 -p 2201 ") {
		t.Fatalf("ssh -R 应当用配置端口 2201: %q", deploy)
	}
	if side != db.IntranetListenSidePivot {
		t.Fatalf("ssh -R 的监听在控制端: %q", side)
	}
	if !strings.Contains(reason, "10.0.0.5:2201") {
		t.Fatalf("ssh -R 的理由要写清控制端端口: %q", reason)
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

// chisel 1.13 不接受 `--fingerprint auto`：客户端把它当指纹校验，握手报
// Invalid fingerprint 后无限重试。默认必须不带该参数，只有配了真指纹才带上。
func TestAutoSelectTunnelChiselFingerprint(t *testing.T) {
	t.Setenv("JINGWEI_PIVOT_SERVER", "10.0.0.5:8788")
	t.Setenv("JINGWEI_PIVOT_CHISEL_FINGERPRINT", "")
	chiselOnly := intranetProbeInfo{Bins: []string{"chisel"}}
	socksTun := &db.IntranetTunnel{ID: 11, Kind: db.IntranetTunnelKindSocks5, ListenPort: 1080}

	deploy, reason, _ := autoSelectTunnelCommand(db.IntranetTunnelKindSocks5, chiselOnly, socksTun)
	if deploy == "" {
		t.Fatalf("默认应当能生成 chisel 命令: reason=%q", reason)
	}
	if strings.Contains(deploy, "--fingerprint") {
		t.Fatalf("默认不该带 --fingerprint: %q", deploy)
	}
	if !strings.Contains(reason, "未固定服务端指纹") {
		t.Fatalf("理由要说明当前信任状态: %q", reason)
	}

	const fp = "llm64BPu/uaJXdhIZrhGqdRuJrqYBE/I2a5DtcViJNI="
	t.Setenv("JINGWEI_PIVOT_CHISEL_FINGERPRINT", "  "+fp+"  ")
	deploy, reason, _ = autoSelectTunnelCommand(db.IntranetTunnelKindSocks5, chiselOnly, socksTun)
	if !strings.Contains(deploy, "--fingerprint '"+fp+"'") {
		t.Fatalf("配了指纹就该带上（且要 shell 引用起来）: %q", deploy)
	}
	if !strings.Contains(reason, "已按 JINGWEI_PIVOT_CHISEL_FINGERPRINT 固定") {
		t.Fatalf("理由要反映已固定: %q", reason)
	}

	// 端口转发分支同理，且 R: 形态不变。
	fwd := &db.IntranetTunnel{ID: 12, Kind: db.IntranetTunnelKindRemote, ListenPort: 9001, RemoteHost: "10.99.0.10", RemotePort: 8000}
	deploy, _, side := autoSelectTunnelCommand(db.IntranetTunnelKindRemote, chiselOnly, fwd)
	if !strings.Contains(deploy, "--fingerprint '"+fp+"'") || !strings.Contains(deploy, "R:0.0.0.0:9001:10.99.0.10:8000") {
		t.Fatalf("R: 形态的 chisel 命令要同时保住指纹与 spec: %q", deploy)
	}
	if side != db.IntranetListenSidePivot {
		t.Fatalf("R: 的监听在控制端（真机实测 chisel server 持有该监听）: %q", side)
	}

	// 非法值（含当年那个 auto）必须拒绝生成，而不是照样下发一条连不上的命令。
	for _, bad := range []string{"auto", "sha256:abc", "short", "'; touch /tmp/pwn #"} {
		t.Setenv("JINGWEI_PIVOT_CHISEL_FINGERPRINT", bad)
		deploy, reason, _ := autoSelectTunnelCommand(db.IntranetTunnelKindSocks5, chiselOnly, socksTun)
		if deploy != "" {
			t.Fatalf("指纹 %q 非法却生成了命令: %q", bad, deploy)
		}
		if !strings.Contains(reason, "JINGWEI_PIVOT_CHISEL_FINGERPRINT") {
			t.Fatalf("拒绝理由要点名变量: %q", reason)
		}
	}
}

// 监听地址写进命令：chisel 不写绑定地址时只听控制端回环，容器里的平台进程拨不到；
// ssh -R 不写时控制端 sshd 也只听回环。两个都得带上登记值（2026-11-05 真机验证）。
func TestAutoSelectTunnelHonoursListenHost(t *testing.T) {
	t.Setenv("JINGWEI_PIVOT_SERVER", "10.0.0.5:8788")
	t.Setenv("JINGWEI_PIVOT_CHISEL_FINGERPRINT", "")
	chiselOnly := intranetProbeInfo{Bins: []string{"chisel"}}
	sshOnly := intranetProbeInfo{Bins: []string{"ssh"}}

	rev := &db.IntranetTunnel{ID: 21, Kind: db.IntranetTunnelKindRemote, ListenHost: "0.0.0.0", ListenPort: 9001, RemoteHost: "10.99.0.10", RemotePort: 8000}
	deploy, _, _ := autoSelectTunnelCommand(rev.Kind, chiselOnly, rev)
	if !strings.Contains(deploy, "R:0.0.0.0:9001:10.99.0.10:8000") {
		t.Fatalf("chisel 反向要把监听地址写进 spec: %q", deploy)
	}

	bound := &db.IntranetTunnel{ID: 22, Kind: db.IntranetTunnelKindRemote, ListenHost: "127.0.0.1", ListenPort: 9002, RemoteHost: "10.99.0.10", RemotePort: 8000}
	deploy, _, _ = autoSelectTunnelCommand(bound.Kind, chiselOnly, bound)
	if !strings.Contains(deploy, "R:127.0.0.1:9002:") {
		t.Fatalf("登记了具体监听地址就该照它绑，不能自作主张放宽: %q", deploy)
	}

	socks := &db.IntranetTunnel{ID: 23, Kind: db.IntranetTunnelKindSocks5, ListenHost: "0.0.0.0", ListenPort: 1080}
	deploy, _, _ = autoSelectTunnelCommand(socks.Kind, chiselOnly, socks)
	if !strings.Contains(deploy, "R:0.0.0.0:1080:socks") {
		t.Fatalf("SOCKS5 也要带绑定地址: %q", deploy)
	}

	fwd := &db.IntranetTunnel{ID: 24, Kind: db.IntranetTunnelKindPort, ListenHost: "0.0.0.0", ListenPort: 8473, RemoteHost: "10.0.0.8", RemotePort: 80}
	deploy, _, _ = autoSelectTunnelCommand(fwd.Kind, sshOnly, fwd)
	if !strings.Contains(deploy, "-R 0.0.0.0:8473:10.0.0.8:80") {
		t.Fatalf("ssh -R 不带绑定地址时控制端只听回环，必须显式写出: %q", deploy)
	}

	// 登记了具体监听地址时照它绑，不放宽。
	bindFwd := &db.IntranetTunnel{ID: 25, Kind: db.IntranetTunnelKindPort, ListenHost: "172.17.0.1", ListenPort: 8474, RemoteHost: "10.0.0.8", RemotePort: 80}
	deploy, _, _ = autoSelectTunnelCommand(bindFwd.Kind, sshOnly, bindFwd)
	if !strings.Contains(deploy, "-R 172.17.0.1:8474:10.0.0.8:80") {
		t.Fatalf("ssh -R 要按登记的监听地址绑: %q", deploy)
	}
}

// ssh -R 拨的是控制端那个目标可连入的 sshd，用户名默认取目标侧登录名——两边不同名时
// BatchMode 直接认证失败。JINGWEI_PIVOT_SSH_USER 用来钉住它，非法值必须拒绝而不是下发。
func TestAutoSelectTunnelPivotSSHUser(t *testing.T) {
	t.Setenv("JINGWEI_PIVOT_SERVER", "10.0.0.5:8788")
	t.Setenv("JINGWEI_PIVOT_SSH_PORT", "2222")
	sshOnly := intranetProbeInfo{Bins: []string{"ssh"}}
	tun := &db.IntranetTunnel{ID: 31, Kind: db.IntranetTunnelKindSocks5, ListenPort: 1080}

	t.Setenv("JINGWEI_PIVOT_SSH_USER", "")
	deploy, _, _ := autoSelectTunnelCommand(db.IntranetTunnelKindSocks5, sshOnly, tun)
	if !strings.Contains(deploy, "'10.0.0.5'") || strings.Contains(deploy, "@10.0.0.5") {
		t.Fatalf("未配用户名时只给地址，由 ssh 用目标侧登录名: %q", deploy)
	}

	t.Setenv("JINGWEI_PIVOT_SSH_USER", "  pivot ")
	deploy, reason, _ := autoSelectTunnelCommand(db.IntranetTunnelKindSocks5, sshOnly, tun)
	if !strings.Contains(deploy, "'pivot@10.0.0.5'") {
		t.Fatalf("配了用户名要拼进 ssh 目的地址: %q", deploy)
	}
	if strings.Contains(reason, "JINGWEI_PIVOT_SSH_USER 不是合法用户名") {
		t.Fatalf("合法用户名不该被拒: %q", reason)
	}

	for _, bad := range []string{"a b", "pivot;touch /tmp/pwn", "$(id)", "root@x", "piv/ot"} {
		t.Setenv("JINGWEI_PIVOT_SSH_USER", bad)
		deploy, reason, _ := autoSelectTunnelCommand(db.IntranetTunnelKindSocks5, sshOnly, tun)
		if deploy != "" {
			t.Fatalf("用户名 %q 非法却生成了命令: %q", bad, deploy)
		}
		if !strings.Contains(reason, "JINGWEI_PIVOT_SSH_USER") {
			t.Fatalf("拒绝理由要点名变量: %q", reason)
		}
	}

	// IPv6 控制端地址要带方括号，否则 ssh 把冒号当 user:host 分隔。
	t.Setenv("JINGWEI_PIVOT_SSH_USER", "pivot")
	t.Setenv("JINGWEI_PIVOT_SERVER", "[fd00::5]:8788")
	deploy, _, _ = autoSelectTunnelCommand(db.IntranetTunnelKindSocks5, sshOnly, tun)
	if !strings.Contains(deploy, "'pivot@[fd00::5]'") {
		t.Fatalf("IPv6 控制端地址要引用并加括号: %q", deploy)
	}
}
