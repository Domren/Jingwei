package scanner

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// SSH 命令通道：内网里大量主机只有 22 端口，没有 web 服务，永远落不下 webshell。
// 复用弱口令直接登录才能把它们纳入受管会话，执行、信息收集、维持与撤离台账才
// 走得通。输出仍然走平台统一的 cwd/退出码标记协议（见 server 侧 intranetScript），
// 这里只负责把一段 shell 脚本送到目标上并把合并后的回显取回来。

const (
	sshDefaultTimeout = 15 * time.Second
	sshMaxOutput      = 4 << 20
)

// SSHCommandTarget describes one SSH-backed command execution.
type SSHCommandTarget struct {
	Addr     string
	User     string
	Password string
	Timeout  time.Duration
}

// SSHProbeTarget is the address+port shape used before a session is created, so
// an operator can test a credential without opening a ledger row.
func SSHAddr(host string, port int) string {
	if port <= 0 {
		port = 22
	}
	return net.JoinHostPort(strings.Trim(strings.TrimSpace(host), "[]"), fmt.Sprint(port))
}

func sshDialTimeout(t time.Duration) time.Duration {
	if t <= 0 {
		return sshDefaultTimeout
	}
	return t
}

// RunSSHCommand runs script on the target's login shell and returns its combined
// output. A non-zero exit status is not an error here: the exit code travels in
// the marker trailer the caller parses out of the output.
func RunSSHCommand(ctx context.Context, target SSHCommandTarget, script string) (string, error) {
	if strings.TrimSpace(target.Addr) == "" {
		return "", errors.New("SSH 地址为空")
	}
	if strings.TrimSpace(target.User) == "" {
		return "", errors.New("SSH 账号为空")
	}
	timeout := sshDialTimeout(target.Timeout)
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	dialer := &net.Dialer{Timeout: timeout}
	conn0, err := dialer.DialContext(cctx, "tcp", target.Addr)
	if err != nil {
		return "", sshDialError(err)
	}
	cfg := &ssh.ClientConfig{
		User: target.User,
		Auth: []ssh.AuthMethod{ssh.Password(target.Password)},
		// 渗透工具面对的是没有可信密钥链的目标机；已知主机指纹在这里既不可得，
		// 也不构成防线（同网段的中间人本来就在攻击面之内）。
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         timeout,
	}
	conn, chans, reqs, err := ssh.NewClientConn(conn0, target.Addr, cfg)
	if err != nil {
		_ = conn0.Close()
		return "", sshAuthError(err)
	}
	client := ssh.NewClient(conn, chans, reqs)

	type runResult struct {
		out string
		err error
	}
	done := make(chan runResult, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				done <- runResult{err: fmt.Errorf("SSH 执行异常: %v", r)}
			}
		}()
		session, serr := client.NewSession()
		if serr != nil {
			done <- runResult{err: serr}
			return
		}
		defer session.Close()
		out, rerr := session.CombinedOutput(script)
		if len(out) > sshMaxOutput {
			out = append(append([]byte{}, out[:sshMaxOutput]...),
				[]byte("\n...[输出超过 4MiB 已截断]")...)
		}
		// 命令本身返回非零不算通道故障：退出码写在标记里，由调用方判定。
		var exit *ssh.ExitError
		if rerr != nil && errors.As(rerr, &exit) {
			rerr = nil
		}
		done <- runResult{out: string(out), err: rerr}
	}()

	select {
	case res := <-done:
		_ = client.Close()
		if res.err != nil {
			return res.out, res.err
		}
		return res.out, nil
	case <-cctx.Done():
		// 关掉 client 会打断正在跑的 session，goroutine 随即退出。
		_ = client.Close()
		return "", cctx.Err()
	}
}

func sshDialError(err error) error {
	msg := strings.TrimSpace(err.Error())
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return fmt.Errorf("SSH 连接超时: %s", msg)
	case errors.Is(err, context.Canceled):
		return err
	case strings.Contains(msg, "connection refused"):
		return fmt.Errorf("SSH 端口拒绝连接: %s", msg)
	case strings.Contains(msg, "no such host"), strings.Contains(msg, "lookup "):
		return fmt.Errorf("SSH 目标无法解析（地址不可达或不在本机的网络视图内）: %s", msg)
	}
	return fmt.Errorf("SSH 连接失败: %s", msg)
}

func sshAuthError(err error) error {
	msg := strings.TrimSpace(err.Error())
	if strings.Contains(msg, "unable to authenticate") || strings.Contains(msg, "handshake failed") {
		return fmt.Errorf("SSH 认证失败（账号或口令无效）: %s", msg)
	}
	return fmt.Errorf("SSH 握手失败: %s", msg)
}
