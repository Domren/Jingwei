package scanner

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// SSH 认证探针。
//
// 这里刻意只做「认证」这一件事：认证成功后立刻关闭传输，不开 session、不执行命令。
// 本模块的边界是记下「这组凭据可用」这条事实，用不用它由人决定（见包注释）。
type sshCredAdapter struct{}

func (sshCredAdapter) Protocol() string { return "ssh" }

// Identify 读服务端的版本行就关连接——这是 KEX 之前唯一的明文，也是不发出任何
// 客户端字节就能拿到的协议证据（被动通道，走 banner 格式）。
func (a sshCredAdapter) Identify(ctx context.Context, ep CredEndpoint) (bool, string, error) {
	w, err := credDial(ctx, credAddr(ep))
	if err != nil {
		return false, "", err
	}
	defer w.close()
	line, err := w.readLine(512)
	if err != nil && len(line) == 0 {
		return false, "", err
	}
	text := strings.TrimSpace(string(line))
	return strings.HasPrefix(text, "SSH-"), text, nil
}

func (a sshCredAdapter) Try(ctx context.Context, ep CredEndpoint, cred Credential) (res CredAttempt, err error) {
	res = credNewAttempt(cred)
	addr := credAddr(ep)
	w, err := credDial(ctx, addr)
	if err != nil {
		return res.withErr(err)
	}
	defer w.close()
	defer func() { res.syncWire(w) }()

	// 先把服务端的版本行读走：x/crypto 不把它交给调用方，而「对面是 OpenSSH 9.6」
	// 恰好是这条结果里唯一能逐字节复现的部分。读完再接回流开头交给它，两边都不丢。
	line, err := w.readLine(512)
	if err != nil && len(line) == 0 {
		return res.withErr(err)
	}
	serverVersion := strings.TrimSpace(string(line))
	if serverVersion != "" && !strings.HasPrefix(serverVersion, "SSH-") {
		res.Outcome = CredInconclusive
		res.Reason = "端口有人应答，但首行不是 SSH 版本标识：" + credPreview(line)
		return res, nil
	}
	cfg := &ssh.ClientConfig{
		User:            cred.Username,
		Auth:            []ssh.AuthMethod{ssh.Password(cred.Password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         credHandshakeTimeout(ctx),
		// 只允许口令。把 publickey / keyboard-interactive 一起交给服务端挑选，一次尝试
		// 就变成多种机制的连发：锁定计数对不上，「这次到底试了什么」也说不清。
		// 而且密钥登录不属于「弱口令检测」这个问题域。
	}
	transport, chans, reqs, err := ssh.NewClientConn(&credPeek{Conn: w.conn, buf: line}, addr, cfg)
	if err != nil {
		return sshClassify(res, err, addr, cred, serverVersion), nil
	}
	client := ssh.NewClient(transport, chans, reqs)
	// 认证通过就断开：会话开起来已经是「使用凭据」，不是「验证凭据」。
	_ = client.Close()
	res.Outcome = CredHit
	res.Banner = serverVersion
	res.RawReq = append([]byte(nil), transport.ClientVersion()...)
	res.EvidenceText = sshEvidence(addr, serverVersion, string(transport.ClientVersion()), cred, res.Outcome, "")
	return res, nil
}

// credHandshakeTimeout 把上层预算换成 x/crypto 要的 Timeout——它不接 context。
// 下限一秒：预算只剩一丝时握手必然完不成，但「一秒后被掐」和「参数非法」是两回事。
func credHandshakeTimeout(ctx context.Context) time.Duration {
	remaining := credAttemptTimeout
	if dl, ok := ctx.Deadline(); ok {
		if left := time.Until(dl); left < remaining {
			remaining = left
		}
	}
	if remaining < time.Second {
		return time.Second
	}
	return remaining
}

// sshClassify 把 x/crypto 的握手错误分成三类。分错任何一类都会让报告说谎：
// 把「对端提前断开」写成 deny，等于宣称这组口令已被排除；把 deny 写成不可判定，
// 操作员会以为网络有问题而反复重试，直到把账号锁进 faillock。
func sshClassify(res CredAttempt, err error, addr string, cred Credential, serverVersion string) CredAttempt {
	msg := strings.TrimSpace(err.Error())
	lower := strings.ToLower(msg)
	res.Reason = msg
	switch {
	case strings.Contains(lower, "unable to authenticate"),
		strings.Contains(lower, "no supported methods remained"),
		strings.Contains(lower, "incorrect password"):
		res.Outcome = CredDeny
	case credLockedText(lower), strings.Contains(lower, "too many authentication failures"):
		// OpenSSH 的 MaxAuthTries 用断开表达「别再试了」；faillock 类模块会给明文文案。
		// 两种都必须让该端点停手。
		res.Outcome = CredLocked
		res.Reason = "对端提示认证次数已达上限或账号被锁，已停手：" + msg
	case strings.Contains(lower, "handshake failed"), strings.Contains(lower, "connection reset"),
		strings.Contains(lower, "eof"), strings.Contains(lower, "broken pipe"):
		res.Outcome = CredInconclusive
		res.Reason = "握手在完成前被对端中断（可能是 MaxStartups、访问控制或 fail2ban），" +
			"服务端没有对这组口令表态：" + msg
	default:
		res.Outcome, _ = credFailFromErr(err)
		if res.Outcome == CredUnreachable {
			res.Reason = msg
		}
	}
	res.EvidenceText = sshEvidence(addr, serverVersion, "", cred, res.Outcome, res.Reason)
	return res
}

// sshEvidence 是 SSH 专属的证据文本。KEX 之后流量全加密，通用的字节模板会生成一条
// 「重放这些字节」的命令——照做的人只会拿到一个版本 banner，而不是这里的结论。
// 所以这里给出真正能复现结论的做法：用同一组参数再认证一次。
func sshEvidence(addr, serverVersion, clientVersion string, cred Credential, outcome CredOutcome, reason string) string {
	var b strings.Builder
	b.WriteString("# 协议: SSH (TCP)\n")
	fmt.Fprintf(&b, "# 端点: %s\n", addr)
	if v := strings.TrimSpace(serverVersion); v != "" {
		fmt.Fprintf(&b, "# 服务端版本: %s\n", v)
	}
	if v := strings.TrimSpace(clientVersion); v != "" {
		fmt.Fprintf(&b, "# 本端版本: %s（版本行之后就是 KEX 加密通道）\n", v)
	}
	b.WriteString("# 采集方式: SSH 传输层认证结果。版本行之后的报文都在 KEX 加密通道内，" +
		"逐字节重放拿不到同样的结论，因此这里给的是等价复现命令\n")
	fmt.Fprintf(&b, "# 复现命令: ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no "+
		"-o StrictHostKeyChecking=no -o BatchMode=no -p %s %s@%s\n",
		sshPortOf(addr), cred.Username, sshHostOf(addr))
	fmt.Fprintf(&b, "# 结论: %s\n", credOutcomeCN(outcome))
	if r := strings.TrimSpace(reason); r != "" {
		fmt.Fprintf(&b, "# 判定说明: %s\n", r)
	}
	fmt.Fprintf(&b, "# 凭据: %s / %s\n", cred.Username, cred.Password)
	return strings.TrimRight(b.String(), "\n")
}

func sshHostOf(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}

func sshPortOf(addr string) string {
	_, port, err := net.SplitHostPort(addr)
	if err != nil || port == "" {
		return "22"
	}
	return port
}

func credOutcomeCN(o CredOutcome) string {
	switch o {
	case CredHit:
		return "凭据可用（认证被服务端接受）"
	case CredDeny:
		return "凭据被服务端明确拒绝"
	case CredUnreachable:
		return "连不上，谈不上认证"
	case CredLocked:
		return "触发锁定或认证次数上限，已停手"
	case CredUnsupported:
		return "本平台不实现该认证方式"
	default:
		return "不可判定"
	}
}

func init() { RegisterCredAdapter(sshCredAdapter{}) }
