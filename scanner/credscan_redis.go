package scanner

import (
	"context"
	"strconv"
	"strings"
)

// Redis 认证探针。AUTH 用 RESP 的 bulk string 发送：行式命令下口令里的 \r\n 与空格会
// 变成第二条命令，字典里混进这种字节不是假设，是导入词典时真出现过的情况。
type redisCredAdapter struct{}

func (redisCredAdapter) Protocol() string { return "redis" }

// Identify 主动发 PING——Redis 连上后不给 banner，不问就没有任何协议证据。
// 这一句不含用户数据，因此不算凭据尝试。
func (a redisCredAdapter) Identify(ctx context.Context, ep CredEndpoint) (bool, string, error) {
	addr := credAddr(ep)
	w, err := credDial(ctx, addr)
	if err != nil {
		return false, "", err
	}
	defer w.close()
	if err := w.write([]byte("PING\r\n")); err != nil {
		return false, "", err
	}
	raw, err := w.read()
	if err != nil {
		return false, "", err
	}
	if len(raw) == 0 || !strings.ContainsRune("+-:$*", rune(raw[0])) {
		return false, credPreview(raw), nil
	}
	// +PONG 与 -NOAUTH 都算确认：后者说明服务在听、只是要求认证，那正是待测状态。
	return true, credPreview(raw), nil
}

func (a redisCredAdapter) Try(ctx context.Context, ep CredEndpoint, cred Credential) (res CredAttempt, err error) {
	addr := credAddr(ep)
	res = credNewAttempt(cred)
	w, err := credDial(ctx, addr)
	if err != nil {
		return res.withErr(err)
	}
	defer w.close()
	// 字节快照放在 defer 里：中途任何一条 write/read 失败，已经发出去的那半截也要留证——
	// 「发了一半被断开」本身就是报告里要写清的事实。
	defer func() { res.syncWire(w) }()

	// Redis 6 之后的 ACL 用户要带用户名；用户名留空时按 requirepass 的老形式发。
	auth := respBulkArray("AUTH", cred.Username, cred.Password)
	if strings.TrimSpace(cred.Username) == "" {
		auth = respBulkArray("AUTH", cred.Password)
	}
	if err = w.write(auth); err != nil {
		return res.withErr(err)
	}
	raw, err := w.read()
	if err != nil {
		return res.withErr(err)
	}
	res.Banner = credPreview(raw)

	switch {
	case respOK(raw):
		// AUTH +OK 只说明认证通过，还要 PING 拿到 +PONG 才证明这是个可用会话。
		// 少了这一步，「协议回了个 OK 但不是能用」的假命中会直接进报告。
		if err = w.write([]byte("PING\r\n")); err != nil {
			return res.withErr(err)
		}
		p, perr := w.read()
		if perr != nil {
			return res.withErr(perr)
		}
		if respOK(p) || strings.HasPrefix(string(p), "+PONG") {
			res.Outcome = CredHit
			res.Banner = credPreview(append(append([]byte{}, raw...), p...))
			return res, nil
		}
		res.Outcome = CredInconclusive
		res.Reason = "AUTH 成功但 PING 没确认会话：" + credPreview(p)
		return res, nil
	case respErr(raw):
		msg := strings.ToLower(string(raw))
		switch {
		case strings.Contains(msg, "no password is set"),
			strings.Contains(msg, "without any password configured"):
			// 服务端根本没开认证：空口令就是可用凭据；非空口令不算命中——
			// 让访问成立的是「没有凭据」，不是这组口令。
			if strings.TrimSpace(cred.Password) == "" && strings.TrimSpace(cred.Username) == "" {
				res.Outcome = CredHit
				res.Reason = "目标未启用认证（requirepass 为空），空口令即可访问"
				return res, nil
			}
			res.Outcome = CredDeny
			res.Reason = "目标未启用认证，非空口令不构成可用凭据"
			return res, nil
		case credLockedText(msg):
			res.Outcome = CredLocked
			res.Reason = "目标提示账号锁定或临时封禁，已停手"
			return res, nil
		case strings.Contains(msg, "denied redis is running in protected mode"):
			// 保护模式拒绝的是客户端来源，不是这组口令；写成拒绝会让人以为换口令能过。
			res.Outcome = CredInconclusive
			res.Reason = "目标启用保护模式，拒绝非本机客户端（与凭据无关）"
			return res, nil
		case strings.Contains(msg, "wrongpass"), strings.Contains(msg, "invalid password"),
			strings.Contains(msg, "invalid username-password"):
			// Redis 6 起 ACL 默认用户也存在「用户被禁用」这种形态，措辞里带 user is disabled。
			res.Outcome = CredDeny
			return res, nil
		default:
			res.Outcome = CredDeny
			res.Reason = "服务端拒绝该凭据：" + credPreview(raw)
			return res, nil
		}
	default:
		res.Outcome = CredInconclusive
		res.Reason = "认证回复不是 RESP 的 + 或 - 类型：" + credPreview(raw)
		return res, nil
	}
}

func init() { RegisterCredAdapter(redisCredAdapter{}) }

// respBulkArray 编码 `*N\r\n$len\r\n<arg>\r\n`。长度按字节算，所以二进制字节与 CRLF 都安全。
func respBulkArray(cmd string, args ...string) []byte {
	out := []byte("*" + strconv.Itoa(len(args)+1) + "\r\n")
	out = append(out, respBulk(cmd)...)
	for _, a := range args {
		out = append(out, respBulk(a)...)
	}
	return out
}

func respBulk(s string) []byte {
	return []byte("$" + strconv.Itoa(len(s)) + "\r\n" + s + "\r\n")
}

func respOK(raw []byte) bool  { return len(raw) > 0 && raw[0] == '+' }
func respErr(raw []byte) bool { return len(raw) > 0 && raw[0] == '-' }

// credLockedText 认「锁定/封禁」而不是「口令错」的措辞。判错方向的代价不对称：
// 把锁定读成拒绝会继续打字典直到把账号锁死，把拒绝读成锁定会漏掉真正可用的口令。
// 因此只认明确点名锁定或限流的词，不做模糊匹配。
func credLockedText(msg string) bool {
	for _, p := range []string{
		"temporarily blocked", "blocked because of many connection errors",
		"too many login failures", "too many failed", "account locked",
		"locked due to", "user is locked",
	} {
		if strings.Contains(msg, p) {
			return true
		}
	}
	return false
}
