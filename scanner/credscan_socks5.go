package scanner

import (
	"context"
	"strings"
)

// SOCKS5 认证探针（RFC 1929 的用户名/口令子协商）。
type socks5CredAdapter struct{}

func (socks5CredAdapter) Protocol() string { return "socks5" }

const (
	socksVersion5     = 0x05
	socksMethodNone   = 0x00
	socksMethodGSSAPI = 0x01
	socksMethodUser   = 0x02
	socksMethodNoAuth = 0xFF
)

// socksGreeting 同时提供「无认证」与「用户名/口令」。只提供一种是错的：
// 只支持无认证的代理会被选不出来，然后被判成「不是 SOCKS5」。
var socksGreeting = []byte{socksVersion5, 0x02, socksMethodNone, socksMethodUser}

// Identify 只看版本回音：以 0x05 开头就是会说 SOCKS5 的服务。
// 支持哪种方法在 Try 里按选择结果处理。
func (a socks5CredAdapter) Identify(ctx context.Context, ep CredEndpoint) (bool, string, error) {
	addr := credAddr(ep)
	w, err := credDial(ctx, addr)
	if err != nil {
		return false, "", err
	}
	defer w.close()
	if err := w.write(socksGreeting); err != nil {
		return false, "", err
	}
	raw, err := w.readN(2)
	if err != nil {
		return false, credPreview(raw), err
	}
	if len(raw) < 2 || raw[0] != socksVersion5 {
		return false, credPreview(raw), nil
	}
	return true, socksMethodNote(raw[1]), nil
}

func (a socks5CredAdapter) Try(ctx context.Context, ep CredEndpoint, cred Credential) (res CredAttempt, err error) {
	addr := credAddr(ep)
	res = credNewAttempt(cred)
	w, err := credDial(ctx, addr)
	if err != nil {
		return res.withErr(err)
	}
	defer w.close()
	defer func() { res.syncWire(w) }()

	if err = w.write(socksGreeting); err != nil {
		return res.withErr(err)
	}
	greet, err := w.readN(2)
	if err != nil {
		return res.withErr(err)
	}
	if len(greet) < 2 || greet[0] != socksVersion5 {
		res.Outcome = CredInconclusive
		res.Reason = "对端未按 SOCKS5 回应方法选择"
		return res, nil
	}
	res.Banner = socksMethodNote(greet[1])
	switch greet[1] {
	case socksMethodUser:
		// 继续走 RFC 1929 子协商。
	case socksMethodNone:
		// 代理不要求任何凭据：空凭据是可用凭据；非空凭据不算命中——
		// 让访问成立的是「没有认证」，不是这组口令。
		if strings.TrimSpace(cred.Username) == "" && strings.TrimSpace(cred.Password) == "" {
			res.Outcome = CredHit
			res.Reason = "该 SOCKS5 代理不要求认证，空凭据即可使用"
			return res, nil
		}
		res.Outcome = CredDeny
		res.Reason = "该代理不要求认证，非空凭据不构成可用口令对"
		return res, nil
	case socksMethodNoAuth:
		res.Outcome = CredUnsupported
		res.Reason = "服务端既不要用户名/口令也不接受无认证，本平台不实现其提供的方法"
		return res, nil
	case socksMethodGSSAPI:
		res.Outcome = CredUnsupported
		res.Reason = "服务端要求 GSSAPI 认证，本平台不实现"
		return res, nil
	default:
		res.Outcome = CredUnsupported
		res.Reason = "服务端选择了未知认证方法 0x" + socksHex(greet[1])
		return res, nil
	}

	if strings.ContainsRune(cred.Username, 0) || strings.ContainsRune(cred.Password, 0) {
		res.Outcome = CredInconclusive
		res.Reason = "凭据含 NUL 字节，无法按 RFC 1929 的长度字段无歧义编码，未发送"
		return res, nil
	}
	if err = w.write(socksAuthRequest(cred.Username, cred.Password)); err != nil {
		return res.withErr(err)
	}
	reply, err := w.readN(2)
	if err != nil {
		// 子协商没走完就被断开不能算「这组口令被拒绝」：直接关连接同样出现在版本不对、
		// 访问控制拦截、服务异常时。只有服务端明确说了失败，才有资格写 deny。
		res.Outcome = CredInconclusive
		res.Reason = "对端在认证子协商未完成时断开；服务端没有明确拒绝，不能记成口令错误"
		return res, nil
	}
	switch {
	case len(reply) >= 2 && reply[0] == 0x01 && reply[1] == 0x00:
		res.Outcome = CredHit
	case len(reply) >= 2 && reply[0] == 0x01 && reply[1] == 0xFF:
		res.Outcome = CredDeny
	case len(reply) >= 2 && reply[0] == 0x01:
		// dante 对失败的答复是 0x01 而不是 RFC 1929 的 0xFF。服务端已经对这次认证
		// 表了态、且不是成功，就该记拒绝；记成不可判定会让人反复重试同一组口令。
		res.Outcome = CredDeny
		res.Reason = "服务端答复认证失败（状态 0x" + socksHex(reply[1]) + "）"
	default:
		res.Outcome = CredInconclusive
		res.Reason = "认证回复不是 RFC 1929 的子协商格式"
	}
	return res, nil
}

// socksAuthRequest 编码 0x01 <ulen> <user> <plen> <pass>。长度按字节算，
// 所以口令里的 CRLF 不会改变字段边界。
func socksAuthRequest(user, pass string) []byte {
	out := []byte{0x01, byte(len(user))}
	out = append(out, user...)
	out = append(out, byte(len(pass)))
	return append(out, pass...)
}

func socksHex(b byte) string {
	const digits = "0123456789abcdef"
	return string([]byte{digits[b>>4], digits[b&0x0f]})
}

func socksMethodNote(method byte) string {
	if method == socksMethodUser {
		return "SOCKS5 · 认证方法 username/password (RFC 1929)"
	}
	return "SOCKS5 · 认证方法 0x" + socksHex(method)
}

func init() { RegisterCredAdapter(socks5CredAdapter{}) }
