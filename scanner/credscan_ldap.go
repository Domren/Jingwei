package scanner

import (
	"context"
	"fmt"
)

// LDAP / LDAPS：一次简单的 bind 请求就是一次凭据判定。
//
// 只实现 BER 的最小子集（长度 + 整数 + 八位串 + 构造类型）：bind 报文是固定的形状，
// 为它引一个 ASN.1 库不值得——而且库会把「服务端到底回了什么结果码」藏进 error 里，
// 而报告要的正是那个码（0 成功 / 49 凭据错 / 8 要求 TLS）。
type ldapCredAdapter struct {
	tls bool
}

func (a ldapCredAdapter) Protocol() string {
	if a.tls {
		return "ldaps"
	}
	return "ldap"
}

func (a ldapCredAdapter) connect(ctx context.Context, ep CredEndpoint) (*credWire, error) {
	w, err := credDial(ctx, credAddr(ep))
	if err != nil {
		return nil, err
	}
	if a.tls {
		// 目录服务的证书几乎都是自签；跳过校验，凭据是否可用的结论只来自 bind 结果码。
		if err := w.upgradeTLS(ctx, ep.Host); err != nil {
			w.close()
			return nil, err
		}
	}
	return w, nil
}

func (a ldapCredAdapter) Identify(ctx context.Context, ep CredEndpoint) (bool, string, error) {
	w, err := a.connect(ctx, ep)
	if err != nil {
		return false, "", err
	}
	defer w.close()
	// 匿名 bind：能回 BindResponse 就说明这是一个 LDAP 服务。
	if err := w.write(ldapBindRequest("", "")); err != nil {
		return false, "", err
	}
	raw, err := ldapReadResponse(w)
	if err != nil && len(raw) == 0 {
		return false, "", err
	}
	code, diag, ok := ldapParseBindResponse(raw)
	if !ok {
		return false, "", fmt.Errorf("响应不是 LDAP BindResponse")
	}
	return true, fmt.Sprintf("LDAP BindResponse resultCode=%d %s", code, diag), nil
}

func (a ldapCredAdapter) Try(ctx context.Context, ep CredEndpoint, cred Credential) (res CredAttempt, err error) {
	res = credNewAttempt(cred)
	w, err := a.connect(ctx, ep)
	if err != nil {
		return res.withErr(err)
	}
	defer w.close()
	defer func() { res.syncWire(w) }()

	if err := w.write(ldapBindRequest(cred.Username, cred.Password)); err != nil {
		return res.withErr(err)
	}
	raw, err := ldapReadResponse(w)
	if err != nil && len(raw) == 0 {
		return res.withErr(err)
	}
	code, diag, ok := ldapParseBindResponse(raw)
	if !ok {
		res.Outcome = CredInconclusive
		res.Reason = "响应不是 LDAP BindResponse"
		return res, nil
	}
	res.Banner = fmt.Sprintf("LDAP BindResponse resultCode=%d %s", code, diag)
	switch code {
	case 0:
		if cred.Username == "" && cred.Password == "" {
			res.Outcome = CredHit
			res.Reason = "服务器允许匿名绑定（未启用认证）"
		} else {
			res.Outcome = CredHit
		}
	case 49:
		res.Outcome = CredDeny
		res.Reason = "invalidCredentials：" + diag
	case 8, 13, 48:
		// strongAuthRequired / confidentialityRequired / inappropriateAuthentication：
		// 服务器要求先建立 TLS 或更强的认证，这不代表口令错了。
		res.Outcome = CredInconclusive
		res.Reason = fmt.Sprintf("服务器拒绝明文 bind（resultCode=%d %s），需 TLS 或更强认证", code, diag)
	default:
		res.Outcome = CredInconclusive
		res.Reason = fmt.Sprintf("bind 返回 resultCode=%d %s", code, diag)
	}
	return res, nil
}

// ── BER 最小组件 ──────────────────────────────────────────────────────────────

func berLength(n int) []byte {
	if n < 0x80 {
		return []byte{byte(n)}
	}
	var tmp []byte
	for n > 0 {
		tmp = append([]byte{byte(n & 0xff)}, tmp...)
		n >>= 8
	}
	return append([]byte{0x80 | byte(len(tmp))}, tmp...)
}

func berTLV(tag byte, content []byte) []byte {
	out := []byte{tag}
	out = append(out, berLength(len(content))...)
	return append(out, content...)
}

func berInt(v int) []byte {
	if v == 0 {
		return berTLV(0x02, []byte{0})
	}
	var tmp []byte
	for v > 0 {
		tmp = append([]byte{byte(v & 0xff)}, tmp...)
		v >>= 8
	}
	if tmp[0]&0x80 != 0 {
		tmp = append([]byte{0}, tmp...)
	}
	return berTLV(0x02, tmp)
}

func berOctet(s string) []byte { return berTLV(0x04, []byte(s)) }

// ldapBindRequest 构造版本 3、简单认证的 BindRequest。
func ldapBindRequest(user, pass string) []byte {
	auth := berTLV(0x80, []byte(pass)) // [0] simple, primitive
	bind := berTLV(0x60, concatBytes(berInt(3), berOctet(user), auth))
	msg := berTLV(0x30, concatBytes(berInt(1), bind))
	return msg
}

func concatBytes(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// berReadTLV 从 b[off:] 读一个 TLV，返回 tag、内容与下一个偏移；数据不完整时 ok=false。
func berReadTLV(b []byte, off int) (tag byte, value []byte, next int, ok bool) {
	if off+2 > len(b) {
		return 0, nil, 0, false
	}
	tag = b[off]
	l := int(b[off+1])
	off += 2
	if l&0x80 != 0 {
		n := l & 0x7f
		if n == 0 || n > 3 || off+n > len(b) {
			return 0, nil, 0, false
		}
		l = 0
		for i := 0; i < n; i++ {
			l = l<<8 | int(b[off])
			off++
		}
	}
	if off+l > len(b) {
		return 0, nil, 0, false
	}
	return tag, b[off : off+l], off + l, true
}

// ldapParseBindResponse 从报文里取 BindResponse 的 resultCode 与诊断信息。
func ldapParseBindResponse(b []byte) (int, string, bool) {
	_, msg, _, ok := berReadTLV(b, 0) // LDAPMessage SEQUENCE
	if !ok {
		return 0, "", false
	}
	off := 0
	_, _, next, ok := berReadTLV(msg, off) // messageID
	if !ok {
		return 0, "", false
	}
	off = next
	tag, op, _, ok := berReadTLV(msg, off)
	if !ok || tag != 0x61 {
		return 0, "", false
	}
	codeTag, codeVal, next2, ok := berReadTLV(op, 0)
	if !ok || codeTag != 0x0a || len(codeVal) == 0 {
		return 0, "", false
	}
	code := 0
	for _, v := range codeVal {
		code = code<<8 | int(v)
	}
	// resultCode 之后依次是 matchedDN 与 diagnosticMessage，两者都是 OCTET STRING；
	// 跳过 matchedDN 再取诊断信息，否则报告里写的是「匹配到的 DN」而不是失败原因。
	diag := ""
	if t, _, next3, ok := berReadTLV(op, next2); ok && t == 0x04 {
		if t2, v2, _, ok2 := berReadTLV(op, next3); ok2 && t2 == 0x04 {
			diag = string(v2)
		}
	}
	return code, diag, true
}

// ldapReadResponse 先读 BER 头拿到总长度，再按长度读满——LDAP 应答没有固定长度，
// 盲读 64 字节会在短应答上一直等到超时。
func ldapReadResponse(w *credWire) ([]byte, error) {
	head, err := w.readN(2)
	if err != nil {
		return head, err
	}
	length := int(head[1])
	if head[1]&0x80 != 0 {
		n := int(head[1] & 0x7f)
		if n == 0 || n > 3 {
			return head, fmt.Errorf("非法 BER 长度")
		}
		extra, err := w.readN(n)
		head = append(head, extra...)
		if err != nil {
			return head, err
		}
		length = 0
		for _, b := range extra {
			length = length<<8 | int(b)
		}
	}
	body, err := w.readN(length)
	return append(head, body...), err
}

func init() {
	RegisterCredAdapter(ldapCredAdapter{})
	RegisterCredAdapter(ldapCredAdapter{tls: true})
}
