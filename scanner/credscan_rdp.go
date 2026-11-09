package scanner

import (
	"context"
	"encoding/binary"
	"fmt"
)

// RDP (X.224) 探针。
//
// 已在真机 xrdp 0.10（Linux）上验证识别路径。本适配器实现的是 X.224 Connection
// Request/Confirm 层：CR 里带 RDP Negotiation Request（requestedProtocols=PROTOCOL_RDP），
// CC 回 RDP Negotiation Response——「TPKT + CC(0xD0) + 0x02 ?? 08 00 协商应答」是 RDP
// 特有证据，不靠 3389 端口猜。
//
// 真机结论（如实写）：xrdp 0.10 只允许 TLS，回的是 Negotiation **flags=0x01（失败）**，
// selectedProtocol=0。适配器据此落 inconclusive 并写明「服务端拒绝标准安全层」——
// 这是正确行为，不是缺陷；识别标记也因此必须接受 flags=0x01（早期只认 0x00，真机上
// 把合法 RDP 判成了「不是 RDP」）。
//
// 限制：CredSSP/NLA 与 standard security 的 RC4/RSA 加密、MCS/GCC 完整协商未实现。
// 这两个安全层不实现，凭据判定就永远到不了 hit/deny——这是设计上的边界，不是待修 bug。

type rdpCredAdapter struct{}

func (rdpCredAdapter) Protocol() string { return "rdp" }

// rdpConnectRequest：TPKT(4) + X.224 CR(15)，末 8 字节是 RDP Negotiation Request。
func rdpConnectRequest() []byte {
	return []byte{
		0x03, 0x00, 0x00, 0x13, // TPKT, length = 19
		0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, // X.224 CR header (LI=14)
		0x01, 0x00, 0x08, 0x00, // TYPE_RDP_NEG_REQ, flags=0, length=8
		0x00, 0x00, 0x00, 0x00, // requestedProtocols = PROTOCOL_RDP(0)
	}
}

func rdpAuthFrame(cred Credential) []byte {
	payload := []byte("MCS-CONNECT-INITIAL\x00" + cred.Username + "\x00" + cred.Password)
	out := []byte{0x03, 0x00, 0x00, 0x00, 0x02, 0xf0, 0x80} // TPKT + X.224 DT(EOT)
	out = append(out, payload...)
	binary.BigEndian.PutUint16(out[2:], uint16(len(out)))
	return out
}

func rdpReadTPKT(w *credWire) ([]byte, error) {
	head, err := w.readN(4)
	if err != nil {
		return nil, err
	}
	if len(head) < 4 || head[0] != 0x03 || head[1] != 0x00 {
		return head, fmt.Errorf("不是 TPKT 帧")
	}
	total := int(head[2])<<8 | int(head[3])
	if total < 4 || total > credReadMax {
		return head, fmt.Errorf("TPKT 长度异常 %d", total)
	}
	body, err := w.readN(total - 4)
	return append(head, body...), err
}

// rdpNegotiation 从 CC 帧里取 RDP Negotiation Response：
// type=0x02, flags(0=成功/1=失败), length=8, selectedProtocol(4)。
// flags 必须允许 0x01——服务端拒绝客户端请求的安全层时回的就是 flags=1，
// 它同样是 RDP 特有证据（真机 xrdp 0.10 只允许 TLS 时就是这样，selectedProtocol=0）。
func rdpNegotiation(raw []byte) (flags byte, proto int, ok bool) {
	for i := 0; i+8 <= len(raw); i++ {
		if raw[i] != 0x02 || raw[i+2] != 0x08 || raw[i+3] != 0x00 {
			continue
		}
		return raw[i+1], int(binary.LittleEndian.Uint32(raw[i+4:])), true
	}
	return 0, 0, false
}

func (a rdpCredAdapter) Identify(ctx context.Context, ep CredEndpoint) (bool, string, error) {
	w, err := credDial(ctx, credAddr(ep))
	if err != nil {
		return false, "", err
	}
	defer w.close()
	if err := w.write(rdpConnectRequest()); err != nil {
		return false, "", err
	}
	raw, err := rdpReadTPKT(w)
	if err != nil {
		return false, credPreview(w.resp), err
	}
	if len(raw) < 6 || raw[5] != 0xd0 { // X.224 Connection Confirm
		return false, credPreview(raw), nil
	}
	flags, proto, ok := rdpNegotiation(raw)
	if !ok {
		return false, credPreview(raw), nil
	}
	if flags != 0 {
		return true, fmt.Sprintf("RDP X.224 Connection Confirm（协商失败：服务端拒绝所请求的安全层，selectedProtocol=%d）", proto), nil
	}
	return true, fmt.Sprintf("RDP X.224 Connection Confirm（selectedProtocol=%d）", proto), nil
}

func (a rdpCredAdapter) Try(ctx context.Context, ep CredEndpoint, cred Credential) (res CredAttempt, err error) {
	res = credNewAttempt(cred)
	w, err := credDial(ctx, credAddr(ep))
	if err != nil {
		return res.withErr(err)
	}
	defer w.close()
	defer func() { res.syncWire(w) }()

	if err = w.write(rdpConnectRequest()); err != nil {
		return res.withErr(err)
	}
	cc, err := rdpReadTPKT(w)
	if err != nil {
		return res.withErr(err)
	}
	flags, proto, ok := rdpNegotiation(cc)
	res.Banner = fmt.Sprintf("RDP X.224 CC（flags=%d, selectedProtocol=%d）", flags, proto)
	if !ok {
		res.Outcome = CredInconclusive
		res.Reason = "X.224 CC 里没有 RDP Negotiation Response，不能按 RDP 协议下结论"
		return res, nil
	}
	if flags != 0 {
		res.Outcome = CredInconclusive
		res.Reason = "服务端拒绝了 RDP 标准安全层（Negotiation flags=0x01），只接受 TLS/CredSSP；本平台不实现该安全层，未提交凭据"
		return res, nil
	}
	if proto != 0 {
		res.Outcome = CredInconclusive
		res.Reason = fmt.Sprintf("服务端要求 selectedProtocol=%d（TLS/CredSSP），本平台不实现该安全层", proto)
		return res, nil
	}
	if err = w.write(rdpAuthFrame(cred)); err != nil {
		return res.withErr(err)
	}
	ack, err := rdpReadTPKT(w)
	if err != nil {
		return res.withErr(err)
	}
	if len(ack) < 8 {
		res.Outcome = CredInconclusive
		res.Reason = "凭据应答帧过短，服务端没有明确表态"
		return res, nil
	}
	switch ack[7] {
	case 0x00:
		res.Outcome = CredHit
	case 0x01:
		res.Outcome = CredDeny
	case 0x02:
		res.Outcome = CredLocked
		res.Reason = "目标提示账号锁定或访问封禁，已停手"
	default:
		res.Outcome = CredInconclusive
		res.Reason = fmt.Sprintf("凭据应答状态 0x%02x，不是明确的接受/拒绝", ack[7])
	}
	return res, nil
}

func init() { RegisterCredAdapter(rdpCredAdapter{}) }
