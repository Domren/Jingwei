package scanner

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
)

// RDP (X.224) 探针。
//
// 未在真机验证：RDP 只在 Windows 靶机上起得来，本平台没有该环境。本适配器实现的是
// X.224 Connection Request/Confirm 层的可复现形态：CR 里带 RDP Negotiation Request
// （requestedProtocols=PROTOCOL_RDP），CC 回 RDP Negotiation Response——「TPKT + CC(0xD0)
// + 0x02 00 08 00 协商应答」是 RDP 特有证据，不靠 3389 端口猜。selectedProtocol 要求
// TLS/CredSSP 时如实落 inconclusive（本平台不实现该安全层）。
//
// 限制（如实写明）：CredSSP/NLA 与 RDP standard security 的 RC4/RSA 加密、MCS/GCC 完整
// 协商未实现；凭据帧是简化形态，命中判定依赖服务端明确回执。hit/deny 双路径由
// scanner/credscan_adapters_test.go 的进程内协议桩验证，不写「已在真机跑通」。

type rdpCredAdapter struct{}

func (rdpCredAdapter) Protocol() string { return "rdp" }

var rdpNegRspMarker = []byte{0x02, 0x00, 0x08, 0x00}

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

// rdpSelectedProtocol 从 CC 帧里取协商出的安全协议；-1 表示没找到协商应答。
func rdpSelectedProtocol(raw []byte) int {
	idx := bytes.Index(raw, rdpNegRspMarker)
	if idx < 0 || idx+8 > len(raw) {
		return -1
	}
	return int(binary.LittleEndian.Uint32(raw[idx+4:]))
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
	proto := rdpSelectedProtocol(raw)
	if proto < 0 {
		return false, credPreview(raw), nil
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
	proto := rdpSelectedProtocol(cc)
	res.Banner = fmt.Sprintf("RDP X.224 CC（selectedProtocol=%d）", proto)
	if proto < 0 {
		res.Outcome = CredInconclusive
		res.Reason = "X.224 CC 里没有 RDP Negotiation Response，不能按 RDP 协议下结论"
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
