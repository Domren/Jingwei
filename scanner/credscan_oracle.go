package scanner

import (
	"context"
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// Oracle Net / TNS 探针。
//
// 实现到 TNS 帧层：Connect(1) 拿 Accept(2)/Resend(11)/Redirect(5)，再发一次认证请求，
// 按服务端回执判定。TNS 包头 8 字节（2B 长度 + 2B 校验 + 1B type + 1B 保留 + 2B 头校验）
// 与「长度自洽」合起来是协议特有证据，不靠 1521 端口猜。
//
// 限制（如实写明）：Oracle 的 O3LOGON（DES/AUTH_SESSKEY）与 12c 的 PBKDF2 认证交换
// 未实现，认证请求里放的是按口令派生的摘要而非真实 O3LOGON 报文。真机部署前需按
// Oracle Net 规范补齐认证交换。本轮未在真机验证，hit/deny 双路径由进程内协议桩覆盖。

type oracleCredAdapter struct{}

func (oracleCredAdapter) Protocol() string { return "oracle" }

func tnsPacket(typ byte, payload []byte) []byte {
	total := 8 + len(payload)
	out := make([]byte, 8)
	out[0], out[1] = byte(total>>8), byte(total)
	out[4] = typ
	return append(out, payload...)
}

func tnsRead(w *credWire) (byte, []byte, error) {
	head, err := w.readN(8)
	if err != nil {
		return 0, nil, err
	}
	total := int(head[0])<<8 | int(head[1])
	if total < 8 || total > credReadMax {
		return 0, head, fmt.Errorf("TNS 包长度异常 %d", total)
	}
	body, err := w.readN(total - 8)
	return head[4], body, err
}

func tnsConnect(ep CredEndpoint) []byte {
	desc := "(DESCRIPTION=(CONNECT_DATA=(SERVICE_NAME=" +
		CredParam(ep, "service_name", "orcl") +
		")(CID=(PROGRAM=Jingwei-CredScan)(HOST=jw)(USER=scanner))))"
	hdr := make([]byte, 30)
	binary.BigEndian.PutUint16(hdr[0:], 0x0138) // version
	binary.BigEndian.PutUint16(hdr[2:], 0x012c) // compat
	binary.BigEndian.PutUint16(hdr[8:], 2048)   // SDU
	binary.BigEndian.PutUint16(hdr[10:], 2048)  // TDU
	binary.BigEndian.PutUint16(hdr[16:], 1)
	binary.BigEndian.PutUint16(hdr[18:], uint16(len(desc)))
	binary.BigEndian.PutUint16(hdr[20:], 30) // offset to connect data
	binary.BigEndian.PutUint32(hdr[22:], 2048)
	return append(hdr, []byte(desc)...)
}

func oraclePassDigest(pass string) string {
	sum := md5.Sum([]byte(pass))
	return hex.EncodeToString(sum[:])
}

func (a oracleCredAdapter) Identify(ctx context.Context, ep CredEndpoint) (bool, string, error) {
	w, err := credDial(ctx, credAddr(ep))
	if err != nil {
		return false, "", err
	}
	defer w.close()
	if err := w.write(tnsPacket(1, tnsConnect(ep))); err != nil {
		return false, "", err
	}
	typ, _, err := tnsRead(w)
	if err != nil {
		return false, credPreview(w.resp), err
	}
	// 只有 TNS 的 connect 类应答才算确认：2 Accept / 4 Refuse / 5 Redirect / 11 Resend。
	switch typ {
	case 2, 4, 5, 11:
		return true, fmt.Sprintf("Oracle TNS 连接应答 type=%d", typ), nil
	default:
		return false, credPreview(w.resp), nil
	}
}

func (a oracleCredAdapter) Try(ctx context.Context, ep CredEndpoint, cred Credential) (res CredAttempt, err error) {
	res = credNewAttempt(cred)
	w, err := credDial(ctx, credAddr(ep))
	if err != nil {
		return res.withErr(err)
	}
	defer w.close()
	defer func() { res.syncWire(w) }()

	if err = w.write(tnsPacket(1, tnsConnect(ep))); err != nil {
		return res.withErr(err)
	}
	typ, _, err := tnsRead(w)
	if err != nil {
		return res.withErr(err)
	}
	if typ != 2 && typ != 5 && typ != 11 {
		res.Outcome = CredInconclusive
		res.Reason = fmt.Sprintf("TNS 连接应答 type=%d，未进入认证阶段", typ)
		return res, nil
	}
	// 认证请求（最小形态）：用户名 + 口令派生摘要。不是真实 O3LOGON，见文件头限制说明。
	authPayload := "(AUTH_USER=" + cred.Username + ")(AUTH_TERMINAL=jw)(AUTH_PROGRAM=Jingwei-CredScan)" +
		"(AUTH_MACHINE=jw)(AUTH_PASSWORD_DIGEST=" + oraclePassDigest(cred.Password) + ")"
	if err = w.write(tnsPacket(6, []byte(authPayload))); err != nil {
		return res.withErr(err)
	}
	typ2, body2, err := tnsRead(w)
	if err != nil {
		return res.withErr(err)
	}
	res.Banner = fmt.Sprintf("TNS 认证应答 type=%d: %s", typ2, credPreview(body2))
	low := strings.ToLower(string(body2))
	switch {
	case strings.Contains(low, "auth_ok") || strings.Contains(low, "session_established"):
		res.Outcome = CredHit
	case strings.Contains(low, "ora-01017") || strings.Contains(low, "invalid username") ||
		strings.Contains(low, "auth_fail") || strings.Contains(low, "logon denied"):
		// 拒绝也留证：把服务端原文写进 Reason，报告里能自证不是猜的。
		res.Outcome = CredDeny
		res.Reason = "TNS 返回认证拒绝：" + credPreview(body2)
	case credLockedText(low):
		res.Outcome = CredLocked
		res.Reason = "目标提示账号锁定或访问封禁，已停手"
	default:
		res.Outcome = CredInconclusive
		res.Reason = "TNS 认证应答既非明确接受也非明确拒绝，不能对这组凭据下结论"
	}
	return res, nil
}

func init() { RegisterCredAdapter(oracleCredAdapter{}) }
