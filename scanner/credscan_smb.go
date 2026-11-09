package scanner

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"unicode/utf16"
)

// SMB2 (445) 登录探针：NetBIOS session 帧 + SMB2 NEGOTIATE + SESSION_SETUP 的
// NTLMSSP 三消息。SMB2 头里的 FE 'S' 'M' 'B' magic 是协议特有证据，不靠端口猜；
// hit 的握手层「接受」信号是最后一次 SESSION_SETUP 的 STATUS_SUCCESS(0)，
// LOGON_FAILURE(0xC000006D) 是明确拒绝，ACCOUNT_LOCKED_OUT(0xC0000234) 是锁定。
//
// 限制（如实写明）：[MS-NLMP] 的 NTOWFv1(MD4) / NTLMv2(HMAC-MD5 + AV-pair blob) 密码学
// 未实现（本轮不引 x/crypto/md4、也不自实现 MD4），Type3 里的 NT 质询应答是按口令派生的
// 占位值。真机部署前必须按 [MS-NLMP] 补齐 NTLM 计算，或让 Samba 允许对应机制。
// lab 登记了 Samba 用例，但本轮未在真机验证 hit 路径；SMB2/NTLMSSP 帧状态机与
// STATUS_* 判定由进程内协议桩覆盖。不写「已在真机跑通」。

type smbCredAdapter struct{}

func (smbCredAdapter) Protocol() string { return "smb" }

var smb2Magic = []byte{0xfe, 0x53, 0x4d, 0x42}

const (
	smb2CmdNegotiate    = 0x0000
	smb2CmdSessionSetup = 0x0001
	smb2StatusSuccess   = 0x00000000
	smb2StatusMoreProc  = 0xc0000016
	smb2StatusLogonFail = 0xc000006d
	smb2StatusLockedOut = 0xc0000234
)

func smb2Frame(msg []byte) []byte {
	out := make([]byte, 4) // NetBIOS session: 0x00 + 3-byte BE length
	n := len(msg)
	out[1], out[2], out[3] = byte(n>>16), byte(n>>8), byte(n)
	return append(out, msg...)
}

func smb2ReadFrame(w *credWire) ([]byte, error) {
	head, err := w.readN(4)
	if err != nil {
		return nil, err
	}
	n := int(head[1])<<16 | int(head[2])<<8 | int(head[3])
	if n < 64 || n > credReadMax {
		return nil, fmt.Errorf("SMB2 帧长度异常 %d", n)
	}
	return w.readN(n)
}

func smb2Header(command uint16, status uint32, messageID uint64) []byte {
	h := make([]byte, 64)
	copy(h, smb2Magic)
	binary.LittleEndian.PutUint16(h[4:], 64) // StructureSize
	binary.LittleEndian.PutUint32(h[8:], status)
	binary.LittleEndian.PutUint16(h[12:], command)
	binary.LittleEndian.PutUint64(h[24:], messageID)
	return h
}

func smb2Negotiate() []byte {
	h := smb2Header(smb2CmdNegotiate, 0, 1)
	body := make([]byte, 36)
	binary.LittleEndian.PutUint16(body[0:], 36) // StructureSize
	binary.LittleEndian.PutUint16(body[2:], 5)  // DialectCount
	for i, d := range []uint16{0x0202, 0x0210, 0x0222, 0x0224, 0x0311} {
		binary.LittleEndian.PutUint16(body[36-10+i*2:], d)
	}
	return append(h, body...)
}

func smb2SessionSetup(messageID uint64, secBuf []byte) []byte {
	h := smb2Header(smb2CmdSessionSetup, 0, messageID)
	body := make([]byte, 24)
	binary.LittleEndian.PutUint16(body[0:], 25)  // StructureSize
	binary.LittleEndian.PutUint16(body[12:], 88) // SecurityBufferOffset = 64 + 24
	binary.LittleEndian.PutUint16(body[14:], uint16(len(secBuf)))
	return append(append(h, body...), secBuf...)
}

func smb2Status(frame []byte) uint32 {
	if len(frame) < 12 {
		return 0xffffffff
	}
	return binary.LittleEndian.Uint32(frame[8:])
}

func smb2SecurityBuffer(frame []byte) []byte {
	if len(frame) < 72 {
		return nil
	}
	off := int(binary.LittleEndian.Uint16(frame[68:]))
	ln := int(binary.LittleEndian.Uint16(frame[70:]))
	if off <= 0 || ln <= 0 || off+ln > len(frame) {
		return nil
	}
	return frame[off : off+ln]
}

func smbUTF16(s string) []byte {
	u := utf16.Encode([]rune(s))
	out := make([]byte, len(u)*2)
	for i, v := range u {
		binary.LittleEndian.PutUint16(out[i*2:], v)
	}
	return out
}

func smbSecField(dst []byte, l, off int) {
	binary.LittleEndian.PutUint16(dst[0:], uint16(l))
	binary.LittleEndian.PutUint16(dst[2:], uint16(l))
	binary.LittleEndian.PutUint32(dst[4:], uint32(off))
}

func ntlmNegotiate() []byte {
	b := append([]byte("NTLMSSP\x00"), 0x01, 0x00, 0x00, 0x00) // type 1
	b = append(b, 0x07, 0x82, 0x08, 0xa0)                      // flags
	b = append(b, make([]byte, 16)...)                         // domain + workstation fields
	return b
}

// smbNTResponse 是 NT 质询应答的占位实现：HMAC-MD5(口令派生 key, ServerChallenge)。
// 它不是 [MS-NLMP] 的 NTLMv2/v1，见文件头限制说明。
func smbNTResponse(pass string, challenge []byte) []byte {
	key := md5.Sum(smbUTF16(pass))
	h := hmac.New(md5.New, key[:])
	h.Write(challenge)
	return h.Sum(nil)
}

// ntlmChallengeOf 取 Type2 固定偏移 24..32 的 ServerChallenge。
func ntlmChallengeOf(sec []byte) []byte {
	if len(sec) < 32 || !bytes.HasPrefix(sec, []byte("NTLMSSP\x00")) {
		return nil
	}
	return append([]byte(nil), sec[24:32]...)
}

func ntlmAuth(cred Credential, challenge []byte) []byte {
	nt := smbNTResponse(cred.Password, challenge)
	domain, user, ws := smbUTF16("."), smbUTF16(cred.Username), smbUTF16("JW")
	const hdr = 64
	off := hdr
	lmOff := off
	ntOff := off + 0
	domOff := ntOff + len(nt)
	usrOff := domOff + len(domain)
	wsOff := usrOff + len(user)
	keyOff := wsOff + len(ws)
	out := make([]byte, hdr)
	copy(out, []byte("NTLMSSP\x00"))
	binary.LittleEndian.PutUint32(out[8:], 3) // type 3
	smbSecField(out[12:], 0, lmOff)           // LM response（空）
	smbSecField(out[20:], len(nt), ntOff)
	smbSecField(out[28:], len(domain), domOff)
	smbSecField(out[36:], len(user), usrOff)
	smbSecField(out[44:], len(ws), wsOff)
	smbSecField(out[52:], 0, keyOff)
	binary.LittleEndian.PutUint32(out[60:], 0x078208a0)
	out = append(out, nt...)
	out = append(out, domain...)
	out = append(out, user...)
	out = append(out, ws...)
	return out
}

func (a smbCredAdapter) Identify(ctx context.Context, ep CredEndpoint) (bool, string, error) {
	w, err := credDial(ctx, credAddr(ep))
	if err != nil {
		return false, "", err
	}
	defer w.close()
	if err := w.write(smb2Frame(smb2Negotiate())); err != nil {
		return false, "", err
	}
	frame, err := smb2ReadFrame(w)
	if err != nil {
		return false, credPreview(w.resp), err
	}
	if len(frame) < 4 || !bytes.Equal(frame[:4], smb2Magic) {
		return false, credPreview(frame), nil
	}
	dialect := 0
	if len(frame) >= 72 {
		dialect = int(binary.LittleEndian.Uint16(frame[70:]))
	}
	return true, fmt.Sprintf("SMB2 NEGOTIATE 响应（dialect 0x%04x）", dialect), nil
}

func (a smbCredAdapter) Try(ctx context.Context, ep CredEndpoint, cred Credential) (res CredAttempt, err error) {
	res = credNewAttempt(cred)
	w, err := credDial(ctx, credAddr(ep))
	if err != nil {
		return res.withErr(err)
	}
	defer w.close()
	defer func() { res.syncWire(w) }()

	if err = w.write(smb2Frame(smb2Negotiate())); err != nil {
		return res.withErr(err)
	}
	if _, err = smb2ReadFrame(w); err != nil {
		return res.withErr(err)
	}
	// 第一次 SESSION_SETUP：NTLMSSP_NEGOTIATE
	if err = w.write(smb2Frame(smb2SessionSetup(2, ntlmNegotiate()))); err != nil {
		return res.withErr(err)
	}
	ss1, err := smb2ReadFrame(w)
	if err != nil {
		return res.withErr(err)
	}
	st1 := smb2Status(ss1)
	if st1 == smb2StatusSuccess {
		// 服务端不要求认证：空凭据是可用凭据，非空不算命中。
		if cred.Username == "" && cred.Password == "" {
			res.Outcome = CredHit
			res.Reason = "该 SMB 端点不要求认证，空凭据即可建立会话"
		} else {
			res.Outcome = CredDeny
			res.Reason = "该 SMB 端点不要求认证，非空凭据不构成可用凭据"
		}
		return res, nil
	}
	if st1 != smb2StatusMoreProc {
		res.Outcome = CredInconclusive
		res.Reason = fmt.Sprintf("SESSION_SETUP 未进入 NTLMSSP 质询（status=0x%08x）", st1)
		return res, nil
	}
	challenge := ntlmChallengeOf(smb2SecurityBuffer(ss1))
	if challenge == nil {
		res.Outcome = CredInconclusive
		res.Reason = "SESSION_SETUP 应答里没有合法的 NTLMSSP CHALLENGE"
		return res, nil
	}
	// 第二次 SESSION_SETUP：NTLMSSP_AUTH
	if err = w.write(smb2Frame(smb2SessionSetup(3, ntlmAuth(cred, challenge)))); err != nil {
		return res.withErr(err)
	}
	ss2, err := smb2ReadFrame(w)
	if err != nil {
		return res.withErr(err)
	}
	res.Banner = fmt.Sprintf("SMB2 SESSION_SETUP status=0x%08x", smb2Status(ss2))
	switch smb2Status(ss2) {
	case smb2StatusSuccess:
		res.Outcome = CredHit
	case smb2StatusLogonFail:
		res.Outcome = CredDeny
	case smb2StatusLockedOut:
		res.Outcome = CredLocked
		res.Reason = "目标提示账号锁定（STATUS_ACCOUNT_LOCKED_OUT），已停手"
	default:
		res.Outcome = CredInconclusive
		res.Reason = fmt.Sprintf("SESSION_SETUP 返回 status=0x%08x，不是明确的成功/拒绝", smb2Status(ss2))
	}
	return res, nil
}

func init() { RegisterCredAdapter(smbCredAdapter{}) }
