package scanner

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode/utf16"

	//lint:ignore SA1019 NTLMv2 的 NTOWFv1 按 [MS-NLMP] 规定必须是 MD4，只用于计算口令散列，不用于防篡改
	"golang.org/x/crypto/md4"
)

// SMB2 (445) 登录探针：NetBIOS session 帧 + SMB2 NEGOTIATE + SESSION_SETUP 的
// NTLMSSP 三消息。SMB2 头里的 FE 'S' 'M' 'B' magic 是协议特有证据，不靠端口猜；
// hit 的握手层「接受」信号是最后一次 SESSION_SETUP 的 STATUS_SUCCESS(0)，
// LOGON_FAILURE(0xC000006D) 是明确拒绝，ACCOUNT_LOCKED_OUT(0xC0000234) 是锁定。
//
// 认证按 [MS-NLMP] 3.3.2 的 NTLMv2 实现：NTOWFv1 = MD4(UTF16LE(口令))，
// NTOWFv2 = HMAC-MD5(NTOWFv1, UTF16LE(UPPER(用户)+域))，应答 = HMAC-MD5(NTOWFv2,
// ServerChallenge||blob) || blob。域与 TargetInfo 都取服务端质询里给的那份原样回填。
//
// 已在真机 Samba 4.24 上验证 hit/deny 双路径。真机暴露并修掉三处：NEGOTIATE 的方言
// 数组必须从体偏移 36 起（塞进 ClientGuid 区会让服务端断连），且不能声明 3.1.1
// （它要求 negotiate context）；MessageId 必须从 0 开始（Samba 的序列号校验会拒 1）；
// 第二次 SESSION_SETUP 必须带回服务端上一次响应里的 SessionId，否则 INVALID_PARAMETER。
//
// 限制：未实现 NTLMv1 与签名/密封（session key 下发但不用）；SMB3 加密未协商。

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
	// SESSION_SETUP 响应体偏移 2 的 SessionFlags：guest / null 会话即使
	// status=SUCCESS 也不代表凭据有效（Samba 的 map to guest = bad user 就是
	// 把任意不存在的账号降级成访客会话）。不认这两位会把「任意口令」判成命中。
	smb2SessionFlagGuest = 0x0001
	smb2SessionFlagNull  = 0x0002
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
	binary.LittleEndian.PutUint16(h[6:], 1)  // CreditCharge
	binary.LittleEndian.PutUint32(h[8:], status)
	binary.LittleEndian.PutUint16(h[12:], command)
	binary.LittleEndian.PutUint16(h[14:], 1) // CreditRequest
	binary.LittleEndian.PutUint64(h[24:], messageID)
	return h
}

// smb2Negotiate 组 NEGOTIATE Request：36 字节固定体 + DialectCount*2 字节方言数组。
// 方言数组从体偏移 36 开始，不是塞进 ClientGuid/ClientStartTime 里——塞错位置服务端
// 解析到「方言数量 5 但数组不存在」，直接断连。
// 只谈到 0x0224(SMB 3.0.2)：3.1.1 必须带 negotiate context（preauth 完整性），
// 不带会被拒，而我们用不到 3.1.1 的加密/预授权。
func smb2Negotiate() []byte {
	dialects := []uint16{0x0202, 0x0210, 0x0222, 0x0224}
	h := smb2Header(smb2CmdNegotiate, 0, 0)
	body := make([]byte, 36)
	binary.LittleEndian.PutUint16(body[0:], 36)                    // StructureSize
	binary.LittleEndian.PutUint16(body[2:], uint16(len(dialects))) // DialectCount
	binary.LittleEndian.PutUint16(body[4:], 1)                     // SecurityMode: signing enabled
	for _, d := range dialects {
		tmp := make([]byte, 2)
		binary.LittleEndian.PutUint16(tmp, d)
		body = append(body, tmp...)
	}
	return append(h, body...)
}

func smb2SessionSetup(messageID, sessionID uint64, secBuf []byte) []byte {
	h := smb2Header(smb2CmdSessionSetup, 0, messageID)
	// 第二次 SESSION_SETUP 必须带回服务端上一次响应里的 SessionId，
	// 带 0 会被判 STATUS_INVALID_PARAMETER（真机 Samba 4.24 实测）。
	binary.LittleEndian.PutUint64(h[40:], sessionID)
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

// smb2SessionFlags 取 SESSION_SETUP 响应体的 SessionFlags（64 字节头之后的
// StructureSize(2) 之后）。帧不完整时返回 0，按「无特殊标记」处理。
func smb2SessionFlags(frame []byte) uint16 {
	if len(frame) < 68 {
		return 0
	}
	return binary.LittleEndian.Uint16(frame[66:68])
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

// ntlmType2 是 [MS-NLMP] 2.2.1.2 CHALLENGE_MESSAGE 里我们算 NTLMv2 需要的部分。
type ntlmType2 struct {
	challenge  []byte
	targetName string
	targetInfo []byte
	flags      uint32
}

func smbDecodeUTF16(b []byte) string {
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(b[i*2:])
	}
	return string(utf16.Decode(u))
}

// ntlmParseType2 解析服务端质询。TargetInfo 必须原样回填进 NTLMv2 blob——
// 自己拼一份 AV-pair 会被 Windows 判成无效（Samba 宽松些，但没必要赌）。
func ntlmParseType2(sec []byte) *ntlmType2 {
	if len(sec) < 32 || !bytes.HasPrefix(sec, []byte("NTLMSSP\x00")) ||
		binary.LittleEndian.Uint32(sec[8:]) != 2 {
		return nil
	}
	t := &ntlmType2{
		challenge: append([]byte(nil), sec[24:32]...),
		flags:     binary.LittleEndian.Uint32(sec[20:]),
	}
	if n, off := int(binary.LittleEndian.Uint16(sec[12:])), int(binary.LittleEndian.Uint32(sec[16:])); n > 0 && off+n <= len(sec) {
		t.targetName = smbDecodeUTF16(sec[off : off+n])
	}
	if len(sec) >= 48 {
		n, off := int(binary.LittleEndian.Uint16(sec[40:])), int(binary.LittleEndian.Uint32(sec[44:]))
		if n > 0 && off+n <= len(sec) {
			t.targetInfo = append([]byte(nil), sec[off:off+n]...)
		}
	}
	return t
}

// ntlmV2Response 按 [MS-NLMP] 3.3.2 算 NTLMv2：
//
//	NTOWFv1 = MD4(UTF16LE(password))
//	NTOWFv2 = HMAC-MD5(NTOWFv1, UTF16LE(UPPER(user) + domain))
//	blob    = 0x01010000 | 00000000 | FILETIME | ClientChallenge | 00000000 | TargetInfo | 00000000
//	proof   = HMAC-MD5(NTOWFv2, ServerChallenge || blob)
//	应答    = proof || blob
//
// 用户名必须大写后再拼域，且域用的是服务端在质询里给的名字——这两点任一处写错，
// Samba 与 Windows 都只会回 LOGON_FAILURE，看起来跟口令错一模一样。
func ntlmV2Response(cred Credential, t2 *ntlmType2) []byte {
	m := md4.New()
	m.Write(smbUTF16(cred.Password))
	v1 := m.Sum(nil)

	dom := t2.targetName
	if dom == "" {
		dom = "."
	}
	h := hmac.New(md5.New, v1)
	h.Write(smbUTF16(strings.ToUpper(cred.Username) + dom))
	v2 := h.Sum(nil)

	blob := []byte{0x01, 0x01, 0x00, 0x00, 0, 0, 0, 0}
	ft := make([]byte, 8) // FILETIME：从 1601 起的 100ns 计数
	binary.LittleEndian.PutUint64(ft, uint64(time.Now().Unix()+11644473600)*10000000)
	blob = append(blob, ft...)
	cli := make([]byte, 8)
	if _, err := io.ReadFull(rand.Reader, cli); err != nil {
		copy(cli, []byte("jwlabcbr"))
	}
	blob = append(blob, cli...)
	blob = append(blob, 0, 0, 0, 0)
	if len(t2.targetInfo) > 0 {
		blob = append(blob, t2.targetInfo...)
	} else {
		blob = append(blob, 0, 0, 0, 0) // EOL
	}
	blob = append(blob, 0, 0, 0, 0)

	hh := hmac.New(md5.New, v2)
	hh.Write(t2.challenge)
	hh.Write(blob)
	return append(hh.Sum(nil), blob...)
}

func ntlmAuth(cred Credential, t2 *ntlmType2) []byte {
	nt := ntlmV2Response(cred, t2)
	dom := t2.targetName
	if dom == "" {
		dom = "."
	}
	domain, user, ws := smbUTF16(dom), smbUTF16(cred.Username), smbUTF16("JW")
	const hdr = 64
	off := hdr
	ntOff := off
	domOff := ntOff + len(nt)
	usrOff := domOff + len(domain)
	wsOff := usrOff + len(user)
	keyOff := wsOff + len(ws)
	out := make([]byte, hdr)
	copy(out, []byte("NTLMSSP\x00"))
	binary.LittleEndian.PutUint32(out[8:], 3) // type 3
	smbSecField(out[12:], 0, 0)               // LM response 空：null 字段的 offset 也必须为 0
	smbSecField(out[20:], len(nt), ntOff)
	smbSecField(out[28:], len(domain), domOff)
	smbSecField(out[36:], len(user), usrOff)
	smbSecField(out[44:], len(ws), wsOff)
	smbSecField(out[52:], 0, keyOff)
	binary.LittleEndian.PutUint32(out[60:], t2.flags)
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
	if len(frame) >= 70 {
		// DialectRevision 在 SMB2 头之后的结构体偏移 4：64+4 = 68。
		dialect = int(binary.LittleEndian.Uint16(frame[68:]))
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
	if err = w.write(smb2Frame(smb2SessionSetup(1, 0, ntlmNegotiate()))); err != nil {
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
	t2 := ntlmParseType2(smb2SecurityBuffer(ss1))
	if t2 == nil {
		res.Outcome = CredInconclusive
		res.Reason = "SESSION_SETUP 应答里没有合法的 NTLMSSP CHALLENGE"
		return res, nil
	}
	// 第二次 SESSION_SETUP：NTLMSSP_AUTH（NTLMv2 应答），必须带回上一步的 SessionId。
	var sessionID uint64
	if len(ss1) >= 48 {
		sessionID = binary.LittleEndian.Uint64(ss1[40:])
	}
	if err = w.write(smb2Frame(smb2SessionSetup(2, sessionID, ntlmAuth(cred, t2)))); err != nil {
		return res.withErr(err)
	}
	ss2, err := smb2ReadFrame(w)
	if err != nil {
		return res.withErr(err)
	}
	res.Banner = fmt.Sprintf("SMB2 SESSION_SETUP status=0x%08x", smb2Status(ss2))
	switch smb2Status(ss2) {
	case smb2StatusSuccess:
		if flags := smb2SessionFlags(ss2); flags&(smb2SessionFlagGuest|smb2SessionFlagNull) != 0 {
			if cred.Username == "" && cred.Password == "" {
				res.Outcome = CredHit
				res.Reason = "该 SMB 端点允许匿名访客会话（SessionFlags=guest/null），无需凭据即可访问"
			} else {
				// 真机 Samba（map to guest = bad user）实测：不存在的账号也会回 SUCCESS，
				// 只是被降级成访客会话。此时凭据并未通过认证，必须判拒绝。
				res.Outcome = CredDeny
				res.Reason = fmt.Sprintf("凭据被服务端映射为访客会话（SessionFlags=0x%04x），实际未通过认证", flags)
			}
			return res, nil
		}
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
