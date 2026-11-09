package scanner

import (
	"context"
	"encoding/binary"
	"fmt"
	"strings"
	"unicode/utf16"
)

// MSSQL / TDS 登录探针。
//
// 实现到 TDS 的帧层：PreLogin(0x12) 拿服务端版本、Login7(0x10) 提交凭据、再按
// token 流里的 LOGINACK(0xAD) / ERROR(0xAA) 判定。口令按 [MS-TDS] 的规则逐字节
// 「高低 4 位互换后异或 0xA5」混淆，这是真实的 TDS 行为。
//
// 限制（如实写明）：Login7 的可变字段按最小形态填充，未逐字段照抄 [MS-TDS] 的全部
// offset/length 语义；TDS 的 TLS/加密协商与 SSPI/NTLM 变体未实现。因此真机部署前需要
// 对着 MSSQL 容器核对 Login7 布局。本轮未在真机验证，hit/deny 双路径由进程内协议桩覆盖。

type mssqlCredAdapter struct{}

func (mssqlCredAdapter) Protocol() string { return "mssql" }

func mssqlPacket(typ byte, payload []byte) []byte {
	total := 8 + len(payload)
	out := make([]byte, 8)
	out[0], out[1] = typ, 0x01 // EOM
	out[2], out[3] = byte(total>>8), byte(total)
	return append(out, payload...)
}

// mssqlPreLogin 发 VERSION / ENCRYPTION / MARS 三个 option，数据区跟在 option 表后。
func mssqlPreLogin() []byte {
	table := []byte{
		0x00, 0x00, 0x00, 0x00, 0x06, // VERSION @0 len6
		0x01, 0x00, 0x06, 0x00, 0x01, // ENCRYPTION @6 len1
		0x04, 0x00, 0x07, 0x00, 0x01, // MARS @7 len1
		0xff,
	}
	data := []byte{0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00}
	return append(table, data...)
}

func mssqlReadPacket(w *credWire) (byte, []byte, error) {
	head, err := w.readN(8)
	if err != nil {
		return 0, nil, err
	}
	total := int(head[2])<<8 | int(head[3])
	if total < 8 || total > credReadMax {
		return 0, head, fmt.Errorf("TDS 包长度异常 %d", total)
	}
	body, err := w.readN(total - 8)
	return head[0], body, err
}

func mssqlUTF16(s string) []byte {
	u := utf16.Encode([]rune(s))
	out := make([]byte, len(u)*2)
	for i, v := range u {
		binary.LittleEndian.PutUint16(out[i*2:], v)
	}
	return out
}

func mssqlDecodeUTF16(b []byte) string {
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(b[i*2:])
	}
	return string(utf16.Decode(u))
}

func mssqlObfuscate(b []byte) []byte {
	out := make([]byte, len(b))
	for i, v := range b {
		out[i] = ((v << 4) | (v >> 4)) ^ 0xa5
	}
	return out
}

// mssqlLogin7 组一个最小形态的 Login7：36 字节固定头 + 9 组 (offset,length) + 变长数据区。
func mssqlLogin7(cred Credential, host string) []byte {
	parts := [][]byte{
		mssqlUTF16("jw"),
		mssqlUTF16(cred.Username),
		mssqlObfuscate(mssqlUTF16(cred.Password)),
		mssqlUTF16("Jingwei"),
		mssqlUTF16(host),
		mssqlUTF16("Jingwei"),
		mssqlUTF16("us_english"),
		mssqlUTF16("master"),
		nil,
	}
	const fixed, pairs = 36, 9
	hdr := fixed + pairs*4
	off := hdr
	offs, lens := make([]int, pairs), make([]int, pairs)
	for i, p := range parts {
		offs[i], lens[i] = off, len(p)/2
		off += len(p)
	}
	out := make([]byte, hdr)
	binary.LittleEndian.PutUint32(out[0:], uint32(off)) // Length
	binary.LittleEndian.PutUint32(out[4:], 0x74000004)  // TDS 7.4
	binary.LittleEndian.PutUint32(out[8:], 4096)        // PacketSize
	binary.LittleEndian.PutUint32(out[12:], 0x07000000)
	binary.LittleEndian.PutUint32(out[16:], 1234) // ClientPID
	out[24], out[25] = 0xe0, 0x03
	for i := 0; i < pairs; i++ {
		p := fixed + i*4
		binary.LittleEndian.PutUint16(out[p:], uint16(offs[i]))
		binary.LittleEndian.PutUint16(out[p+2:], uint16(lens[i]))
	}
	for _, part := range parts {
		out = append(out, part...)
	}
	return out
}

func mssqlErrorTokenText(b []byte) string {
	if len(b) < 2 {
		return ""
	}
	l := int(binary.LittleEndian.Uint16(b))
	p := b[2:]
	if l > len(p) {
		l = len(p)
	}
	p = p[:l]
	if len(p) < 8 {
		return ""
	}
	n := int(binary.LittleEndian.Uint16(p[6:]))
	msg := p[8:]
	if n*2 > len(msg) {
		n = len(msg) / 2
	}
	return mssqlDecodeUTF16(msg[:n*2])
}

// mssqlClassifyLogin 只看 token 流里服务端亲口说的结论。
func mssqlClassifyLogin(body []byte) (CredOutcome, string) {
	for i := 0; i < len(body); {
		switch body[i] {
		case 0xad: // LOGINACK：服务端明确接受登录，这是 hit 的握手层信号
			return CredHit, ""
		case 0xaa: // ERROR token
			txt := mssqlErrorTokenText(body[i+1:])
			if strings.TrimSpace(txt) == "" {
				txt = credPreview(body)
			}
			if credLockedText(strings.ToLower(txt)) {
				return CredLocked, "目标提示账号锁定或访问封禁，已停手：" + txt
			}
			return CredDeny, "TDS 返回登录错误：" + credPreview([]byte(txt))
		default: // INFO / DONE / 未知 token：长度不固定，不冒险跳过，收尾
			return "", ""
		}
	}
	return "", ""
}

func (a mssqlCredAdapter) Identify(ctx context.Context, ep CredEndpoint) (bool, string, error) {
	w, err := credDial(ctx, credAddr(ep))
	if err != nil {
		return false, "", err
	}
	defer w.close()
	if err := w.write(mssqlPacket(0x12, mssqlPreLogin())); err != nil {
		return false, "", err
	}
	typ, body, err := mssqlReadPacket(w)
	if err != nil {
		return false, credPreview(w.resp), err
	}
	if typ != 0x04 { // Tabular Result / PreLogin response
		return false, credPreview(w.resp), nil
	}
	// option 表里找 VERSION(0x00)：这是 TDS 特有的握手证据，不是「端口有人回话」。
	for i := 0; i+4 < len(body) && body[i] != 0xff; i += 5 {
		if body[i] != 0x00 {
			continue
		}
		off := int(body[i+1])<<8 | int(body[i+2])
		ln := int(body[i+3])<<8 | int(body[i+4])
		if off+6 <= len(body) && ln >= 6 {
			v := body[off:]
			return true, fmt.Sprintf("TDS PreLogin 响应，服务端版本 %d.%d.%d", v[0], v[1], int(v[2])<<8|int(v[3])), nil
		}
	}
	return true, "TDS PreLogin 响应（Tabular Result 0x04）", nil
}

func (a mssqlCredAdapter) Try(ctx context.Context, ep CredEndpoint, cred Credential) (res CredAttempt, err error) {
	res = credNewAttempt(cred)
	w, err := credDial(ctx, credAddr(ep))
	if err != nil {
		return res.withErr(err)
	}
	defer w.close()
	defer func() { res.syncWire(w) }()

	if err = w.write(mssqlPacket(0x12, mssqlPreLogin())); err != nil {
		return res.withErr(err)
	}
	if _, _, err = mssqlReadPacket(w); err != nil {
		return res.withErr(err)
	}
	if err = w.write(mssqlPacket(0x10, mssqlLogin7(cred, ep.Host))); err != nil {
		return res.withErr(err)
	}
	typ, body, err := mssqlReadPacket(w)
	if err != nil {
		return res.withErr(err)
	}
	res.Banner = fmt.Sprintf("TDS 登录应答 (type=0x%02x, %d 字节)", typ, len(body))
	if outcome, reason := mssqlClassifyLogin(body); outcome != "" {
		res.Outcome, res.Reason = outcome, reason
		return res, nil
	}
	res.Outcome = CredInconclusive
	res.Reason = "登录应答里没有 LOGINACK 或 ERROR token，不能对这组凭据下结论"
	return res, nil
}

func init() { RegisterCredAdapter(mssqlCredAdapter{}) }
