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
// 已在真机 SQL Server 2022（Linux 容器）验证 hit/deny 双路径。真机暴露并修掉四处：
// PreLogin 的 option offset 要相对包体（不是从 0 起，否则覆盖 option 表本身）；Login7
// 头必须带 ClientID(6) 与 SSPI/AtchDBFile/ChangePassword/cbSSPILong 共 22 字节尾部；
// Extension 在 fExtension=0 时 offset 与 length 必须同时为 0；登录应答是分包的，
// LOGINACK 往往在 ENVCHANGE/INFO 之后的包里，只看第一个包会漏判成功。
//
// 限制：TDS over TLS 与 SSPI/NTLM（Windows 集成认证）未实现——PreLogin 协商出服务端
// 强制加密时如实落 unsupported，并写明「未提交凭据」。

type mssqlCredAdapter struct{}

func (mssqlCredAdapter) Protocol() string { return "mssql" }

func mssqlPacket(typ byte, payload []byte) []byte {
	total := 8 + len(payload)
	out := make([]byte, 8)
	out[0], out[1] = typ, 0x01 // EOM
	out[2], out[3] = byte(total>>8), byte(total)
	return append(out, payload...)
}

// mssqlPreLogin 发 VERSION / ENCRYPTION / MARS 三个 option。
// option 表每个 5 字节（token + offset(2,BE) + length(2,BE)），0xFF 结尾共 16 字节；
// 偏移是相对 PRELOGIN 包体起点的，所以数据区必须从 16 开始——从 0 开始会把 option
// 表自己覆盖掉，服务端只会回一个通用错误。
func mssqlPreLogin() []byte {
	table := []byte{
		0x00, 0x00, 0x10, 0x00, 0x06, // VERSION    @16 len 6
		0x01, 0x00, 0x16, 0x00, 0x01, // ENCRYPTION @22 len 1
		0x04, 0x00, 0x17, 0x00, 0x01, // MARS       @23 len 1
		0xff,
	}
	// VERSION 用 15.0.2000（SQL Server 2019 起的口径），ENCRYPTION=0x02
	// （ENCRYPT_NOT_SUP：先按明文谈，服务端强制加密时会回 ENCRYPT_ON，由 Try 识别）。
	data := []byte{0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00}
	return append(table, data...)
}

// mssqlPreLoginEncryption 从 PreLogin 响应里取 ENCRYPTION option 的值。
// 0=OFF, 1=ON, 2=NOT_SUP, 3=REQ。返回 -1 表示没有这个 option。
func mssqlPreLoginEncryption(body []byte) int {
	for i := 0; i+4 < len(body) && body[i] != 0xff; i += 5 {
		if body[i] != 0x01 {
			continue
		}
		off := int(binary.BigEndian.Uint16(body[i+1:]))
		ln := int(binary.BigEndian.Uint16(body[i+3:]))
		if ln >= 1 && off < len(body) {
			return int(body[off])
		}
	}
	return -1
}

func mssqlReadPacket(w *credWire) (typ byte, status byte, body []byte, err error) {
	head, err := w.readN(8)
	if err != nil {
		return 0, 0, nil, err
	}
	total := int(head[2])<<8 | int(head[3])
	if total < 8 || total > credReadMax {
		return 0, 0, head, fmt.Errorf("TDS 包长度异常 %d", total)
	}
	body, err = w.readN(total - 8)
	return head[0], head[1], body, err
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

// mssqlLogin7 按 [MS-TDS] 2.2.6.4 组包：
//
//	36 字节固定头 + 9 组变长 (offset,length) + ClientID(6)
//	+ SSPI / AtchDBFile / ChangePassword 三组 (offset,length) + 变长数据区
//
// 少写尾部 18 字节（ClientID 与三组 offset/length）服务端会把整包判成畸形，
// 表现为「连上就被断」而不是「口令错」——两种结果都没法用。
//
// 字符串字段的 length 是字符数，只有 Extension 那组是字节数。
func mssqlLogin7(cred Credential, host string) []byte {
	strs := [][]byte{
		mssqlUTF16("jingwei"),                     // HostName
		mssqlUTF16(cred.Username),                 // UserName
		mssqlObfuscate(mssqlUTF16(cred.Password)), // Password
		mssqlUTF16("jingwei"),                     // AppName
		mssqlUTF16(host),                          // ServerName
		nil,                                       // Extension（length 是字节数，此处为空）
		mssqlUTF16("jingwei"),                     // CltIntName
		nil,                                       // Language（留空：设了 fLanguage 就必须给存在的语言）
		mssqlUTF16("master"),                      // Database
	}
	const fixed = 36
	// ClientID(6) + SSPI(4) + AtchDBFile(4) + ChangePassword(4) + cbSSPILong(4)。
	// 规范把 cbSSPILong 写成「仅 fExtension=1 时存在」，但 SQL Server 按 7.4 解析时
	// 总是读这 4 字节——少写就报 login packet structurally invalid（真机对照 pytds
	// 抓包确认：它的 OptionFlags3=0x08 也带着这 4 字节）。
	const tail = 6 + 4 + 4 + 4 + 4
	hdr := fixed + len(strs)*4 + tail

	off := hdr
	offs, lens := make([]int, len(strs)), make([]int, len(strs))
	for i, s := range strs {
		if i == 5 {
			// fExtension=0 时 ibExtension 与 cbExtension 必须同时为 0。给一个指向
			// 结构末尾的 offset 而 cbExtension=0 是自相矛盾，服务端会判整包畸形。
			offs[i], lens[i] = 0, 0
			continue
		}
		offs[i], lens[i] = off, len(s)/2
		off += len(s)
	}

	out := make([]byte, hdr)
	binary.LittleEndian.PutUint32(out[0:], uint32(off)) // Length：整包（含变长数据）
	binary.LittleEndian.PutUint32(out[4:], 0x74000004)  // TDS 7.4
	binary.LittleEndian.PutUint32(out[8:], 4096)        // PacketSize
	binary.LittleEndian.PutUint32(out[12:], 0x00000007) // ClientProgVer
	binary.LittleEndian.PutUint32(out[16:], 1234)       // ClientPID
	binary.LittleEndian.PutUint32(out[20:], 0)          // ConnectionID
	out[24] = 0xf0                                      // OptionFlags1: UseDB|Database(fatal)|SetLang|DumpLoad
	out[25] = 0x02                                      // OptionFlags2: ODBC（不设 fLanguage，语言字段留空）
	out[26] = 0x00                                      // TypeFlags: SQL_DFLT
	out[27] = 0x08                                      // OptionFlags3: fUnknownCollationHandling
	binary.LittleEndian.PutUint32(out[28:], 480)        // ClientTimeZone（UTC+8，与真实客户端一致）
	binary.LittleEndian.PutUint32(out[32:], 0x0409)     // ClientLCID: en-US

	for i := range strs {
		p := fixed + i*4
		binary.LittleEndian.PutUint16(out[p:], uint16(offs[i]))
		binary.LittleEndian.PutUint16(out[p+2:], uint16(lens[i]))
	}
	// ClientID 全 0（6 字节，保持零值）；SSPI / AtchDBFile / ChangePassword 三组
	// offset 指向数据区末尾、length 为 0。
	base := fixed + len(strs)*4
	binary.LittleEndian.PutUint16(out[base+6:], uint16(off))  // ibSSPI
	binary.LittleEndian.PutUint16(out[base+8:], 0)            // cbSSPI
	binary.LittleEndian.PutUint16(out[base+10:], uint16(off)) // ibAtchDBFile
	binary.LittleEndian.PutUint16(out[base+12:], 0)
	binary.LittleEndian.PutUint16(out[base+14:], uint16(off)) // ibChangePassword
	binary.LittleEndian.PutUint16(out[base+16:], 0)

	for _, s := range strs {
		out = append(out, s...)
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
// 登录成功的应答里，业务 token 的顺序通常是 ENVCHANGE(切库) → INFO → ENVCHANGE(语言)
// → INFO → LOGINACK；遇到第一个非结论 token 就收工会把成功当失败。
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
		case 0xab, 0xa9, 0xe3, 0xe4: // INFO / ORDER / ENVCHANGE / SESSIONSTATE：2 字节长度
			if i+3 > len(body) {
				return "", ""
			}
			i += 3 + int(binary.LittleEndian.Uint16(body[i+1:]))
		case 0xfd, 0xfe, 0xff: // DONE / DONEPROC / DONEINPROC：固定 13 字节
			i += 13
		case 0x79: // RETURNSTATUS：固定 5 字节
			i += 5
		default:
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
	typ, _, body, err := mssqlReadPacket(w)
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
	_, _, preBody, err := mssqlReadPacket(w)
	if err != nil {
		return res.withErr(err)
	}
	// 服务端强制加密时，接下来的字节是 TLS 握手而不是 TDS，继续发 Login7 只会得到
	// 一堆解不出来的数据。这里如实停下，并把「没提交凭据」写清楚。
	if enc := mssqlPreLoginEncryption(preBody); enc == 1 || enc == 3 {
		res.Outcome = CredUnsupported
		res.Reason = "服务端要求 TDS over TLS（PreLogin ENCRYPTION=ON/REQ），本适配器未实现 TLS 层，未提交凭据"
		return res, nil
	}
	if err = w.write(mssqlPacket(0x10, mssqlLogin7(cred, ep.Host))); err != nil {
		return res.withErr(err)
	}
	// 登录应答是分包的：切库/切语言的 ENVCHANGE 与 INFO 往往先在第一个包里，
	// LOGINACK 在后面的包。只看第一个包会把它误判成「没有结论」。
	var lastType byte
	var got int
	for i := 0; i < 8; i++ {
		typ, status, part, perr := mssqlReadPacket(w)
		if perr != nil {
			if got == 0 {
				return res.withErr(perr)
			}
			break
		}
		lastType = typ
		got += len(part)
		if outcome, reason := mssqlClassifyLogin(part); outcome != "" {
			res.Banner = fmt.Sprintf("TDS 登录应答 (type=0x%02x, %d 字节)", typ, got)
			res.Outcome, res.Reason = outcome, reason
			return res, nil
		}
		if status&0x01 != 0 { // EOM：流的最后一个包
			break
		}
	}
	res.Banner = fmt.Sprintf("TDS 登录应答 (type=0x%02x, %d 字节)", lastType, got)
	res.Outcome = CredInconclusive
	res.Reason = "登录应答里没有 LOGINACK 或 ERROR token，不能对这组凭据下结论"
	return res, nil
}

func init() { RegisterCredAdapter(mssqlCredAdapter{}) }
