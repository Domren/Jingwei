package scanner

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// MySQL / MariaDB 认证探针。
//
// 支持 mysql_native_password、caching_sha2_password（快速通道与公钥完整通道）、
// sha256_password、mysql_clear_password。服务端改口要求别的机制时报 unsupported，
// 不报 deny——「我们不会算这个」与「这组口令不对」是两句不同的话。
type mysqlCredAdapter struct{}

func (mysqlCredAdapter) Protocol() string { return "mysql" }

const (
	mysqlClientLongPassword     = 0x00000001
	mysqlClientConnectWithDB    = 0x00000008
	mysqlClientProtocol41       = 0x00000200
	mysqlClientSSL              = 0x00000800
	mysqlClientSecureConnection = 0x00008000
	mysqlClientPluginAuth       = 0x00080000
	mysqlClientPluginAuthLenenc = 0x00200000
	mysqlMaxPacket              = 1 << 20
)

// Identify 只读服务端首发问候包：里面就带版本号与认证插件名，是这条端点属于 MySQL 的
// 直接证据。不读认证插件名就没法判断「认得出但不会算」的情况。
func (a mysqlCredAdapter) Identify(ctx context.Context, ep CredEndpoint) (bool, string, error) {
	w, err := credDial(ctx, credAddr(ep))
	if err != nil {
		return false, "", err
	}
	defer w.close()
	p, err := mysqlReadPacket(w)
	if err != nil {
		return false, "", err
	}
	g, err := mysqlParseGreeting(p.payload)
	if err != nil {
		return false, credPreview(w.resp), nil
	}
	return true, "MySQL " + g.serverVersion + " · 认证插件 " + g.authPlugin, nil
}

func (a mysqlCredAdapter) Try(ctx context.Context, ep CredEndpoint, cred Credential) (res CredAttempt, err error) {
	res = credNewAttempt(cred)
	w, err := credDial(ctx, credAddr(ep))
	if err != nil {
		return res.withErr(err)
	}
	defer w.close()
	defer func() { res.syncWire(w) }()

	flow := &mysqlFlow{w: w}
	p, err := flow.read()
	if err != nil {
		return res.withErr(err)
	}
	if p.payload[0] == 0xff {
		return classifyMySQLError(res, p.payload), nil
	}
	g, err := mysqlParseGreeting(p.payload)
	if err != nil {
		res.Outcome = CredInconclusive
		res.Reason = "问候包解析失败：" + err.Error()
		return res, nil
	}
	res.Banner = "MySQL " + g.serverVersion + " · 认证插件 " + g.authPlugin

	plugin := g.authPlugin
	scramble := g.scramble
	flags := uint32(mysqlClientLongPassword | mysqlClientProtocol41 | mysqlClientSecureConnection |
		mysqlClientPluginAuth | mysqlClientPluginAuthLenenc)
	db := CredParam(ep, CredParamDatabase, "")
	if db != "" {
		flags |= mysqlClientConnectWithDB
	}
	if g.capabilities&mysqlClientSSL != 0 {
		// 服务端支持 TLS 就走 TLS：caching_sha2 的完整认证在明文信道上要靠服务端 RSA 公钥，
		// 而把口令明文发出去的风险与公钥那套复杂度相比，TLS 更值得。
		if err = w.mysqlStartTLS(ctx, flow, credAddr(ep), flags, cred, db); err != nil {
			res.Outcome = CredInconclusive
			res.Reason = "服务端支持 TLS 但握手没起来：" + err.Error()
			return res, nil
		}
		res.TLS = true
	}
	if err = flow.write(mysqlHandshakePayload(cred, db, plugin, scramble, flags, res.TLS)); err != nil {
		return res.withErr(err)
	}

	for {
		rp, err := flow.read()
		if err != nil {
			return res.withErr(err)
		}
		if len(rp.payload) == 0 {
			res.Outcome = CredInconclusive
			res.Reason = "收到零长度报文，认证握手无法继续"
			return res, nil
		}
		switch {
		// OK 包：首字节 0x00 且长度够（影响行数 + 插入 id + 状态 + 告警）。
		// 不用序号判断——认证切换与 AuthMoreData 之后序号会连续变化，写死了会把 OK 看成未知包。
		case rp.payload[0] == 0x00 && len(rp.payload) >= 5:
			res.Outcome = CredHit
			return res, nil
		case rp.payload[0] == 0xff:
			return classifyMySQLError(res, rp.payload), nil
		case rp.payload[0] == 0xfe:
			next, sc, err2 := mysqlParseAuthSwitch(rp.payload)
			if err2 != nil {
				res.Outcome = CredUnsupported
				res.Reason = err2.Error()
				return res, nil
			}
			plugin, scramble = next, sc
			res.Banner = "MySQL " + g.serverVersion + " · 切换到认证插件 " + plugin
			if err = flow.write(mysqlAuthData(plugin, cred, scramble, res.TLS)); err != nil {
				return res.withErr(err)
			}
		case rp.payload[0] == 0x01 && len(rp.payload) >= 2:
			switch rp.payload[1] {
			case 0x03: // caching_sha2 快速通道成功，后面紧跟 OK
				continue
			case 0x04: // 需要完整认证
				if res.TLS {
					if err = flow.write(append([]byte(cred.Password), 0)); err != nil {
						return res.withErr(err)
					}
					continue
				}
				if err = mysqlFullAuthWithPublicKey(flow, cred, scramble); err != nil {
					res.Outcome = CredInconclusive
					res.Reason = "caching_sha2 完整认证没走完：" + err.Error()
					return res, nil
				}
			default:
				res.Outcome = CredInconclusive
				res.Reason = "收到未预期的认证附加数据 0x" + strconv.FormatUint(uint64(rp.payload[1]), 16)
				return res, nil
			}
		default:
			res.Outcome = CredInconclusive
			res.Reason = "认证回复包首字节 0x" + strconv.FormatUint(uint64(rp.payload[0]), 16) + " 无法判定"
			return res, nil
		}
	}
}

// mysqlFlow 管包序号。服务端每发一包，下一包就得是它的序号 +1；客户端连发两包
// （SSL 请求与握手响应）时自己递增。写死序号在认证切换之后会撞车——MySQL 用
// 1156 "Got packets out of order" 回你，那是我们的错，不该写成目标的行为。
type mysqlFlow struct {
	w   *credWire
	seq byte
}

func (f *mysqlFlow) read() (mysqlPacket, error) {
	p, err := mysqlReadPacket(f.w)
	if err != nil {
		return p, err
	}
	f.seq = p.packetNum + 1
	return p, nil
}

func (f *mysqlFlow) write(payload []byte) error {
	if err := mysqlWritePacket(f.w, f.seq, payload); err != nil {
		return err
	}
	f.seq++
	return nil
}

type mysqlGreeting struct {
	serverVersion string
	scramble      []byte
	authPlugin    string
	capabilities  uint32
}

// mysqlPacket 是一条 MySQL 报文：3 字节长度 + 1 字节序号 + 载荷。
type mysqlPacket struct {
	packetNum byte
	payload   []byte
}

func mysqlReadPacket(w *credWire) (mysqlPacket, error) {
	hdr, err := w.readN(4)
	if err != nil && len(hdr) < 4 {
		return mysqlPacket{}, err
	}
	size := int(uint32(hdr[0]) | uint32(hdr[1])<<8 | uint32(hdr[2])<<16)
	if size <= 0 {
		return mysqlPacket{}, fmt.Errorf("MySQL 报文长度非法: %d", size)
	}
	body, err := w.readN(size)
	if err != nil && len(body) < size {
		return mysqlPacket{}, err
	}
	return mysqlPacket{packetNum: hdr[3], payload: body[:size]}, nil
}

func mysqlWritePacket(w *credWire, num byte, payload []byte) error {
	hdr := []byte{byte(len(payload)), byte(len(payload) >> 8), byte(len(payload) >> 16), num}
	return w.write(append(hdr, payload...))
}

// mysqlParseGreeting 解协议版本 10 的首发问候包。字段是变长的，所以每一步都要检查
// 剩余长度——截断的 banner 不能猜出「支持某插件」这种结论。
func mysqlParseGreeting(b []byte) (*mysqlGreeting, error) {
	if len(b) < 2 || b[0] != 0x0a {
		return nil, errors.New("不是 MySQL 协议版本 10 的问候包")
	}
	end := bytes.IndexByte(b, 0)
	if end < 0 {
		return nil, errors.New("问候包缺服务端版本结束符")
	}
	g := &mysqlGreeting{serverVersion: string(b[1:end])}
	pos := end + 1
	if pos+4+8+1 > len(b) {
		return nil, errors.New("问候包长度不足")
	}
	pos += 4 // connection id
	salt1 := b[pos : pos+8]
	pos += 8 + 1
	var capsLow uint32
	if pos+2 <= len(b) {
		capsLow = uint32(binary.LittleEndian.Uint16(b[pos : pos+2]))
		pos += 2
	}
	g.capabilities = capsLow
	var salt2 []byte
	var plugin string
	if capsLow&mysqlClientProtocol41 != 0 {
		if pos+6 > len(b) {
			return nil, errors.New("问候包在协议 4.1 字段处被截断")
		}
		pos += 1 + 2 + 2
		g.capabilities |= uint32(binary.LittleEndian.Uint16(b[pos-2:pos])) << 16
		pluginDataLen := 0
		if g.capabilities&mysqlClientPluginAuth != 0 {
			if pos >= len(b) {
				return nil, errors.New("问候包缺认证插件数据长度")
			}
			pluginDataLen = int(b[pos])
			pos++
		}
		pos += 10 // 保留
		if g.capabilities&mysqlClientSecureConnection != 0 {
			want := 12
			if pluginDataLen > 12 {
				want = pluginDataLen - 8
			}
			if pos+want <= len(b) {
				salt2 = b[pos : pos+want]
				pos += want
			}
		}
		if g.capabilities&mysqlClientPluginAuth != 0 && pos < len(b) {
			if e := bytes.IndexByte(b[pos:], 0); e >= 0 {
				plugin = string(b[pos : pos+e])
			} else {
				plugin = string(b[pos:])
			}
		}
	}
	salt := append(append([]byte{}, salt1...), salt2...)
	if len(salt) > 20 {
		salt = salt[:20] // 协议把 20 字节 salt 拆成 8+12，多余部分是保留位
	}
	g.scramble, g.authPlugin = salt, plugin
	return g, nil
}

// mysqlHandshakePayload 拼 HandshakeResponse41。
func mysqlHandshakePayload(cred Credential, db, plugin string, scramble []byte, flags uint32, withTLS bool) []byte {
	var b bytes.Buffer
	var caps [4]byte
	binary.LittleEndian.PutUint32(caps[:], flags)
	b.Write(caps[:])
	var maxPkt [4]byte
	binary.LittleEndian.PutUint32(maxPkt[:], mysqlMaxPacket)
	b.Write(maxPkt[:])
	b.WriteByte(0x2d) // utf8_general_ci：认证阶段字符集不影响口令字节
	b.Write(make([]byte, 23))
	b.WriteString(cred.Username)
	b.WriteByte(0)
	data := mysqlAuthData(plugin, cred, scramble, withTLS)
	b.WriteByte(byte(len(data)))
	b.Write(data)
	if db != "" {
		b.WriteString(db)
		b.WriteByte(0)
	}
	if plugin != "" {
		b.WriteString(plugin)
		b.WriteByte(0)
	}
	return b.Bytes()
}

// mysqlAuthData 按插件算应答。TLS 与否只对 clear_password 有意义：明文信道下发裸口令
// 是服务端插件自己要求的，本平台照做但在结论里会标出这条信道是明文。
func mysqlAuthData(plugin string, cred Credential, scramble []byte, tlsOn bool) []byte {
	switch plugin {
	case "mysql_native_password", "":
		return nativeScramble(cred.Password, scramble)
	case "caching_sha2_password":
		return sha256Scramble(cred.Password, scramble)
	case "sha256_password", "mysql_clear_password":
		return append([]byte(cred.Password), 0)
	default:
		return nil
	}
}

// nativeScramble = SHA1(pass) XOR SHA1(salt + SHA1(SHA1(pass)))。
func nativeScramble(password string, salt []byte) []byte {
	if password == "" {
		return nil
	}
	a := sha1Sum([]byte(password))
	b := sha1Sum(a)
	c := sha1Sum(append(append([]byte{}, salt...), b...))
	out := make([]byte, len(a))
	for i := range a {
		out[i] = a[i] ^ c[i]
	}
	return out
}

// sha256Scramble = XOR(SHA256(pass), SHA256(SHA256(SHA256(pass)) + salt))。
func sha256Scramble(password string, salt []byte) []byte {
	if password == "" {
		return []byte{0}
	}
	x := sha256Sum([]byte(password))
	y := sha256Sum(x)
	z := sha256Sum(append(append([]byte{}, y...), salt...))
	out := make([]byte, len(x))
	for i := range x {
		out[i] = x[i] ^ z[i]
	}
	return out
}

func sha1Sum(b []byte) []byte { h := sha1.Sum(b); return h[:] }

func sha256Sum(b []byte) []byte { h := sha256.Sum256(b); return h[:] }

// mysqlFullAuthWithPublicKey 走 caching_sha2 的完整通道（明文信道上唯一可行的做法）：
// 要服务端 RSA 公钥，把「口令逐字节 XOR salt（循环）」的结果用 OAEP-SHA1 加密后回过去。
func mysqlFullAuthWithPublicKey(flow *mysqlFlow, cred Credential, salt []byte) error {
	if err := flow.write([]byte{0x02}); err != nil { // 请求服务端 RSA 公钥
		return err
	}
	rp, err := flow.read()
	if err != nil {
		return err
	}
	if rp.payload[0] != 0x01 {
		return fmt.Errorf("要公钥却回了 0x%x", rp.payload[0])
	}
	keyPEM := bytes.TrimRight(rp.payload[1:], "\x00")
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return errors.New("服务端公钥不是合法 PEM")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return err
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return errors.New("服务端公钥不是 RSA")
	}
	// 完整认证：口令逐字节 XOR salt（循环），补 NUL，再 OAEP(SHA-1) 加密。
	plain := append([]byte(cred.Password), 0)
	if len(salt) > 0 {
		for i := range plain {
			plain[i] ^= salt[i%len(salt)]
		}
	}
	enc, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, rsaPub, plain, nil)
	if err != nil {
		return err
	}
	return flow.write(enc)
}

// mysqlStartTLS 按协议先发 32 字节的 SSL 请求包（只到字符集那一段），再升 TLS，
// 之后的握手响应走加密信道。序号必须接上，不然服务端直接断。
func (w *credWire) mysqlStartTLS(ctx context.Context, flow *mysqlFlow, addr string, flags uint32, cred Credential, db string) error {
	req := mysqlHandshakePayload(cred, db, "", nil, flags|mysqlClientSSL, true)
	if len(req) < 32 {
		return errors.New("SSL 请求包长度不足 32 字节")
	}
	// SSLRequest 只发到字符集那一段（32 字节）为止；升 TLS 之后的握手响应
	// 必须由客户端接着往上递增序号，flow.write 已经把它记下了。
	if err := flow.write(req[:32]); err != nil {
		return err
	}
	return w.upgradeTLS(ctx, hostOnly(addr))
}

// classifyMySQLError 按错误号分派。1045 是口令/账号不对，1129 是来源被限流封禁，
// 1040 是连接数打满——三种在报告里必须是三种话。
func classifyMySQLError(res CredAttempt, payload []byte) CredAttempt {
	num, text := mysqlErrNo(payload), mysqlErrText(payload)
	res.Banner = text
	switch {
	case num == 1129 || num == 1045 && strings.Contains(strings.ToLower(text), "blocked"):
		res.Outcome = CredLocked
		res.Reason = "来源因连续失败被封，已停手"
	case strings.Contains(strings.ToLower(text), "account is locked"),
		strings.Contains(strings.ToLower(text), "locked"):
		res.Outcome = CredLocked
		res.Reason = "服务端提示账号锁定，已停手"
	case num == 1040, num == 1203:
		res.Outcome = CredInconclusive
		res.Reason = "连接数或用户连接上限：" + text
	case num == 1045 || num == 1022 || num == 28 || strings.HasPrefix(text, "Access denied"):
		res.Outcome = CredDeny
	case num == 1044 || num == 1049:
		res.Outcome = CredInconclusive
		res.Reason = "库或权限层面被拒，认证结论没走到：" + text
	default:
		res.Outcome = CredInconclusive
		res.Reason = "服务端错误 " + strconv.Itoa(num) + "：" + text
	}
	return res
}

// mysqlErrNo 取错误号。协议 4.1 之后是 ERR + 2 字节号 + '#' + 5 字节 SQLSTATE + 文本。
func mysqlErrNo(payload []byte) int {
	if len(payload) < 3 {
		return -1
	}
	return int(binary.LittleEndian.Uint16(payload[1:3]))
}

func mysqlErrText(payload []byte) string {
	if len(payload) < 3 {
		return ""
	}
	msg := string(payload[3:])
	if len(payload) > 8 && payload[3] == '#' {
		msg = string(payload[9:])
	}
	return strings.TrimSpace(msg)
}

// mysqlParseAuthSwitch 解 0xFE 认证切换请求：插件名 + 下一个 salt。
func mysqlParseAuthSwitch(payload []byte) (string, []byte, error) {
	rest := payload[1:]
	end := bytes.IndexByte(rest, 0)
	if end < 0 {
		return "", nil, errors.New("认证切换包缺插件名结束符")
	}
	plugin := string(rest[:end])
	if !mysqlPluginKnown(plugin) {
		return plugin, nil, fmt.Errorf("%w：服务端切换到 %s", errUnsupportedAuth, plugin)
	}
	salt := rest[end+1:]
	if n := bytes.IndexByte(salt, 0); n >= 0 {
		salt = salt[:n]
	}
	if len(salt) > 20 {
		salt = salt[:20]
	}
	return plugin, salt, nil
}

func mysqlPluginKnown(plugin string) bool {
	switch plugin {
	case "mysql_native_password", "caching_sha2_password", "sha256_password", "mysql_clear_password", "":
		return true
	}
	return false
}

func init() { RegisterCredAdapter(mysqlCredAdapter{}) }
