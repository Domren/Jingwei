package scanner

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

// PostgreSQL 认证探针：trust / cleartext / md5 / SCRAM-SHA-256 / SCRAM-SHA-1。
//
// md5 与 SHA-1 在这里是被协议要求的，不是本平台的选型——服务端说用哪种就得算哪种，
// 换成「更现代的哈希」只会得到一句 authentication failed 和一条假结论。
//
// 库名挂在端点参数上（CredParamDatabase）：库不存在与口令错是两件事，压成同一句
// 「认证失败」会让报告把没测出来的东西说成测过了。
type pgCredAdapter struct{}

func (pgCredAdapter) Protocol() string { return "postgresql" }

const (
	pgProtocolVersion3 = 196608
	pgSSLRequestCode   = 80877103
	pgDefaultDatabase  = "postgres"
	// pgProbeUser 只用于 Identify：明显不存在的账号，服务端一定在认证阶段就拒掉，
	// 所以这条探测既不留会话，也碰不到任何真实账号的口令策略。
	pgProbeUser = "jw_probe_nonexistent"
)

// Identify 先发 SSLRequest，再用一个不存在的账号发 StartupMessage。
// 只看 SSLRequest 的回音（单个 'S'/'N' 字节）不足以定性——任何以 N 开头的 banner 都能冒充；
// 要的是「一个结构合法的 PG 后端报文」。
func (a pgCredAdapter) Identify(ctx context.Context, ep CredEndpoint) (bool, string, error) {
	w, err := credDial(ctx, credAddr(ep))
	if err != nil {
		return false, "", err
	}
	defer w.close()
	sslSupported, err := pgAskSSL(w)
	if err != nil {
		return false, "", err
	}
	if sslSupported {
		// 服务端答应升 TLS 之后就必须真的升上去：PostgreSQL 在收到 'S' 之后只在加密通道上
		// 接受 StartupMessage，明文发过去会被直接断开——真机验证（服务端开了 SSL）就是这么
		// 把「Identify 只报了 unexpected EOF，而 Try 却认证成功」这条不一致暴露出来的。
		if err = w.upgradeTLS(ctx, hostOnly(credAddr(ep))); err != nil {
			return false, "PostgreSQL · 服务端要求 TLS，但握手没起来：" + err.Error(), nil
		}
	}
	if err := pgWriteStartup(w, pgProbeUser, pgDefaultDatabase, false); err != nil {
		return false, "", err
	}
	p, err := pgReadPacket(w)
	if err != nil {
		return false, "", err
	}
	switch p.typ {
	case 'R', 'E', 'N', 'Z':
		return true, "PostgreSQL" + pgSSLNote(sslSupported) + " · " + pgBanner(p), nil
	default:
		return false, credPreview(w.resp), nil
	}
}

func (a pgCredAdapter) Try(ctx context.Context, ep CredEndpoint, cred Credential) (res CredAttempt, err error) {
	res = credNewAttempt(cred)
	w, err := credDial(ctx, credAddr(ep))
	if err != nil {
		return res.withErr(err)
	}
	defer w.close()
	defer func() { res.syncWire(w) }()

	sslSupported, err := pgAskSSL(w)
	if err != nil {
		return res.withErr(err)
	}
	if sslSupported {
		// 跳过证书校验：目标数据库的 CA 不可能预装在这台机器上，而把明文口令发给一个
		// 没验证过身份的对端更糟。SCRAM 的服务端签名校验才是真正的防线。
		if err = w.upgradeTLS(ctx, hostOnly(credAddr(ep))); err != nil {
			res.Outcome = CredInconclusive
			res.Reason = "服务端要求 TLS，但握手没起来：" + err.Error()
			return res, nil
		}
		res.TLS = true
	}
	db := CredParam(ep, CredParamDatabase, pgDefaultDatabase)
	if err = pgWriteStartup(w, cred.Username, db, true); err != nil {
		return res.withErr(err)
	}

	var sasl *pgSASL
	var passwordSent bool
	for {
		p, err := pgReadPacket(w)
		if err != nil {
			return res.withErr(err)
		}
		switch p.typ {
		case 'E':
			return classifyPGError(res, p)
		case 'R':
			switch t := pgAuthType(p); t {
			case 0:
				if sasl != nil && !sasl.signatureValid() {
					// 口令已经发出去了但对端算不回正确的签名：不能报命中。
					res.Outcome = CredInconclusive
					res.Reason = "SCRAM 服务端签名校验不过：对端身份无法确认，不据此下结论"
					return res, nil
				}
				if !passwordSent {
					// 什么都没发就通过 = trust。可用的是「这个账号不需要口令」，
					// 不是手上这组口令；写成命中会把配置问题报成口令问题。
					if strings.TrimSpace(cred.Password) == "" {
						res.Outcome = CredHit
						res.Reason = "服务端对该来源配置为 trust，该账号无需口令即可登录"
						return res, nil
					}
					res.Outcome = CredInconclusive
					res.Reason = "服务端配置为 trust：口令从未被校验，这组口令的有效性无从判定"
					return res, nil
				}
				res.Outcome = CredHit
				return res, nil
			case 3:
				passwordSent = true
				if err = pgWritePasswordPacket(w, cred.Password); err != nil {
					return res.withErr(err)
				}
			case 5:
				passwordSent = true
				if len(p.body) < 8 {
					res.Outcome = CredInconclusive
					res.Reason = "md5 认证报文里没有 4 字节 salt"
					return res, nil
				}
				salt := p.body[len(p.body)-4:]
				if err = pgWritePasswordPacket(w, pgMD5Scramble(cred.Password, cred.Username, salt)); err != nil {
					return res.withErr(err)
				}
			case 10:
				sasl, err = newPgSASL(p.body[4:], cred)
				if err != nil {
					if isCredUnsupported(err) {
						res.Outcome = CredUnsupported
						res.Reason = err.Error()
						return res, nil
					}
					return res.withErr(err)
				}
				passwordSent = true
				if err = pgWriteSASLInit(w, sasl.mech, sasl.clientFirstBare()); err != nil {
					return res.withErr(err)
				}
			case 11:
				if sasl == nil {
					res.Outcome = CredInconclusive
					res.Reason = "没发过 SASL 初始化就收到 SASLContinue，握手状态无法继续"
					return res, nil
				}
				if sasl.serverFirst != "" {
					res.Outcome = CredInconclusive
					res.Reason = "收到第二条 SASLContinue，握手状态无法继续"
					return res, nil
				}
				final, err := sasl.handleServerFirst(string(p.body[4:]))
				if err != nil {
					res.Outcome = CredInconclusive
					res.Reason = "SCRAM 服务端第一条消息不可用：" + err.Error()
					return res, nil
				}
				// client-final 同样是按字节计长，不补 NUL（抓 libpq 的包确认的）。
				if err = pgWritePacket(w, 'p', []byte(final)); err != nil {
					return res.withErr(err)
				}
			case 12:
				if sasl == nil {
					res.Outcome = CredInconclusive
					res.Reason = "收到 SASLFinal 但没有 SCRAM 会话"
					return res, nil
				}
				sasl.handleServerFinal(string(p.body[4:]))
			default:
				res.Outcome = CredUnsupported
				res.Reason = "服务端要求的认证类型 " + strconv.Itoa(t) + " 本平台不实现"
				return res, nil
			}
		case 'S', 'K', 'Z', 'N', 'T', 'A', 'D':
			// 参数状态、取消密钥、就绪、通知：都不改判定，继续读下一个后端报文。
		default:
			res.Outcome = CredInconclusive
			res.Reason = "启动阶段收到未知后端报文类型 " + string(p.typ)
			return res, nil
		}
	}
}

// classifyPGError 按 SQLSTATE 分派。码是唯一可靠的依据：消息文案随版本与语言变，
// 而「口令错」「库不存在」「没配 pg_hba」在报告里必须是三种不同的话。
func classifyPGError(res CredAttempt, p pgPacket) (CredAttempt, error) {
	code, msg := pgError(p)
	res.Banner = msg
	switch {
	case code == "28P01" || code == "28P00":
		res.Outcome = CredDeny
	case code == "28000":
		res.Outcome = CredInconclusive
		res.Reason = "服务端未允许该来源或认证方式（pg_hba），与凭据无关：" + msg
	case code == "3D000", code == "3F000":
		res.Outcome = CredInconclusive
		res.Reason = "数据库不可用，认证结论没走到：" + msg
	case code == "53300", code == "53400", code == "08006":
		res.Outcome = CredInconclusive
		res.Reason = "连接数或会话状态限制：" + msg
	case credLockedText(strings.ToLower(msg)):
		res.Outcome = CredLocked
		res.Reason = "服务端提示账号锁定或来源限流，已停手"
	default:
		res.Outcome = CredInconclusive
		res.Reason = "启动阶段收到未预期错误（" + code + "）：" + msg
	}
	return res, nil
}

// ── 报文读写 ─────────────────────────────────────────────────────────────────

type pgPacket struct {
	typ  byte
	body []byte
}

// pgAskSSL 发 SSLRequest（8 字节、不含任何凭据）并读一个字节。
// 'S' 表示支持 TLS，'N' 表示只能明文；别的字节说明对面不是 PostgreSQL。
func pgAskSSL(w *credWire) (bool, error) {
	req := make([]byte, 8)
	binary.BigEndian.PutUint32(req[0:4], 8)
	binary.BigEndian.PutUint32(req[4:8], pgSSLRequestCode)
	if err := w.write(req); err != nil {
		return false, err
	}
	raw, err := w.readN(1)
	if err != nil && len(raw) == 0 {
		return false, err
	}
	switch raw[0] {
	case 'S':
		return true, nil
	case 'N':
		return false, nil
	default:
		return false, fmt.Errorf("%w：SSLRequest 回了 %q，不是 PostgreSQL 的 S/N 应答",
			errUnsupportedAuth, string(raw[0]))
	}
}

// pgReadPacket 读一个后端报文：类型字节 + 4 字节长度（含长度自身）+ 载荷。
func pgReadPacket(w *credWire) (pgPacket, error) {
	hdr, err := w.readN(5)
	if err != nil && len(hdr) < 5 {
		return pgPacket{}, err
	}
	p := pgPacket{typ: hdr[0]}
	size := int(binary.BigEndian.Uint32(hdr[1:5]))
	if size < 4 {
		return p, fmt.Errorf("PG 报文长度非法: %d", size)
	}
	body := make([]byte, size-4)
	if size > 4 {
		got, err := w.readN(size - 4)
		if err != nil && len(got) < size-4 {
			return p, err
		}
		copy(body, got)
	}
	p.body = body
	return p, nil
}

func pgWriteStartup(w *credWire, user, db string, withAppName bool) error {
	var b bytes.Buffer
	var ver [4]byte
	binary.BigEndian.PutUint32(ver[:], pgProtocolVersion3)
	b.Write(ver[:])
	fields := [][2]string{{"user", user}, {"database", db}}
	if withAppName {
		fields = append(fields, [2]string{"application_name", "jingwei"})
	}
	for _, kv := range fields {
		b.WriteString(kv[0])
		b.WriteByte(0)
		b.WriteString(kv[1])
		b.WriteByte(0)
	}
	b.WriteByte(0)
	return pgWritePacket(w, 0, b.Bytes())
}

func pgWritePasswordPacket(w *credWire, payload string) error {
	return pgWritePacket(w, 'p', append([]byte(payload), 0))
}

// pgWriteSASLInit 是 SASLInitialResponse：机制名 + 4 字节长度 + client-first。
// 长度给 -1 会被服务端按「没有数据」处理，那样 SCRAM 永远走不完。
func pgWriteSASLInit(w *credWire, mech, clientFirstBare string) error {
	// 长度字段按抓包对齐：机制名以 NUL 结尾，其后的 client-first 是「按字节计长的块」，
	// 块里不再补 NUL。给 client-first 补 NUL 会被 PG 判成 08P01 malformed SCRAM message
	// （真机验证抓出来的：口令已经发出去了，客户端却连认证都没完成）。
	body := []byte(mech + "\x00")
	body = binary.BigEndian.AppendUint32(body, uint32(len(clientFirstBare)+3))
	body = append(body, "n,,"...)
	body = append(body, clientFirstBare...)
	return pgWritePacket(w, 'p', body)
}

// pgWritePacket 加类型字节与长度；类型 0 是 StartupMessage（它没有类型字节）。
func pgWritePacket(w *credWire, typ byte, body []byte) error {
	out := make([]byte, 0, len(body)+8)
	if typ != 0 {
		out = append(out, typ)
	}
	out = binary.BigEndian.AppendUint32(out, uint32(len(body)+4))
	out = append(out, body...)
	return w.write(out)
}

func pgAuthType(p pgPacket) int {
	if len(p.body) < 4 {
		return -1
	}
	return int(binary.BigEndian.Uint32(p.body[:4]))
}

// pgError 取 SQLSTATE 与消息。没有码时返回 "-"，调用方据此落到不可判定而不是拒绝。
func pgError(p pgPacket) (code, msg string) {
	for _, field := range bytes.Split(p.body, []byte{0}) {
		if len(field) < 2 {
			continue
		}
		switch field[0] {
		case 'C':
			code = string(field[1:])
		case 'M':
			msg = string(field[1:])
		}
	}
	if code == "" {
		code = "-"
	}
	return code, strings.TrimSpace(msg)
}

func pgBanner(p pgPacket) string {
	if p.typ == 'E' {
		_, msg := pgError(p)
		return msg
	}
	return "认证类型 " + strconv.Itoa(pgAuthType(p))
}

func pgSSLNote(supported bool) string {
	if supported {
		return " · 支持 TLS"
	}
	return " · 仅明文"
}

// pgMD5Scramble = "md5" + hex(md5(hex(md5(password+user)) + salt))。
func pgMD5Scramble(password, user string, salt []byte) string {
	inner := md5.Sum([]byte(password + user))
	outer := md5.Sum(append([]byte(hex.EncodeToString(inner[:])), salt...))
	return "md5" + hex.EncodeToString(outer[:])
}

// hostOnly 从 host:port 取 host，给 TLS ServerName 用。
func hostOnly(addr string) string {
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			return strings.Trim(addr[:i], "[]")
		}
	}
	return addr
}

// upgradeTLS 把裸连接升成 TLS，之后的字节记录继续记**通道内**的明文：密文对读报告的人
// 没有信息量，而判定依据本来就是握手里的明文字段。TLS 这件事另记在 res.TLS 上，
// 复现方式因此不会被写成一条裸 socket 命令。
func (w *credWire) upgradeTLS(ctx context.Context, serverName string) error {
	tc := tls.Client(w.conn, &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	})
	hctx, cancel := context.WithTimeout(ctx, credAttemptTimeout)
	defer cancel()
	if err := tc.HandshakeContext(hctx); err != nil {
		return err
	}
	w.conn = tc
	return nil
}

// pgSASL 只负责「选机制 + 报文封装」，SCRAM 数学在 scram.go 里和 MongoDB 共用。
type pgSASL struct {
	scram       *scramClient
	mech        string
	serverFirst string
	serverFinal string
}

func newPgSASL(mechList []byte, cred Credential) (*pgSASL, error) {
	var mechs []string
	for _, m := range bytes.Split(mechList, []byte{0}) {
		if len(m) > 0 {
			mechs = append(mechs, string(m))
		}
	}
	s := &pgSASL{}
	for _, m := range mechs {
		switch m {
		case "SCRAM-SHA-256":
			s.mech = m
		case "SCRAM-SHA-1":
			s.mech = m
		}
		if s.mech != "" {
			break
		}
	}
	if s.mech == "" {
		return nil, fmt.Errorf("%w：服务端只提供 %s", errUnsupportedAuth, strings.Join(mechs, "/"))
	}
	hs := ScramSHA256
	if s.mech == "SCRAM-SHA-1" {
		hs = ScramSHA1
	}
	c, err := newScramClient(hs, cred.Password)
	if err != nil {
		return nil, err
	}
	s.scram = c
	return s, nil
}

// clientFirstBare：PG 的身份在 StartupMessage 里已经给过，SASL 的 client-first
// 因此必须带空用户名；这里再塞一次反而会被服务端当成格式错误。
func (s *pgSASL) clientFirstBare() string { return s.scram.FirstBare() }

func (s *pgSASL) handleServerFirst(msg string) (string, error) {
	s.serverFirst = msg
	return s.scram.HandleServerFirst(msg)
}

func (s *pgSASL) handleServerFinal(msg string) { s.serverFinal = msg }

// signatureValid 校验服务端签名。口令已经发出去了，不认回这个签名就等于把
// 「对面到底是不是那台库」交给一个没验证过的对象。
func (s *pgSASL) signatureValid() bool {
	if s.serverFinal == "" {
		return false
	}
	return s.scram.VerifyServerFinal(s.serverFinal)
}

func init() { RegisterCredAdapter(pgCredAdapter{}) }
