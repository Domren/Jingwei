package scanner

import (
	"encoding/binary"
	"net"
	"strconv"
	"strings"
	"testing"
)

// pgFake 是进程内的 PostgreSQL 靶子：按脚本回一组后端报文。
// SCRAM 不在这里测——PG 16 默认就是 scram-sha-256，真库跑一次比在这儿重写一遍
// 服务端数学更有说服力（也更不会测出一个只有自己认得的实现）。
type pgFake struct {
	messages []pgPacket // 服务端要依次发出的报文
	sslReply byte       // 'S' 或 'N'
}

func (f pgFake) serve(c net.Conn) {
	// 客户端先给 SSLRequest（8 字节），回一个字节；然后 StartupMessage，之后按脚本发。
	hdr := make([]byte, 8)
	if _, err := readFully(c, hdr); err != nil {
		return
	}
	if _, err := c.Write([]byte{f.sslReply}); err != nil {
		return
	}
	startup := make([]byte, 4)
	if _, err := readFully(c, startup); err != nil {
		return
	}
	size := int(binary.BigEndian.Uint32(startup))
	rest := make([]byte, size-4)
	if _, err := readFully(c, rest); err != nil {
		return
	}
	for _, p := range f.messages {
		body := make([]byte, 0, len(p.body)+5)
		body = append(body, p.typ)
		body = binary.BigEndian.AppendUint32(body, uint32(len(p.body)+4))
		body = append(body, p.body...)
		if _, err := c.Write(body); err != nil {
			return
		}
		// 客户端可能回一个 'p' 包（口令/md5/SCRAM），读掉它，让脚本能继续发下一条。
		if p.typ == 'R' && (pgAuthType(p) == 3 || pgAuthType(p) == 5 || pgAuthType(p) == 10 || pgAuthType(p) == 11) {
			_, _ = pgReadPacketFrom(c)
		}
	}
}

func pgAuthBody(typ int, extra ...byte) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, uint32(typ))
	return append(b, extra...)
}

// pgErrBody 按线上格式拼 ErrorResponse：每个字段是「1 字节标签 + NUL 结尾字符串」，
// 标签与文本之间没有 NUL，整个列表再以一个裸 NUL 结束。
func pgErrBody(code, msg string) []byte {
	var b strings.Builder
	for _, f := range []struct{ tag, text string }{{"S", "FATAL"}, {"C", code}, {"M", msg}} {
		b.WriteByte(f.tag[0])
		b.WriteString(f.text)
		b.WriteByte(0)
	}
	b.WriteByte(0)
	return []byte(b.String())
}

func readFully(c net.Conn, b []byte) (int, error) {
	total := 0
	for total < len(b) {
		n, err := c.Read(b[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

func pgReadPacketFrom(c net.Conn) (pgPacket, error) {
	hdr := make([]byte, 5)
	if _, err := readFully(c, hdr); err != nil {
		return pgPacket{}, err
	}
	size := int(binary.BigEndian.Uint32(hdr[1:5]))
	body := make([]byte, size-4)
	if size > 4 {
		if _, err := readFully(c, body); err != nil {
			return pgPacket{typ: hdr[0]}, err
		}
	}
	return pgPacket{typ: hdr[0], body: body}, nil
}

func newPGFake(t *testing.T, f pgFake) *credTestEndpoint {
	t.Helper()
	return newCredTestEndpoint(t, f.serve)
}

func pgEndpoint(addr string) CredEndpoint {
	host, portStr, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(portStr)
	return CredEndpoint{Host: host, Port: port, Protocol: "postgresql", ProtocolConfirmed: true}
}

func TestCredPostgresIdentify(t *testing.T) {
	ep := newPGFake(t, pgFake{
		sslReply: 'N',
		messages: []pgPacket{{typ: 'E', body: pgErrBody("28000", `no pg_hba.conf entry for host "127.0.0.1", user "jw_probe_nonexistent", database "postgres", no encryption`)}},
	})
	ok, banner, err := pgCredAdapter{}.Identify(credCtx(t), pgEndpoint(ep.addr))
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatalf("结构合法的 PG 错误报文必须确认成 PostgreSQL: %q", banner)
	}
	if !strings.Contains(banner, "PostgreSQL") || !strings.Contains(banner, "pg_hba") {
		t.Fatalf("banner = %q", banner)
	}
	t.Run("不是 PG 的端口不能靠 S/N 冒充", func(t *testing.T) {
		bad := newCredTestEndpoint(t, func(c net.Conn) { writeString(c, "NNNNNNNNHTTP/1.1 200 OK\r\n\r\n") })
		ok, _, _ := pgCredAdapter{}.Identify(credCtx(t), pgEndpoint(bad.addr))
		if ok {
			t.Fatal("以 N 开头的 HTTP banner 被认成了 PG")
		}
	})
}

func TestCredPostgresMd5(t *testing.T) {
	salt := []byte{0x11, 0x22, 0x33, 0x44}
	t.Run("md5 口令正确", func(t *testing.T) {
		want := pgMD5Scramble("pass123", "jingwei", salt)
		ep := newPGFake(t, pgFake{sslReply: 'N', messages: []pgPacket{
			{typ: 'R', body: pgAuthBody(5, salt...)},
			{typ: 'R', body: pgAuthBody(0)},
			{typ: 'S', body: []byte("server_version\x0016.4\x00")},
			{typ: 'Z', body: []byte("I")},
		}})
		res, _ := pgCredAdapter{}.Try(credCtx(t), pgEndpoint(ep.addr), Credential{Username: "jingwei", Password: "pass123"})
		if res.Outcome != CredHit {
			t.Fatalf("res = %+v", res)
		}
		sent := strings.Join(ep.requests(), "")
		if !strings.Contains(sent, want) {
			t.Fatalf("md5 应答算错了：期望 %q，实际发出 %q", want, sent)
		}
	})
	t.Run("md5 口令错误", func(t *testing.T) {
		ep := newPGFake(t, pgFake{sslReply: 'N', messages: []pgPacket{
			{typ: 'R', body: pgAuthBody(5, salt...)},
			{typ: 'E', body: pgErrBody("28P01", "password authentication failed for user \"jingwei\"")},
		}})
		res, _ := pgCredAdapter{}.Try(credCtx(t), pgEndpoint(ep.addr), Credential{Username: "jingwei", Password: "wrong"})
		if res.Outcome != CredDeny {
			t.Fatalf("res = %+v", res)
		}
	})
}

// 库不存在、pg_hba 没放行、连接数打满——三种都不是「这组口令不行」。
// 这一组断言是模块能不能进报告的关键：写成 deny 就等于宣称已经排除过这些口令。
func TestCredPostgresNonCredentialErrors(t *testing.T) {
	salt := []byte{1, 2, 3, 4}
	cases := []struct {
		code, msg, wantContains string
	}{
		{"3D000", `database "jingwei" does not exist`, "数据库不可用"},
		{"28000", `no pg_hba.conf entry for host "127.0.0.1"`, "pg_hba"},
		{"53300", `too many connections for role "jingwei"`, "连接数"},
	}
	for _, tc := range cases {
		t.Run(tc.code, func(t *testing.T) {
			ep := newPGFake(t, pgFake{sslReply: 'N', messages: []pgPacket{
				{typ: 'R', body: pgAuthBody(5, salt...)},
				{typ: 'E', body: pgErrBody(tc.code, tc.msg)},
			}})
			res, _ := pgCredAdapter{}.Try(credCtx(t), pgEndpoint(ep.addr), Credential{Username: "jingwei", Password: "x"})
			if res.Outcome != CredInconclusive {
				t.Fatalf("必须是不可判定: %+v", res)
			}
			if !strings.Contains(res.Reason, tc.wantContains) {
				t.Fatalf("原因要点名成因: %q", res.Reason)
			}
		})
	}
}

func TestCredPostgresTrust(t *testing.T) {
	t.Run("trust 下空口令是命中", func(t *testing.T) {
		ep := newPGFake(t, pgFake{sslReply: 'N', messages: []pgPacket{
			{typ: 'R', body: pgAuthBody(0)},
			{typ: 'Z', body: []byte("I")},
		}})
		res, _ := pgCredAdapter{}.Try(credCtx(t), pgEndpoint(ep.addr), Credential{Username: "jingwei"})
		if res.Outcome != CredHit {
			t.Fatalf("res = %+v", res)
		}
		if !strings.Contains(res.Evidence(), "trust") {
			t.Fatalf("要说明命中来自 trust 配置而不是这组口令: %s", res.Evidence())
		}
	})
	t.Run("trust 下非空口令不能算命中", func(t *testing.T) {
		ep := newPGFake(t, pgFake{sslReply: 'N', messages: []pgPacket{
			{typ: 'R', body: pgAuthBody(0)},
		}})
		res, _ := pgCredAdapter{}.Try(credCtx(t), pgEndpoint(ep.addr), Credential{Username: "jingwei", Password: "猜的"})
		if res.Outcome == CredHit {
			t.Fatalf("trust 根本没校验口令: %+v", res)
		}
		if res.Outcome != CredInconclusive {
			t.Fatalf("应记不可判定: %+v", res)
		}
	})
}

func TestCredPostgresCleartext(t *testing.T) {
	ep := newPGFake(t, pgFake{sslReply: 'N', messages: []pgPacket{
		{typ: 'R', body: pgAuthBody(3)},
		{typ: 'R', body: pgAuthBody(0)},
	}})
	res, _ := pgCredAdapter{}.Try(credCtx(t), pgEndpoint(ep.addr), Credential{Username: "u", Password: "hunter2"})
	if res.Outcome != CredHit {
		t.Fatalf("res = %+v", res)
	}
	// PasswordMessage：'p' + 长度(4+7+1) + 口令 + NUL。字节错了服务端只会说认证失败，
	// 而不是「这个包形不对」，所以这里必须按字节断言。
	if want := "\x70\x00\x00\x00\x0chunter2\x00"; !strings.Contains(strings.Join(ep.requests(), ""), want) {
		t.Fatalf("cleartext 报文形状不对: %q", ep.requests())
	}
}

func TestCredPostgresUnknownSASLMech(t *testing.T) {
	ep := newPGFake(t, pgFake{sslReply: 'N', messages: []pgPacket{
		{typ: 'R', body: append(pgAuthBody(10), []byte("SCRAM-SHA-256-PLUS\x00GSSAPI\x00\x00")...)},
	}})
	res, _ := pgCredAdapter{}.Try(credCtx(t), pgEndpoint(ep.addr), Credential{Username: "u", Password: "p"})
	if res.Outcome != CredUnsupported {
		t.Fatalf("认不出的机制要报不支持，不能报拒绝: %+v", res)
	}
	if !strings.Contains(res.Reason, "SCRAM-SHA-256-PLUS") {
		t.Fatalf("要写清服务端只提供了什么: %q", res.Reason)
	}
}
