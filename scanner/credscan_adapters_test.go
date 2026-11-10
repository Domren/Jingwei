package scanner

import (
	"context"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// credTestEndpoint 是进程内的协议靶子。适配器分支只能靠可控的服务端逐条断言：
// 真实服务的拒绝措辞随版本变、也不给「恰好触发某条分类」的机会，那是真机验证要管的事，
// 不是单测能替代的。
type credTestEndpoint struct {
	addr string
	// got 收客户端发出的每一段字节（按到达顺序）。
	mu  sync.Mutex
	got [][]byte
}

func newCredTestEndpoint(t *testing.T, handler func(c net.Conn)) *credTestEndpoint {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ep := &credTestEndpoint{addr: ln.Addr().String()}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				rec := &recordingConn{Conn: c, ep: ep}
				handler(rec)
			}()
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		<-done
	})
	return ep
}

// recordingConn 把服务端看到的写入按顺序记下来：断言「适配器到底发了什么」比断言
// 它返回了什么更能说明协议实现对不对。
type recordingConn struct {
	net.Conn
	ep *credTestEndpoint
}

// Read 记录的是「服务端收到的字节」，也就是适配器真正发出去的东西。
// 记 Write 是反的：那会把靶子自己的回显当成请求，断言就永远在断言测试代码。
func (c *recordingConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		cp := append([]byte(nil), b[:n]...)
		c.ep.mu.Lock()
		c.ep.got = append(c.ep.got, cp)
		c.ep.mu.Unlock()
	}
	return n, err
}

// credEP 把一个靶子地址变成待测端点。协议名要显式给：Protocol 与 ProtocolConfirmed
// 决定引擎会不会先发 Identify，测试里必须能分别构造。
func credEP(addr, proto string) CredEndpoint {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		panic(err)
	}
	port, _ := strconv.Atoi(portStr)
	return CredEndpoint{Host: host, Port: port, Protocol: proto,
		ProtocolSource: CredProtocolSourceExplicit, ProtocolConfirmed: true}
}

func (ep *credTestEndpoint) requests() []string {
	ep.mu.Lock()
	defer ep.mu.Unlock()
	out := make([]string, 0, len(ep.got))
	for _, b := range ep.got {
		out = append(out, string(b))
	}
	return out
}

// writeString 是服务端往连接里写字节。
func writeString(c net.Conn, s string) { _, _ = c.Write([]byte(s)) }

// readLine 读客户端一行，用于按请求顺序回放响应。
func readLine(c net.Conn) string {
	buf := make([]byte, 4096)
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := c.Read(buf)
	if n <= 0 {
		return ""
	}
	_ = err
	return string(buf[:n])
}

// readTelnetLine 像真 telnetd 那样读一行：先丢掉 IAC 协商三元组，只把剩下的文本当输入。
// 靶子如果不解析协商，就会把自己发出去后客户端的应答当成「用户输入」，
// 适配器的口令分支永远走不到——测试绿得毫无意义。
func readTelnetLine(c net.Conn) string {
	for {
		text := telnetStripForTest(readLine(c))
		if strings.TrimSpace(strings.ReplaceAll(text, "\r", "")) != "" {
			return text
		}
	}
}

func telnetStripForTest(line string) string {
	b := []byte(line)
	out := make([]byte, 0, len(b))
	for i := 0; i < len(b); {
		if b[i] == 0xff && i+2 < len(b) && (b[i+1] == 250 || b[i+1] == 251 ||
			b[i+1] == 252 || b[i+1] == 253 || b[i+1] == 254) {
			i += 3
			continue
		}
		out = append(out, b[i])
		i++
	}
	return string(out)
}

func credCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// ── Redis ────────────────────────────────────────────────────────────────────

func TestCredRedisIdentify(t *testing.T) {
	t.Run("NOAUTH 也算确认：服务在听，只是要求认证", func(t *testing.T) {
		ep := newCredTestEndpoint(t, func(c net.Conn) { writeString(c, "-NOAUTH Authentication required.\r\n") })
		ok, banner, err := redisCredAdapter{}.Identify(credCtx(t), credEP(ep.addr, "redis"))
		if err != nil || !ok {
			t.Fatalf("ok=%v err=%v", ok, err)
		}
		if !strings.Contains(banner, "NOAUTH") {
			t.Fatalf("banner = %q", banner)
		}
	})
	t.Run("22 端口上的 HTTP 不能被当成 Redis", func(t *testing.T) {
		ep := newCredTestEndpoint(t, func(c net.Conn) {
			writeString(c, "HTTP/1.1 400 Bad Request\r\n\r\n")
		})
		ok, _, err := redisCredAdapter{}.Identify(credCtx(t), credEP(ep.addr, "redis"))
		if err != nil {
			t.Fatal(err)
		}
		if ok {
			t.Fatal("非 RESP 回复不能确认成 Redis")
		}
	})
}

func TestCredRedisTry(t *testing.T) {
	cases := []struct {
		name    string
		auth    string
		ping    string
		cred    Credential
		want    CredOutcome
		wantReq string
	}{
		{"口令正确", "+OK\r\n", "+PONG\r\n", Credential{Password: "pass123"}, CredHit, "*2\r\n$4\r\nAUTH\r\n$7\r\npass123\r\n"},
		{"ACL 用户", "+OK\r\n", "+PONG\r\n", Credential{Username: "app", Password: "pass123"}, CredHit,
			"*3\r\n$4\r\nAUTH\r\n$3\r\napp\r\n$7\r\npass123\r\n"},
		{"WRONGPASS 是拒绝", "-WRONGPASS invalid username-password pair\r\n", "", Credential{Password: "x"}, CredDeny, ""},
		{"AUTH 成功但 PING 不认，不能算命中", "+OK\r\n", "-ERR misconfigured\r\n", Credential{Password: "x"}, CredInconclusive, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ep := newCredTestEndpoint(t, func(c net.Conn) {
				line := readLine(c)
				if line == "" {
					return
				}
				writeString(c, tc.auth)
				if tc.ping != "" && strings.Contains(line, "AUTH") {
					readLine(c)
					writeString(c, tc.ping)
				}
			})
			res, _ := redisCredAdapter{}.Try(credCtx(t), credEP(ep.addr, "redis"), tc.cred)
			if res.Outcome != tc.want {
				t.Fatalf("outcome = %q want %q (reason=%q)", res.Outcome, tc.want, res.Reason)
			}
			if tc.wantReq != "" {
				var all string
				for _, w := range ep.requests() {
					all += w
				}
				if !strings.Contains(all, tc.wantReq) {
					t.Fatalf("发出的字节不是 RESP bulk 形式:\n%q", all)
				}
			}
			if len(res.RawReq) == 0 || len(res.RawResp) == 0 {
				t.Fatalf("证据字节缺失: req=%q resp=%q", res.RawReq, res.RawResp)
			}
		})
	}
	t.Run("未启用认证时只有空口令算命中", func(t *testing.T) {
		ep := newCredTestEndpoint(t, func(c net.Conn) {
			readLine(c)
			writeString(c, "-ERR Client sent AUTH, but no password is set. Instance has protection disabled\r\n")
		})
		res, _ := redisCredAdapter{}.Try(credCtx(t), credEP(ep.addr, "redis"), Credential{})
		if res.Outcome != CredHit {
			t.Fatalf("空口令应当命中: %+v", res)
		}
	})
	t.Run("未启用认证时非空口令不算命中", func(t *testing.T) {
		ep := newCredTestEndpoint(t, func(c net.Conn) {
			readLine(c)
			writeString(c, "-ERR Client sent AUTH, but no password is set.\r\n")
		})
		res, _ := redisCredAdapter{}.Try(credCtx(t), credEP(ep.addr, "redis"), Credential{Password: "猜的"})
		if res.Outcome != CredDeny {
			t.Fatalf("非空口令不能算命中: %+v", res)
		}
	})
	t.Run("保护模式拒绝的是来源，不是口令", func(t *testing.T) {
		ep := newCredTestEndpoint(t, func(c net.Conn) {
			readLine(c)
			writeString(c, "-DENIED Redis is running in protected mode because protected mode is enabled\r\n")
		})
		res, _ := redisCredAdapter{}.Try(credCtx(t), credEP(ep.addr, "redis"), Credential{Password: "x"})
		if res.Outcome != CredInconclusive {
			t.Fatalf("保护模式不能记成口令结论: %+v", res)
		}
	})
}

// ── SOCKS5 ───────────────────────────────────────────────────────────────────

func TestCredSocks5(t *testing.T) {
	t.Run("认证通过", func(t *testing.T) {
		ep := newCredTestEndpoint(t, func(c net.Conn) {
			readLine(c)
			writeString(c, "\x05\x02")
			readLine(c)
			writeString(c, "\x01\x00")
		})
		res, _ := socks5CredAdapter{}.Try(credCtx(t), credEP(ep.addr, "socks5"), Credential{Username: "u", Password: "p"})
		if res.Outcome != CredHit {
			t.Fatalf("res = %+v", res)
		}
		if got := ep.requests(); len(got) < 2 || got[1][0] != 0x01 {
			t.Fatalf("子协商格式不对: %q", got)
		}
	})
	t.Run("明确失败才是拒绝", func(t *testing.T) {
		ep := newCredTestEndpoint(t, func(c net.Conn) {
			readLine(c)
			writeString(c, "\x05\x02")
			readLine(c)
			writeString(c, "\x01\xff")
		})
		res, _ := socks5CredAdapter{}.Try(credCtx(t), credEP(ep.addr, "socks5"), Credential{Username: "u", Password: "p"})
		if res.Outcome != CredDeny {
			t.Fatalf("res = %+v", res)
		}
	})
	t.Run("子协商没走完就断开不能记成口令错误", func(t *testing.T) {
		ep := newCredTestEndpoint(t, func(c net.Conn) {
			readLine(c)
			writeString(c, "\x05\x02")
			readLine(c) // 然后直接关连接
		})
		res, _ := socks5CredAdapter{}.Try(credCtx(t), credEP(ep.addr, "socks5"), Credential{Username: "u", Password: "p"})
		if res.Outcome != CredInconclusive {
			t.Fatalf("服务端没说失败，只能不可判定: %+v", res)
		}
		if !strings.Contains(res.Evidence(), "不能记成口令错误") {
			t.Fatalf("证据里要写明为什么不敢下结论: %s", res.Evidence())
		}
	})
	t.Run("不要求认证的代理只把空凭据算命中", func(t *testing.T) {
		handler := func(c net.Conn) {
			readLine(c)
			writeString(c, "\x05\x00")
		}
		ep := newCredTestEndpoint(t, handler)
		res, _ := socks5CredAdapter{}.Try(credCtx(t), credEP(ep.addr, "socks5"), Credential{})
		if res.Outcome != CredHit {
			t.Fatalf("空凭据应当命中: %+v", res)
		}
		ep2 := newCredTestEndpoint(t, handler)
		res2, _ := socks5CredAdapter{}.Try(credCtx(t), credEP(ep2.addr, "socks5"), Credential{Username: "u", Password: "p"})
		if res2.Outcome != CredDeny {
			t.Fatalf("非空凭据不算命中: %+v", res2)
		}
	})
	t.Run("GSSAPI 报不支持而不是失败", func(t *testing.T) {
		ep := newCredTestEndpoint(t, func(c net.Conn) {
			readLine(c)
			writeString(c, "\x05\x01")
		})
		res, _ := socks5CredAdapter{}.Try(credCtx(t), credEP(ep.addr, "socks5"), Credential{Username: "u", Password: "p"})
		if res.Outcome != CredUnsupported {
			t.Fatalf("res = %+v", res)
		}
		if len(ep.requests()) != 1 {
			t.Fatalf("方法谈不拢就不该再发凭据: %q", ep.requests())
		}
	})
}

// ── FTP ──────────────────────────────────────────────────────────────────────

func TestCredFTP(t *testing.T) {
	t.Run("命中", func(t *testing.T) {
		ep := newCredTestEndpoint(t, func(c net.Conn) {
			writeString(c, "220 (vsFTPd 3.0.5)\r\n")
			readLine(c)
			writeString(c, "331 Please specify the password.\r\n")
			readLine(c)
			writeString(c, "230 Login successful.\r\n")
		})
		res, _ := ftpCredAdapter{}.Try(credCtx(t), credEP(ep.addr, "ftp"), Credential{Username: "ftp", Password: "ftp123"})
		if res.Outcome != CredHit {
			t.Fatalf("res = %+v", res)
		}
		sent := strings.Join(ep.requests(), "|")
		if !strings.Contains(sent, "USER ftp\r\n") || !strings.Contains(sent, "PASS ftp123\r\n") {
			t.Fatalf("发出的命令不对: %q", sent)
		}
	})
	t.Run("拒绝", func(t *testing.T) {
		ep := newCredTestEndpoint(t, func(c net.Conn) {
			writeString(c, "220 (vsFTPd 3.0.5)\r\n")
			readLine(c)
			writeString(c, "331 Please specify the password.\r\n")
			readLine(c)
			writeString(c, "530 Login incorrect.\r\n")
		})
		res, _ := ftpCredAdapter{}.Try(credCtx(t), credEP(ep.addr, "ftp"), Credential{Username: "root", Password: "root"})
		if res.Outcome != CredDeny {
			t.Fatalf("res = %+v", res)
		}
	})
	t.Run("banner 不是 220 就不算 FTP", func(t *testing.T) {
		ep := newCredTestEndpoint(t, func(c net.Conn) { writeString(c, "SSH-2.0-OpenSSH_9.6\r\n") })
		ok, _, err := ftpCredAdapter{}.Identify(credCtx(t), credEP(ep.addr, "ftp"))
		if err != nil {
			t.Fatal(err)
		}
		if ok {
			t.Fatal("SSH banner 不能被认成 FTP")
		}
	})
	t.Run("每地址并发上限不是账号锁定", func(t *testing.T) {
		// 421 too many connections 是服务状态：写成 locked 会让人以为账号被锁、
		// 换成不可判定才说得出「稍后再来或降并发」。
		ep := newCredTestEndpoint(t, func(c net.Conn) {
			writeString(c, "421 There are too many connections from your internet address.\r\n")
		})
		res, _ := ftpCredAdapter{}.Try(credCtx(t), credEP(ep.addr, "ftp"), Credential{Username: "u", Password: "p"})
		if res.Outcome != CredInconclusive {
			t.Fatalf("限流不能记成锁定: %+v", res)
		}
	})
	t.Run("账号被锁要说锁定", func(t *testing.T) {
		ep := newCredTestEndpoint(t, func(c net.Conn) {
			writeString(c, "220 ProFTPD\r\n")
			readLine(c)
			writeString(c, "331 Password required\r\n")
			readLine(c)
			writeString(c, "530-User root cannot log in, account locked due to too many failed logins\r\n530 Login incorrect.\r\n")
		})
		res, _ := ftpCredAdapter{}.Try(credCtx(t), credEP(ep.addr, "ftp"), Credential{Username: "root", Password: "root"})
		if res.Outcome != CredLocked {
			t.Fatalf("锁定提示必须落成 locked 并让该端点停手: %+v", res)
		}
	})
	t.Run("含换行的凭据不发送", func(t *testing.T) {
		ep := newCredTestEndpoint(t, func(c net.Conn) { writeString(c, "220 x\r\n") })
		res, _ := ftpCredAdapter{}.Try(credCtx(t), credEP(ep.addr, "ftp"), Credential{Username: "u", Password: "p\r\nSITE EXEC rm -rf /"})
		if res.Outcome != CredInconclusive {
			t.Fatalf("不能把换行发出去再下结论: %+v", res)
		}
		if strings.Contains(strings.Join(ep.requests(), "|"), "SITE") {
			t.Fatalf("第二条命令被注入出去了: %q", ep.requests())
		}
	})
}

// ── Telnet ───────────────────────────────────────────────────────────────────

func TestCredTelnet(t *testing.T) {
	t.Run("口令正确给出 shell 提示符", func(t *testing.T) {
		ep := newCredTestEndpoint(t, func(c net.Conn) {
			writeString(c, "\xff\xfb\x01\xff\xfb\x03Debian GNU\r\nlogin: ")
			if !strings.Contains(readTelnetLine(c), "root") {
				return
			}
			writeString(c, "\xff\xfc\x01Password: ")
			if !strings.Contains(readTelnetLine(c), "toor") {
				return
			}
			writeString(c, "Last login: Mon Nov  5 10:00:00 2026\r\nroot@lab:~# ")
		})
		res, _ := telnetCredAdapter{}.Try(credCtx(t), credEP(ep.addr, "telnet"), Credential{Username: "root", Password: "toor"})
		if res.Outcome != CredHit {
			t.Fatalf("res = %+v", res)
		}
		sent := strings.Join(ep.requests(), "")
		// 对端 WILL ECHO/SGA ⇒ 本端 DONT（0xfe）；应答错了，telnetd 会一直等协商。
		if !strings.Contains(sent, "\xff\xfe\x01") || !strings.Contains(sent, "\xff\xfe\x03") {
			t.Fatalf("没应答 IAC 协商，对端可能一直等: %q", sent)
		}
	})
	t.Run("Login incorrect 是拒绝", func(t *testing.T) {
		ep := newCredTestEndpoint(t, func(c net.Conn) {
			writeString(c, "login: ")
			readTelnetLine(c)
			writeString(c, "Password: ")
			readTelnetLine(c)
			writeString(c, "\nLogin incorrect\nlogin: ")
		})
		res, _ := telnetCredAdapter{}.Try(credCtx(t), credEP(ep.addr, "telnet"), Credential{Username: "root", Password: "bad"})
		if res.Outcome != CredDeny {
			t.Fatalf("res = %+v", res)
		}
	})
	t.Run("回到登录提示且没有成功特征算拒绝", func(t *testing.T) {
		ep := newCredTestEndpoint(t, func(c net.Conn) {
			writeString(c, "Username: ")
			readTelnetLine(c)
			writeString(c, "Password: ")
			readTelnetLine(c)
			writeString(c, "\nUsername: ")
		})
		res, _ := telnetCredAdapter{}.Try(credCtx(t), credEP(ep.addr, "telnet"), Credential{Username: "u", Password: "p"})
		if res.Outcome != CredDeny {
			t.Fatalf("res = %+v", res)
		}
	})
	t.Run("账号锁定要说锁定", func(t *testing.T) {
		ep := newCredTestEndpoint(t, func(c net.Conn) {
			writeString(c, "login: ")
			readTelnetLine(c)
			writeString(c, "Password: ")
			readTelnetLine(c)
			writeString(c, "This account is temporarily blocked because of too many failed logins\nlogin: ")
		})
		res, _ := telnetCredAdapter{}.Try(credCtx(t), credEP(ep.addr, "telnet"), Credential{Username: "u", Password: "p"})
		if res.Outcome != CredLocked {
			t.Fatalf("res = %+v", res)
		}
	})
	t.Run("认不出形状时不可判定，不猜命中", func(t *testing.T) {
		ep := newCredTestEndpoint(t, func(c net.Conn) {
			writeString(c, "login: ")
			readTelnetLine(c)
			writeString(c, "Password: ")
			readTelnetLine(c)
			writeString(c, "System is going down for maintenance NOW!\r\n")
		})
		res, _ := telnetCredAdapter{}.Try(credCtx(t), credEP(ep.addr, "telnet"), Credential{Username: "u", Password: "p"})
		if res.Outcome != CredInconclusive {
			t.Fatalf("没有可判定特征就不能下结论: %+v", res)
		}
	})
	t.Run("IAC 序列不进文本", func(t *testing.T) {
		raw := []byte{0xff, 0xfd, 0x03, 'l', 'o', 'g', 'i', 'n', ':', ' '}
		if got := string(telnetStrip(raw)); got != "login: " {
			t.Fatalf("strip = %q", got)
		}
		if got := telnetReplies([]byte{0xff, 0xfd, 0x03}); len(got) != 1 ||
			string(got[0]) != string([]byte{0xff, 0xfc, 0x03}) {
			t.Fatalf("DO 应当答 WONT: %v", got)
		}
	})
}

func TestCredLockedTextIsNarrow(t *testing.T) {
	// 「口令错」的常见措辞绝不能被认成锁定：那会让任务提前停手，漏掉真正可用的口令。
	for _, msg := range []string{
		"wrongpass invalid username-password pair",
		"access denied for user 'root'@'localhost'",
		"login incorrect",
		"invalid password",
	} {
		if credLockedText(msg) {
			t.Fatalf("把拒绝读成了锁定: %q", msg)
		}
	}
	for _, msg := range []string{
		"account locked due to failed attempts",
		"host blocked because of many connection errors",
		"this account is temporarily blocked",
		"too many failed login attempts",
	} {
		if !credLockedText(msg) {
			t.Fatalf("锁定提示没认出来: %q", msg)
		}
	}
}
