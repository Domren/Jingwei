package scanner

import (
	"context"
	"crypto/hmac"
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"testing"
)

// 原「降级」协议的 hit/deny 双路径。
//
// 桩只回协议真实的帧，适配器必须从帧里读出结论，而不是「连上了就算命中」。这些用例是
// **回归保护**，不是「功能已实现」的证据：桩与适配器可能错得一模一样（2026-11-09 就撞到过，
// 见进度手册 §5.9），能起真服务的协议一律以 `credscan-lab` 的真机用例为准。
//
// 已删除的协议：Oracle / WebLogic 控制台 / WinRM / CobaltStrike。它们没有可复现的真服务，
// 按负责人决定整条不做（协议名、适配器、桩、字典条目一起删），不再用桩维持「支持」的假象。

// ── MSSQL ────────────────────────────────────────────────────────────────────

func mssqlReadPrelogin(c net.Conn) []byte {
	head := make([]byte, 8)
	if _, err := readFull(c, head); err != nil {
		return nil
	}
	n := int(head[2])<<8 | int(head[3])
	if n <= 8 {
		return head[:0]
	}
	body := make([]byte, n-8)
	_, _ = readFull(c, body)
	return append(head, body...)
}

func mssqlPreloginReply() []byte {
	// VERSION @0 len6 + 结束标记，数据区给一个 15.0.2000 的版本号。
	table := []byte{0x00, 0x00, 0x00, 0x00, 0x06, 0xff}
	data := []byte{0x0f, 0x00, 0x00, 0x00, 0x00, 0x00}
	return mssqlPacket(0x04, append(table, data...))
}

func mssqlErrorReply(msg string) []byte {
	body := make([]byte, 8)
	u := mssqlUTF16(msg)
	binary.LittleEndian.PutUint16(body[6:], uint16(len(u)/2))
	body = append(body, u...)
	tok := make([]byte, 2)
	binary.LittleEndian.PutUint16(tok, uint16(len(body)))
	tok = append(tok, body...)
	return mssqlPacket(0x04, append([]byte{0xaa}, tok...))
}

func TestCredMSSQLHitDeny(t *testing.T) {
	ep := newCredTestEndpoint(t, func(c net.Conn) {
		if mssqlReadPrelogin(c) == nil {
			return
		}
		writeString(c, string(mssqlPreloginReply()))
		login := mssqlReadPrelogin(c)
		if login == nil {
			return
		}
		// Login7 里的 username 是 UTF-16LE：按协议真实编码比对，不按明文子串比对。
		if strings.Contains(string(login), string(mssqlUTF16("admin"))) {
			writeString(c, string(mssqlPacket(0x04, []byte{0xad})))
			return
		}
		writeString(c, string(mssqlErrorReply("Login failed for user 'sa'.")))
	})
	ctx := credCtx(t)

	ok, banner, err := mssqlCredAdapter{}.Identify(ctx, credEP(ep.addr, "mssql"))
	if err != nil || !ok || !strings.Contains(banner, "TDS") {
		t.Fatalf("identify = %v %q %v", ok, banner, err)
	}
	hit, err := mssqlCredAdapter{}.Try(ctx, credEP(ep.addr, "mssql"), Credential{Username: "admin", Password: "p"})
	if err != nil || hit.Outcome != CredHit {
		t.Fatalf("hit = %+v err=%v", hit, err)
	}
	deny, err := mssqlCredAdapter{}.Try(ctx, credEP(ep.addr, "mssql"), Credential{Username: "sa", Password: "x"})
	if err != nil || deny.Outcome != CredDeny {
		t.Fatalf("deny = %+v err=%v", deny, err)
	}
	if !strings.Contains(deny.Reason, "Login failed") {
		t.Fatalf("deny reason should carry the server message: %q", deny.Reason)
	}
	if len(deny.RawReq) == 0 || len(deny.RawResp) == 0 {
		t.Fatal("deny must keep wire evidence")
	}
}

// ── SMB2 ─────────────────────────────────────────────────────────────────────

func smb2Reply(cmd uint16, status uint32, msgID uint64, body []byte) []byte {
	return smb2Frame(append(smb2Header(cmd, status, msgID), body...))
}

func smb2NegotiateReply() []byte {
	body := make([]byte, 64)
	binary.LittleEndian.PutUint16(body[0:], 65)
	binary.LittleEndian.PutUint16(body[4:], 0x0302) // DialectRevision -> frame[68]
	return smb2Reply(smb2CmdNegotiate, 0, 1, body)
}

func smb2ChallengeReply() []byte {
	sec := append([]byte("NTLMSSP\x00"), 0x02, 0x00, 0x00, 0x00)
	sec = append(sec, make([]byte, 16)...)           // target name / flags
	sec = append(sec, []byte("0123456789abcdef")...) // ServerChallenge @24..32
	sec = append(sec, make([]byte, 8)...)
	body := make([]byte, 8)
	binary.LittleEndian.PutUint16(body[4:], 72) // SecurityBufferOffset (64+8)
	binary.LittleEndian.PutUint16(body[6:], uint16(len(sec)))
	return smb2Reply(smb2CmdSessionSetup, smb2StatusMoreProc, 2, append(body, sec...))
}

func TestCredSMBHitDeny(t *testing.T) {
	ep := newCredTestEndpoint(t, func(c net.Conn) {
		if _, err := smb2ReadFrame(&credWire{conn: c}); err != nil {
			return
		}
		writeString(c, string(smb2NegotiateReply()))
		if _, err := smb2ReadFrame(&credWire{conn: c}); err != nil {
			return
		}
		writeString(c, string(smb2ChallengeReply()))
		auth, err := smb2ReadFrame(&credWire{conn: c})
		if err != nil {
			return
		}
		// NTLMSSP Type3 里的用户名同样是 UTF-16LE。
		if strings.Contains(string(auth), string(smbUTF16("admin"))) {
			writeString(c, string(smb2Reply(smb2CmdSessionSetup, smb2StatusSuccess, 3, make([]byte, 8))))
			return
		}
		// visitor：Samba 的 map to guest = bad user 会把不存在的账号降级成访客会话，
		// STATUS 仍是 SUCCESS，只靠状态码会把任意口令判成命中。
		if strings.Contains(string(auth), string(smbUTF16("visitor"))) {
			body := make([]byte, 8)
			binary.LittleEndian.PutUint16(body[2:], smb2SessionFlagGuest)
			writeString(c, string(smb2Reply(smb2CmdSessionSetup, smb2StatusSuccess, 3, body)))
			return
		}
		writeString(c, string(smb2Reply(smb2CmdSessionSetup, smb2StatusLogonFail, 3, make([]byte, 8))))
	})
	ctx := credCtx(t)

	ok, banner, err := smbCredAdapter{}.Identify(ctx, credEP(ep.addr, "smb"))
	if err != nil || !ok || !strings.Contains(banner, "SMB2") {
		t.Fatalf("identify = %v %q %v", ok, banner, err)
	}
	hit, err := smbCredAdapter{}.Try(ctx, credEP(ep.addr, "smb"), Credential{Username: "admin", Password: "p"})
	if err != nil || hit.Outcome != CredHit {
		t.Fatalf("hit = %+v err=%v", hit, err)
	}
	deny, err := smbCredAdapter{}.Try(ctx, credEP(ep.addr, "smb"), Credential{Username: "guest", Password: "x"})
	if err != nil || deny.Outcome != CredDeny {
		t.Fatalf("deny = %+v err=%v", deny, err)
	}
	// 访客降级：服务端回 SUCCESS 但带 SESSION_FLAG_GUEST，不能算命中。
	mapped, err := smbCredAdapter{}.Try(ctx, credEP(ep.addr, "smb"), Credential{Username: "visitor", Password: "whatever"})
	if err != nil || mapped.Outcome != CredDeny {
		t.Fatalf("guest-mapped = %+v err=%v", mapped, err)
	}
	if !strings.Contains(mapped.Reason, "访客") {
		t.Fatalf("guest-mapped deny reason should explain the guest mapping: %q", mapped.Reason)
	}
}

// ── SVN ──────────────────────────────────────────────────────────────────────

// svnTestDigest 在测试里独立算一遍 CRAM-MD5 应答：不调生产代码的 svnCRAMResponse，
// 否则 key/msg 取错了两边会一起错，测试永远绿。
func svnTestDigest(password, challenge string) string {
	m := hmac.New(md5.New, []byte(password))
	m.Write([]byte(challenge))
	return hex.EncodeToString(m.Sum(nil))
}

const svnTestChallenge = "<14177855853207743237.1794188582883675@LAPTOP-JWLAB>"

func TestCredSVNHitDeny(t *testing.T) {
	ep := newCredTestEndpoint(t, func(c net.Conn) {
		// 1 greeting；2 客户端 hello；3 mech list；4 CRAM-MD5；5 step(challenge)；6 凭据。
		writeString(c, "( success ( 2 2 ( ) ( edit-pipeline svndiff1 ) ) ) ")
		_ = readLine(c)
		writeString(c, "( success ( ( CRAM-MD5 ) 5:jwlab ) ) ")
		_ = readLine(c)
		writeString(c, fmt.Sprintf("( step ( %d:%s ) ) ", len(svnTestChallenge), svnTestChallenge))
		auth := readLine(c)
		if strings.Contains(auth, "admin ") &&
			strings.Contains(auth, svnTestDigest("p", svnTestChallenge)) {
			writeString(c, "( success ( ) ) ")
			return
		}
		writeString(c, `( failure ( ( 215004 "Unspecified error" "Authentication failed" ) ) ) `)
	})
	ctx := credCtx(t)

	ok, _, err := svnCredAdapter{}.Identify(ctx, credEP(ep.addr, "svn"))
	if err != nil || !ok {
		t.Fatalf("identify = %v %v", ok, err)
	}
	hit, err := svnCredAdapter{}.Try(ctx, credEP(ep.addr, "svn"), Credential{Username: "admin", Password: "p"})
	if err != nil || hit.Outcome != CredHit {
		t.Fatalf("hit = %+v err=%v", hit, err)
	}
	deny, err := svnCredAdapter{}.Try(ctx, credEP(ep.addr, "svn"), Credential{Username: "bob", Password: "x"})
	if err != nil || deny.Outcome != CredDeny {
		t.Fatalf("deny = %+v err=%v", deny, err)
	}
	if len(deny.RawReq) == 0 || len(deny.RawResp) == 0 {
		t.Fatal("deny 也要留 wire 证据")
	}
}

// ── RouterOS API ─────────────────────────────────────────────────────────────

func TestCredRouterOSHitDeny(t *testing.T) {
	ep := newCredTestEndpoint(t, func(c net.Conn) {
		w := &credWire{conn: c}
		words, err := rosReadSentence(w)
		if err != nil {
			return
		}
		if rosHas(words, "/system/identity/print") {
			writeString(c, string(rosSentence("!done")))
			return
		}
		login := strings.Join(words, " ")
		if strings.Contains(login, "admin") {
			writeString(c, string(rosSentence("!done")))
			return
		}
		writeString(c, string(rosSentence("!trap", "=message=invalid user name or password")))
	})
	ctx := credCtx(t)

	ok, banner, err := routerosCredAdapter{}.Identify(ctx, credEP(ep.addr, "routeros"))
	if err != nil || !ok || !strings.Contains(banner, "RouterOS") {
		t.Fatalf("identify = %v %q %v", ok, banner, err)
	}
	hit, err := routerosCredAdapter{}.Try(ctx, credEP(ep.addr, "routeros"), Credential{Username: "admin", Password: ""})
	if err != nil || hit.Outcome != CredHit {
		t.Fatalf("hit = %+v err=%v", hit, err)
	}
	deny, err := routerosCredAdapter{}.Try(ctx, credEP(ep.addr, "routeros"), Credential{Username: "bob", Password: "x"})
	if err != nil || deny.Outcome != CredDeny {
		t.Fatalf("deny = %+v err=%v", deny, err)
	}
}

// ── RDP ──────────────────────────────────────────────────────────────────────

func rdpConfirm(selected uint32) []byte {
	body := []byte{0x0e, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x08, 0x00}
	body = append(body, byte(selected), 0, 0, 0)
	out := append([]byte{0x03, 0x00, 0x00, 0x00}, body...)
	binary.BigEndian.PutUint16(out[2:], uint16(len(out)))
	return out
}

func TestCredRDPHitDeny(t *testing.T) {
	ep := newCredTestEndpoint(t, func(c net.Conn) {
		if _, err := rdpReadTPKT(&credWire{conn: c}); err != nil {
			return
		}
		writeString(c, string(rdpConfirm(0)))
		auth, err := rdpReadTPKT(&credWire{conn: c})
		if err != nil {
			return
		}
		status := byte(0x01)
		if strings.Contains(string(auth), "admin") {
			status = 0x00
		}
		ack := []byte{0x03, 0x00, 0x00, 0x08, 0x02, 0xf0, 0x80, status}
		writeString(c, string(ack))
	})
	ctx := credCtx(t)

	ok, banner, err := rdpCredAdapter{}.Identify(ctx, credEP(ep.addr, "rdp"))
	if err != nil || !ok || !strings.Contains(banner, "RDP") {
		t.Fatalf("identify = %v %q %v", ok, banner, err)
	}
	hit, err := rdpCredAdapter{}.Try(ctx, credEP(ep.addr, "rdp"), Credential{Username: "admin", Password: "p"})
	if err != nil || hit.Outcome != CredHit {
		t.Fatalf("hit = %+v err=%v", hit, err)
	}
	deny, err := rdpCredAdapter{}.Try(ctx, credEP(ep.addr, "rdp"), Credential{Username: "bob", Password: "x"})
	if err != nil || deny.Outcome != CredDeny {
		t.Fatalf("deny = %+v err=%v", deny, err)
	}
}

// ── HTTP 桩（Jenkins / JBoss 共用） ──────────────────────────────────────────

func httpStubReply(c net.Conn, status int, headers map[string]string, body string) {
	var b strings.Builder
	fmt.Fprintf(&b, "HTTP/1.1 %d %s\r\n", status, map[int]string{200: "OK", 401: "Unauthorized", 403: "Forbidden"}[status])
	fmt.Fprintf(&b, "Content-Length: %d\r\n", len(body))
	for k, v := range headers {
		fmt.Fprintf(&b, "%s: %s\r\n", k, v)
	}
	b.WriteString("Connection: close\r\n\r\n")
	b.WriteString(body)
	writeString(c, b.String())
}

// ── Jenkins（表单多轮） ──────────────────────────────────────────────────────

func TestCredJenkinsHitDeny(t *testing.T) {
	ep := newCredTestEndpoint(t, func(c net.Conn) {
		line := readLine(c)
		switch {
		case strings.Contains(line, "GET /login"):
			// Jenkins 2.x 的登录页表单动作是 j_spring_security_check（1.x 才是 Acegi 那个）。
			httpStubReply(c, 200, nil,
				`<html><head><title>Sign in [Jenkins]</title></head><body>`+
					`<form name="login" action="j_spring_security_check" method="post"></form></body></html>`)
		case strings.Contains(line, "GET /crumbIssuer/api/json"):
			httpStubReply(c, 200, map[string]string{"Set-Cookie": "JSESSIONID=anon; Path=/"},
				`{"crumb":"c1","crumbRequestField":"Jenkins-Crumb"}`)
		case strings.Contains(line, "POST /j_spring_security_check"):
			if strings.Contains(line, "j_username=admin") {
				httpStubReply(c, 302, map[string]string{"Location": "/", "Set-Cookie": "JSESSIONID=authed; Path=/"}, "")
				return
			}
			httpStubReply(c, 302, map[string]string{"Location": "/loginError"}, "")
		case strings.Contains(line, "GET /whoAmI/api/json"):
			// 真 Jenkins 对匿名用户也回 "authenticated":true（匿名本身是一个
			// Authentication）。桩照实回，否则「任何口令都判命中」的误报测不出来。
			if strings.Contains(line, "JSESSIONID=authed") {
				httpStubReply(c, 200, nil, `{"_class":"hudson.security.WhoAmI","authenticated":true,"name":"admin"}`)
				return
			}
			httpStubReply(c, 200, nil, `{"_class":"hudson.security.WhoAmI","authenticated":true,"name":"anonymous"}`)
		default:
			httpStubReply(c, 404, nil, "")
		}
	})
	ctx := credCtx(t)

	ok, banner, err := jenkinsCredAdapterIdentify(ctx, ep)
	if err != nil || !ok || !strings.Contains(strings.ToUpper(banner), "JENKINS") {
		t.Fatalf("identify = %v %q %v", ok, banner, err)
	}
	hit, err := formCredAdapter{protocol: "jenkins"}.Try(ctx, credEP(ep.addr, "jenkins"), Credential{Username: "admin", Password: "p"})
	if err != nil || hit.Outcome != CredHit {
		t.Fatalf("hit = %+v err=%v", hit, err)
	}
	deny, err := formCredAdapter{protocol: "jenkins"}.Try(ctx, credEP(ep.addr, "jenkins"), Credential{Username: "bob", Password: "x"})
	if err != nil || deny.Outcome != CredDeny {
		t.Fatalf("deny = %+v err=%v", deny, err)
	}
}

// 只认 Acegi 端点的老服务端（1.x）要能靠 404 回退走到，不能一律 inconclusive。
func TestCredJenkinsAcegiFallback(t *testing.T) {
	ep := newCredTestEndpoint(t, func(c net.Conn) {
		line := readLine(c)
		switch {
		case strings.Contains(line, "POST /j_spring_security_check"):
			httpStubReply(c, 404, nil, "")
		case strings.Contains(line, "POST /j_acegi_security_check"):
			if strings.Contains(line, "j_username=admin") {
				httpStubReply(c, 302, map[string]string{"Location": "/", "Set-Cookie": "JSESSIONID=authed; Path=/"}, "")
				return
			}
			httpStubReply(c, 302, map[string]string{"Location": "/loginError"}, "")
		case strings.Contains(line, "GET /crumbIssuer/api/json"):
			httpStubReply(c, 200, nil, `{"crumb":"c1","crumbRequestField":"Jenkins-Crumb"}`)
		case strings.Contains(line, "GET /whoAmI/api/json"):
			if strings.Contains(line, "JSESSIONID=authed") {
				httpStubReply(c, 200, nil, `{"authenticated":true,"name":"admin"}`)
				return
			}
			httpStubReply(c, 200, nil, `{"authenticated":true,"name":"anonymous"}`)
		default:
			httpStubReply(c, 200, nil, `<title>Jenkins</title>`)
		}
	})
	ctx := credCtx(t)
	hit, err := formCredAdapter{protocol: "jenkins"}.Try(ctx, credEP(ep.addr, "jenkins"), Credential{Username: "admin", Password: "p"})
	if err != nil || hit.Outcome != CredHit {
		t.Fatalf("acegi fallback hit = %+v err=%v", hit, err)
	}
}

// jenkinsCredAdapterIdentify 直接复用适配器的 Identify，避免测试另写一份识别逻辑。
func jenkinsCredAdapterIdentify(ctx context.Context, ep *credTestEndpoint) (bool, string, error) {
	return formCredAdapter{protocol: "jenkins"}.Identify(ctx, credEP(ep.addr, "jenkins"))
}

// ── JBoss / WildFly（Digest） ────────────────────────────────────────────────

// jbossTestDigest 在测试里独立算一遍 Digest 应答：不调生产代码的 digestAuthorization，
// 否则 nonce/qop 口径错了两边会一起错。真机 WildFly 25 证实 /management 只认 Digest，
// Basic 即使口令正确也回 401。
func jbossTestDigest(user, pass, realm, nonce, nc, cnonce, method, uri string) string {
	sum := func(s string) string {
		h := md5.Sum([]byte(s))
		return fmt.Sprintf("%x", h)
	}
	ha1 := sum(user + ":" + realm + ":" + pass)
	ha2 := sum(method + ":" + uri)
	return sum(ha1 + ":" + nonce + ":" + nc + ":" + cnonce + ":auth:" + ha2)
}

// digestHeaderValue 从请求文本里取 Authorization 头里某个键的值。
func digestHeaderValue(req, key string) string {
	needle := key + `="`
	i := strings.Index(req, needle)
	if i < 0 {
		// 不带引号的形态（qop=auth / nc=00000001）
		needle = key + "="
		i = strings.Index(req, needle)
		if i < 0 {
			return ""
		}
		rest := req[i+len(needle):]
		j := strings.IndexAny(rest, ", \r\n")
		if j < 0 {
			return rest
		}
		return rest[:j]
	}
	rest := req[i+len(needle):]
	j := strings.Index(rest, `"`)
	if j < 0 {
		return ""
	}
	return rest[:j]
}

func TestCredJBossDigestHitDeny(t *testing.T) {
	const (
		realm = "ManagementRealm"
		nonce = "dcd98b7102dd2f0e8b11d0f600bfb0c093"
		user  = "admin"
		pass  = "jwlab123"
		uri   = "/management"
	)
	ep := newCredTestEndpoint(t, func(c net.Conn) {
		line := readLine(c)
		if !strings.Contains(line, "GET "+uri) {
			httpStubReply(c, 404, nil, "")
			return
		}
		if !strings.Contains(line, "Authorization: Digest") {
			// 未带凭据：WildFly 真实行为是 401 + Digest 质询，不是 Basic。
			httpStubReply(c, 401, map[string]string{
				"WWW-Authenticate": `Digest realm="` + realm + `", nonce="` + nonce +
					`", opaque="00000000000000000000000000000000", algorithm=MD5, qop=auth`,
			}, "")
			return
		}
		got := digestHeaderValue(line, "response")
		want := jbossTestDigest(digestHeaderValue(line, "username"), pass, realm, nonce,
			digestHeaderValue(line, "nc"), digestHeaderValue(line, "cnonce"), "GET", uri)
		if got != "" && got == want {
			httpStubReply(c, 200, nil, `{"outcome":"success","result":[]}`)
			return
		}
		httpStubReply(c, 401, map[string]string{
			"WWW-Authenticate": `Digest realm="` + realm + `", nonce="` + nonce + `", qop=auth`,
		}, `<html><body>401 - Unauthorized</body></html>`)
	})
	ctx := credCtx(t)

	ok, banner, err := formCredAdapter{protocol: "jboss-console"}.Identify(ctx, credEP(ep.addr, "jboss-console"))
	if err != nil || !ok || !strings.Contains(strings.ToUpper(banner), "JBOSS") {
		t.Fatalf("identify = %v %q %v", ok, banner, err)
	}
	hit, err := formCredAdapter{protocol: "jboss-console"}.Try(ctx, credEP(ep.addr, "jboss-console"),
		Credential{Username: user, Password: pass})
	if err != nil || hit.Outcome != CredHit {
		t.Fatalf("hit = %+v err=%v", hit, err)
	}
	deny, err := formCredAdapter{protocol: "jboss-console"}.Try(ctx, credEP(ep.addr, "jboss-console"),
		Credential{Username: user, Password: "wrongpw"})
	if err != nil || deny.Outcome != CredDeny {
		t.Fatalf("deny = %+v err=%v", deny, err)
	}
}

// ── SNMP（UDP） ──────────────────────────────────────────────────────────────

func snmpUDPStub(t *testing.T, accept func(community string) bool) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			version, community, reqID, ok := snmpReqParts(buf[:n])
			if !ok || !accept(community) {
				// community 不被接受：按 RFC 3412 静默丢弃，一个字节都不回。
				continue
			}
			_, _ = pc.WriteTo(snmpGetResponse(version, community, reqID), addr)
		}
	}()
	return pc.LocalAddr().String()
}

func snmpReqParts(raw []byte) (version int, community string, reqID int, ok bool) {
	tag, msg, _, ok := berReadTLV(raw, 0)
	if !ok || tag != 0x30 {
		return 0, "", 0, false
	}
	t, v, next, ok := berReadTLV(msg, 0)
	if !ok || t != 0x02 {
		return 0, "", 0, false
	}
	version = berIntValue(v)
	t, v, next, ok = berReadTLV(msg, next)
	if !ok || t != 0x04 {
		return 0, "", 0, false
	}
	community = string(v)
	t, pdu, _, ok := berReadTLV(msg, next)
	if !ok || !snmpIsPDUTag(t) {
		return 0, "", 0, false
	}
	t, v, _, ok = berReadTLV(pdu, 0)
	if !ok || t != 0x02 {
		return 0, "", 0, false
	}
	return version, community, berIntValue(v), true
}

func snmpGetResponse(version int, community string, reqID int) []byte {
	pdu := berTLV(0xa2, concatBytes(berInt(reqID), berInt(0), berInt(0),
		berTLV(0x30, nil)))
	return berTLV(0x30, concatBytes(berInt(version), berOctet(community), pdu))
}

func TestCredSNMPHitAndSilentDrop(t *testing.T) {
	addr := snmpUDPStub(t, func(community string) bool {
		// Identify 用协议公开默认的 public 探测形态；Try 用被测 community。
		return community == "s3cret" || community == "public"
	})
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	var port int
	_, _ = fmt.Sscanf(portStr, "%d", &port)
	ep := CredEndpoint{Host: host, Port: port, Protocol: "snmp",
		ProtocolSource: CredProtocolSourceExplicit, ProtocolConfirmed: true}
	ctx := credCtx(t)

	ok, banner, err := snmpCredAdapter{}.Identify(ctx, ep)
	if err != nil || !ok || !strings.Contains(banner, "SNMP") {
		t.Fatalf("identify = %v %q %v", ok, banner, err)
	}
	hit, err := snmpCredAdapter{}.Try(ctx, ep, Credential{Username: "s3cret"})
	if err != nil || hit.Outcome != CredHit {
		t.Fatalf("hit = %+v err=%v", hit, err)
	}
	drop, err := snmpCredAdapter{}.Try(ctx, ep, Credential{Username: "wrong"})
	if err != nil {
		t.Fatal(err)
	}
	if drop.Outcome != CredInconclusive || !strings.Contains(drop.Reason, "静默丢弃") {
		t.Fatalf("silent drop must be inconclusive with its own reason: %+v", drop)
	}
}

// readFull 是 io.ReadFull 的薄包装，避免测试里到处写 ignored error。
func readFull(c net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := c.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}
