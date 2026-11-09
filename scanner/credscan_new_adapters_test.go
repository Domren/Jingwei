package scanner

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"testing"
)

// 12 个原「降级」协议的 hit/deny 双路径。
//
// 这些协议里有一半（WinRM/RDP/CS/RouterOS）在现有三个 Ubuntu 靶机上起不了真服务，
// 所以用进程内协议桩逐条钉「握手层接受 vs 明确拒绝」：桩只回协议真实的帧，适配器必须
// 从帧里读出结论，而不是「连上了就算命中」。真机验证缺口在各适配器文件头已如实标注。

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
	binary.LittleEndian.PutUint16(body[len(body)-2:], 0x0311) // dialect at frame[70]
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
}

// ── SVN ──────────────────────────────────────────────────────────────────────

func TestCredSVNHitDeny(t *testing.T) {
	ep := newCredTestEndpoint(t, func(c net.Conn) {
		writeString(c, "( success ( 2 2 ( ) ( edit-pipeline svndiff1 ) ) )\n")
		_ = readLine(c)                                           // 客户端 hello
		writeString(c, "( success ( 2 ( PLAIN ANONYMOUS ) ) )\n") // 机制列表
		creds := readLine(c)
		// svnserve 的 PLAIN 凭据是 base64("\x00user\x00pass")：用生产代码的同一个
		// 构造器算出期望值来比，而不是猜某一段明文字串。
		if strings.TrimSpace(creds) == strings.TrimSpace(svnCreds(Credential{Username: "admin", Password: "p"})) {
			writeString(c, "( success ( ) )\n")
			return
		}
		writeString(c, "( failure ( ( 210005 \"Authentication failed\" ) ) )\n")
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

// ── Cobalt Strike Team Server ────────────────────────────────────────────────

func TestCredCobaltStrikeHitDeny(t *testing.T) {
	ep := newCredTestEndpoint(t, func(c net.Conn) {
		// Try 只发一帧登录包：读 4 字节长度 + 载荷即可。
		frame := csReadFramePayload(c)
		if strings.Contains(string(frame), "admin") {
			writeString(c, string(csFrame([]byte{0x00})))
			return
		}
		writeString(c, string(csFrame([]byte{0x01})))
	})
	ctx := credCtx(t)

	hit, err := cobaltstrikeCredAdapter{}.Try(ctx, credEP(ep.addr, "cobaltstrike"), Credential{Username: "admin", Password: "p"})
	if err != nil || hit.Outcome != CredHit {
		t.Fatalf("hit = %+v err=%v", hit, err)
	}
	deny, err := cobaltstrikeCredAdapter{}.Try(ctx, credEP(ep.addr, "cobaltstrike"), Credential{Username: "bob", Password: "x"})
	if err != nil || deny.Outcome != CredDeny {
		t.Fatalf("deny = %+v err=%v", deny, err)
	}
}

// csReadFramePayload 读一个 4 字节长度帧的载荷（含 java magic）。
func csReadFramePayload(c net.Conn) []byte {
	head := make([]byte, 4)
	if _, err := readFull(c, head); err != nil {
		return nil
	}
	n := int(binary.BigEndian.Uint32(head))
	if n <= 0 || n > credReadMax {
		return nil
	}
	body := make([]byte, n)
	_, _ = readFull(c, body)
	return body
}

// ── Oracle TNS ───────────────────────────────────────────────────────────────

func TestCredOracleHitDeny(t *testing.T) {
	ep := newCredTestEndpoint(t, func(c net.Conn) {
		w := &credWire{conn: c}
		if _, _, err := tnsRead(w); err != nil { // Connect
			return
		}
		writeString(c, string(tnsPacket(2, []byte("(DESCRIPTION=(ACCEPT))")))) // Accept
		_, authBody, err := tnsRead(w)
		if err != nil {
			return
		}
		if strings.Contains(string(authBody), "AUTH_USER=admin") {
			writeString(c, string(tnsPacket(6, []byte("AUTH_OK (SESSION_ESTABLISHED)"))))
			return
		}
		writeString(c, string(tnsPacket(6, []byte("ORA-01017: invalid username/password; logon denied"))))
	})
	ctx := credCtx(t)

	ok, banner, err := oracleCredAdapter{}.Identify(ctx, credEP(ep.addr, "oracle"))
	if err != nil || !ok || !strings.Contains(banner, "TNS") {
		t.Fatalf("identify = %v %q %v", ok, banner, err)
	}
	hit, err := oracleCredAdapter{}.Try(ctx, credEP(ep.addr, "oracle"), Credential{Username: "admin", Password: "p"})
	if err != nil || hit.Outcome != CredHit {
		t.Fatalf("hit = %+v err=%v", hit, err)
	}
	deny, err := oracleCredAdapter{}.Try(ctx, credEP(ep.addr, "oracle"), Credential{Username: "scott", Password: "x"})
	if err != nil || deny.Outcome != CredDeny {
		t.Fatalf("deny = %+v err=%v", deny, err)
	}
	if !strings.Contains(deny.Reason, "ORA-01017") {
		t.Fatalf("deny reason = %q", deny.Reason)
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

// ── WinRM ────────────────────────────────────────────────────────────────────

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

func TestCredWinRMHitDeny(t *testing.T) {
	ep := newCredTestEndpoint(t, func(c net.Conn) {
		req := readLine(c)
		// 真实 WinRM 跑在 Microsoft-HTTPAPI 上：未认证请求回 401 时也带这个 Server 头，
		// 那正是 Identify 能确认「这是 WinRM 而不是任意 HTTP」的证据。
		challenge := map[string]string{
			"Server":           "Microsoft-HTTPAPI/2.0",
			"WWW-Authenticate": `Basic realm="winrm"`,
		}
		switch {
		case !strings.Contains(req, "Authorization:"):
			httpStubReply(c, 401, challenge, "")
		case strings.Contains(req, "YWRtaW46cA=="): // admin:p
			httpStubReply(c, 200, nil, `<s:Envelope><w:IdentifyResponse>wsman</w:IdentifyResponse></s:Envelope>`)
		default:
			httpStubReply(c, 401, challenge, "")
		}
	})
	ctx := credCtx(t)

	ok, banner, err := winrmCredAdapter{}.Identify(ctx, credEP(ep.addr, "winrm"))
	if err != nil || !ok || !strings.Contains(strings.ToUpper(banner), "WINRM") {
		t.Fatalf("identify = %v %q %v", ok, banner, err)
	}
	hit, err := winrmCredAdapter{}.Try(ctx, credEP(ep.addr, "winrm"), Credential{Username: "admin", Password: "p"})
	if err != nil || hit.Outcome != CredHit {
		t.Fatalf("hit = %+v err=%v", hit, err)
	}
	deny, err := winrmCredAdapter{}.Try(ctx, credEP(ep.addr, "winrm"), Credential{Username: "bob", Password: "x"})
	if err != nil || deny.Outcome != CredDeny {
		t.Fatalf("deny = %+v err=%v", deny, err)
	}
}

func TestCredWinRMNegotiateIsInconclusive(t *testing.T) {
	ep := newCredTestEndpoint(t, func(c net.Conn) {
		_ = readLine(c)
		httpStubReply(c, 401, map[string]string{"WWW-Authenticate": "Negotiate"}, "")
	})
	res, err := winrmCredAdapter{}.Try(credCtx(t), credEP(ep.addr, "winrm"), Credential{Username: "a", Password: "b"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome != CredInconclusive || !strings.Contains(res.Reason, "SPNEGO") {
		t.Fatalf("res = %+v", res)
	}
}

// ── Jenkins（表单多轮） ──────────────────────────────────────────────────────

func TestCredJenkinsHitDeny(t *testing.T) {
	ep := newCredTestEndpoint(t, func(c net.Conn) {
		line := readLine(c)
		switch {
		case strings.Contains(line, "GET /login"):
			// Jenkins 的识别点在登录页：页面里必须有 Jenkins 特有的表单动作。
			httpStubReply(c, 200, nil,
				`<html><head><title>Jenkins</title></head><body>`+
					`<form name="login" action="j_acegi_security_check" method="post"></form></body></html>`)
		case strings.Contains(line, "GET /crumbIssuer/api/json"):
			httpStubReply(c, 200, map[string]string{"Set-Cookie": "JSESSIONID=abc; Path=/"},
				`{"crumb":"c1","crumbRequestField":"Jenkins-Crumb"}`)
		case strings.Contains(line, "POST /j_acegi_security_check"):
			// 请求行、头和正文通常在同一个 TCP 段里到达，一次读全即可。
			if strings.Contains(line, "j_username=admin") {
				httpStubReply(c, 302, map[string]string{"Location": "/"}, "")
				return
			}
			httpStubReply(c, 200, nil, `<div>Invalid username or password</div>`)
		case strings.Contains(line, "GET /whoAmI/api/json"):
			httpStubReply(c, 200, nil, `{"authenticated":true,"name":"admin"}`)
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

// jenkinsCredAdapterIdentify 直接复用适配器的 Identify，避免测试另写一份识别逻辑。
func jenkinsCredAdapterIdentify(ctx context.Context, ep *credTestEndpoint) (bool, string, error) {
	return formCredAdapter{protocol: "jenkins"}.Identify(ctx, credEP(ep.addr, "jenkins"))
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
