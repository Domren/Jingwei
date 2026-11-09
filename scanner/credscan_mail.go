package scanner

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"time"
)

// 邮件三兄弟：POP3 / IMAP / SMTP（各自带一个隐式 TLS 变体）。
//
// 三家都走「一行命令一行应答」，但成功与失败的措辞完全不同：
// POP3 看 +OK/-ERR，IMAP 看标签后的 OK/NO，SMTP 看三位状态码。
// 认证过程本身也记录进证据——报告读者要能照着字节重放。
type mailCredAdapter struct {
	protocol string
	tls      bool
}

func (a mailCredAdapter) Protocol() string { return a.protocol }

func (a mailCredAdapter) connect(ctx context.Context, ep CredEndpoint) (*credWire, error) {
	w, err := credDial(ctx, credAddr(ep))
	if err != nil {
		return nil, err
	}
	if a.tls {
		if err := w.upgradeTLS(ctx, ep.Host); err != nil {
			w.close()
			return nil, err
		}
	}
	return w, nil
}

func (a mailCredAdapter) Identify(ctx context.Context, ep CredEndpoint) (bool, string, error) {
	w, err := a.connect(ctx, ep)
	if err != nil {
		return false, "", err
	}
	defer w.close()
	line, err := w.readLine(4096)
	if err != nil && len(line) == 0 {
		return false, "", err
	}
	text := strings.TrimRight(string(line), "\r\n")
	ok := false
	switch {
	case strings.HasPrefix(a.protocol, "pop3"):
		ok = strings.HasPrefix(text, "+OK")
	case strings.HasPrefix(a.protocol, "imap"):
		ok = strings.HasPrefix(text, "* OK")
	case strings.HasPrefix(a.protocol, "smtp"):
		ok = strings.HasPrefix(text, "220")
	}
	return ok, text, nil
}

func (a mailCredAdapter) Try(ctx context.Context, ep CredEndpoint, cred Credential) (res CredAttempt, err error) {
	res = credNewAttempt(cred)
	w, err := a.connect(ctx, ep)
	if err != nil {
		return res.withErr(err)
	}
	// 隐式 TLS 变体必须把通道状态写进结果：不写的话证据说明会说「以上字节是明文」，
	// 复现命令也会给成裸 socket——照那条命令连 465/995/993 是连不上的。
	// 这一条是 smtp-ssl 真机验证（aiosmtpd 隐式 TLS）抓出来的，进程内桩看不见。
	res.TLS = a.tls
	defer w.close()
	defer func() { res.syncWire(w) }()

	switch {
	case strings.HasPrefix(a.protocol, "pop3"):
		return a.tryPOP3(w, res, cred)
	case strings.HasPrefix(a.protocol, "imap"):
		return a.tryIMAP(w, res, cred)
	default:
		return a.trySMTP(w, res, cred)
	}
}

func (a mailCredAdapter) tryPOP3(w *credWire, res CredAttempt, cred Credential) (CredAttempt, error) {
	banner, err := w.readLine(4096)
	if err != nil && len(banner) == 0 {
		return res.withErr(err)
	}
	res.Banner = strings.TrimRight(string(banner), "\r\n")
	if !strings.HasPrefix(res.Banner, "+OK") {
		res.Outcome = CredInconclusive
		res.Reason = "POP3 banner 不是 +OK"
		return res, nil
	}
	if err := w.writeLine("USER " + cred.Username); err != nil {
		return res.withErr(err)
	}
	userResp, _ := w.readLine(4096)
	if !strings.HasPrefix(string(userResp), "+OK") {
		res.Outcome = CredDeny
		res.Reason = "USER 被拒：" + strings.TrimRight(string(userResp), "\r\n")
		return res, nil
	}
	if err := w.writeLine("PASS " + cred.Password); err != nil {
		return res.withErr(err)
	}
	passResp, err := w.readLineWithin(4096, 15*time.Second)
	if err != nil && len(passResp) == 0 {
		return res.withErr(err)
	}
	line := strings.TrimRight(string(passResp), "\r\n")
	if strings.HasPrefix(line, "+OK") {
		res.Outcome = CredHit
	} else {
		res.Outcome = CredDeny
		res.Reason = "PASS 被拒：" + line
	}
	_ = w.writeLine("QUIT")
	return res, nil
}

func (a mailCredAdapter) tryIMAP(w *credWire, res CredAttempt, cred Credential) (CredAttempt, error) {
	banner, err := w.readLine(4096)
	if err != nil && len(banner) == 0 {
		return res.withErr(err)
	}
	res.Banner = strings.TrimRight(string(banner), "\r\n")
	if !strings.HasPrefix(res.Banner, "* OK") {
		res.Outcome = CredInconclusive
		res.Reason = "IMAP banner 不是 * OK"
		return res, nil
	}
	cmd := fmt.Sprintf(`a1 LOGIN %s %s`, imapQuote(cred.Username), imapQuote(cred.Password))
	if err := w.writeLine(cmd); err != nil {
		return res.withErr(err)
	}
	var last string
	for i := 0; i < 20; i++ {
		line, err := w.readLineWithin(8192, 15*time.Second)
		if err != nil && len(line) == 0 {
			return res.withErr(err)
		}
		text := strings.TrimRight(string(line), "\r\n")
		last = text
		if strings.HasPrefix(text, "a1 ") {
			break
		}
	}
	switch {
	case strings.HasPrefix(last, "a1 OK"):
		res.Outcome = CredHit
	case strings.HasPrefix(last, "a1 NO"), strings.HasPrefix(last, "a1 BAD"):
		res.Outcome = CredDeny
		res.Reason = last
	default:
		res.Outcome = CredInconclusive
		res.Reason = "LOGIN 没有得到带标签的应答：" + last
	}
	_ = w.writeLine("a2 LOGOUT")
	return res, nil
}

// imapQuote 用 IMAP 的带引号字符串传输非 ASCII/含特殊字符的账号口令：
// 反斜杠与双引号要转义，CRLF 直接拒绝（那是命令注入）。
func imapQuote(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return `"` + s + `"`
}

func (a mailCredAdapter) trySMTP(w *credWire, res CredAttempt, cred Credential) (CredAttempt, error) {
	banner, err := w.readLine(4096)
	if err != nil && len(banner) == 0 {
		return res.withErr(err)
	}
	res.Banner = strings.TrimRight(string(banner), "\r\n")
	if !strings.HasPrefix(res.Banner, "220") {
		res.Outcome = CredInconclusive
		res.Reason = "SMTP banner 不是 220"
		return res, nil
	}
	if err := w.writeLine("EHLO jingwei.invalid"); err != nil {
		return res.withErr(err)
	}
	ehlo, authLine := smtpReadMultiline(w)
	if !strings.HasPrefix(ehlo, "250") {
		res.Outcome = CredInconclusive
		res.Reason = "EHLO 被拒：" + credPreview([]byte(ehlo))
		return res, nil
	}
	mechs := strings.ToUpper(authLine)
	usePlain := strings.Contains(mechs, "PLAIN") || mechs == ""
	useLogin := strings.Contains(mechs, "LOGIN")
	if !usePlain && !useLogin {
		res.Outcome = CredInconclusive
		res.Reason = "服务器没有提供 AUTH PLAIN/LOGIN：" + authLine
		return res, nil
	}
	if cred.Username == "" && cred.Password == "" {
		// 空凭据不可能是 SMTP 认证通过：AUTH 没有「匿名」语义。
		res.Outcome = CredDeny
		res.Reason = "SMTP 不支持匿名认证，空凭据不构成可用凭据"
		return res, nil
	}
	var reply string
	if usePlain {
		token := base64.StdEncoding.EncodeToString([]byte("\x00" + cred.Username + "\x00" + cred.Password))
		if err := w.writeLine("AUTH PLAIN " + token); err != nil {
			return res.withErr(err)
		}
		line, _ := w.readLineWithin(4096, 15*time.Second)
		reply = strings.TrimRight(string(line), "\r\n")
	} else {
		_ = w.writeLine("AUTH LOGIN")
		_, _ = w.readLineWithin(4096, 15*time.Second)
		_ = w.writeLine(base64.StdEncoding.EncodeToString([]byte(cred.Username)))
		_, _ = w.readLineWithin(4096, 15*time.Second)
		_ = w.writeLine(base64.StdEncoding.EncodeToString([]byte(cred.Password)))
		line, _ := w.readLineWithin(4096, 15*time.Second)
		reply = strings.TrimRight(string(line), "\r\n")
	}
	switch {
	case strings.HasPrefix(reply, "235"):
		res.Outcome = CredHit
	case strings.HasPrefix(reply, "535"), strings.HasPrefix(reply, "534"), strings.HasPrefix(reply, "530"):
		res.Outcome = CredDeny
		res.Reason = "AUTH 被拒：" + reply
	default:
		res.Outcome = CredInconclusive
		res.Reason = "AUTH 应答无法判定：" + reply
	}
	_ = w.writeLine("QUIT")
	return res, nil
}

// smtpReadMultiline 读 EHLO 的多行应答（250- 续行、250 结束），返回全部文本与 AUTH 行。
func smtpReadMultiline(w *credWire) (string, string) {
	var all []string
	auth := ""
	for i := 0; i < 50; i++ {
		line, err := w.readLine(4096)
		if err != nil && len(line) == 0 {
			break
		}
		text := strings.TrimRight(string(line), "\r\n")
		all = append(all, text)
		if strings.HasPrefix(strings.ToUpper(text), "250-AUTH") || strings.HasPrefix(strings.ToUpper(text), "250 AUTH") {
			auth = strings.TrimSpace(text[4:])
		}
		if len(text) < 4 || text[3] != '-' {
			break
		}
	}
	return strings.Join(all, " | "), auth
}

func init() {
	for _, p := range []struct {
		name string
		tls  bool
	}{
		{"smtp", false}, {"smtp-ssl", true},
		{"pop3", false}, {"pop3-ssl", true},
		{"imap", false}, {"imap-ssl", true},
	} {
		RegisterCredAdapter(mailCredAdapter{protocol: p.name, tls: p.tls})
	}
}
