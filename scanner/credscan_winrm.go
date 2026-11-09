package scanner

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
)

// WinRM / WSMan 适配器。
//
// 未在真机验证：WinRM 只在 Windows 靶机上起得来，本平台没有该环境。本适配器实现的是
// HTTP/SOAP 层可复现的形态（POST /wsman + Basic），hit 取「200 + 应答体是 WSMan
// IdentifyResponse」这个握手层接受信号；服务端要求 Negotiate/NTLM/Kerberos 时如实落
// inconclusive（本平台不实现 SPNEGO），不猜也不写「已在真机跑通」。
// hit/deny 双路径由 scanner/credscan_adapters_test.go 的进程内协议桩验证。

const winrmIdentifyBody = `<?xml version="1.0" encoding="utf-8"?>` +
	`<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" ` +
	`xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd">` +
	`<s:Header/><s:Body><w:Identify/></s:Body></s:Envelope>`

type winrmCredAdapter struct{}

func (winrmCredAdapter) Protocol() string { return "winrm" }

func winrmRequest(path, host, auth, body string) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "POST %s HTTP/1.1\r\n", path)
	fmt.Fprintf(&b, "Host: %s\r\n", host)
	b.WriteString("User-Agent: Jingwei-CredScan\r\n")
	b.WriteString("Content-Type: application/soap+xml;charset=UTF-8\r\n")
	b.WriteString("Connection: close\r\n")
	if auth != "" {
		fmt.Fprintf(&b, "Authorization: %s\r\n", auth)
	}
	fmt.Fprintf(&b, "Content-Length: %d\r\n", len(body))
	b.WriteString("\r\n")
	b.WriteString(body)
	return []byte(b.String())
}

func (a winrmCredAdapter) Identify(ctx context.Context, ep CredEndpoint) (bool, string, error) {
	w := newFormWire(ctx)
	req := winrmRequest(formPath(ep, "/wsman"), ep.Host, "", winrmIdentifyBody)
	status, hdr, body, err := formRound(ctx, w, credAddr(ep), req)
	if err != nil {
		return false, "", err
	}
	if status == 0 {
		return false, credPreview(w.resp), nil
	}
	proof := httpProof("winrm", status, hdr, body)
	return proof != "", httpBanner("winrm", status, hdr, proof), nil
}

func (a winrmCredAdapter) Try(ctx context.Context, ep CredEndpoint, cred Credential) (res CredAttempt, err error) {
	res = credNewAttempt(cred)
	w := newFormWire(ctx)
	defer func() { res.syncWire(w) }()
	addr := credAddr(ep)
	path := formPath(ep, "/wsman")
	auth := "Basic " + base64.StdEncoding.EncodeToString([]byte(cred.Username+":"+cred.Password))
	req := winrmRequest(path, ep.Host, auth, winrmIdentifyBody)
	status, hdr, body, err := formRound(ctx, w, addr, req)
	if err != nil {
		return res.withErr(err)
	}
	res.Banner = httpBanner("winrm", status, hdr, httpProof("winrm", status, hdr, body))

	if status == 401 || status == 407 {
		wa := strings.ToLower(hdr["www-authenticate"])
		if !strings.Contains(wa, "basic") &&
			(strings.Contains(wa, "negotiate") || strings.Contains(wa, "kerberos") || strings.Contains(wa, "ntlm")) {
			res.Outcome = CredInconclusive
			res.Reason = "WinRM 服务端要求 Negotiate/NTLM/Kerberos，本平台不实现 SPNEGO，未对该凭据下结论"
			return res, nil
		}
		res.Outcome = CredDeny
		return res, nil
	}
	if status >= 200 && status < 300 {
		// 无凭据对照：不带 Authorization 再发一次 WSMan Identify。
		w2 := newFormWire(ctx)
		req2 := winrmRequest(path, ep.Host, "", winrmIdentifyBody)
		st2, _, _, e2 := formRound(ctx, w2, addr, req2)
		w.req = append(w.req, w2.req...)
		w.resp = append(w.resp, w2.resp...)
		if e2 == nil && st2 >= 200 && st2 < 300 {
			res.Outcome = CredDeny
			res.Reason = "该 WinRM 端点不带凭据也返回成功（未启用认证），非空凭据不构成可用凭据"
			return res, nil
		}
		low := strings.ToLower(string(body))
		if strings.Contains(low, "identifyresponse") || strings.Contains(low, "wsman") ||
			strings.Contains(low, "schemas.dmtf.org/wbem/wsman") {
			res.Outcome = CredHit
			return res, nil
		}
		res.Outcome = CredInconclusive
		res.Reason = "WinRM 返回 2xx 但应答体不是 WSMan IdentifyResponse，不能确认凭据被接受"
		return res, nil
	}
	if status == 403 {
		res.Outcome = CredInconclusive
		res.Reason = "WinRM 返回 403：可能凭据有效但无权，不计入命中"
		return res, nil
	}
	res.Outcome = CredInconclusive
	res.Reason = fmt.Sprintf("WinRM 返回 HTTP %d，无法据此判定凭据", status)
	return res, nil
}

func init() { RegisterCredAdapter(winrmCredAdapter{}) }
