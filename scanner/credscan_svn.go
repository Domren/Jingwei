package scanner

import (
	"context"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
)

// svnserve (svn://) 登录探针。
//
// 服务端一连上就发 `( success ( 2 2 ( ) ( edit-pipeline ... ) ) )` 这种 S-expression
// greeting——「success + edit-pipeline/svn」是 svnserve 特有的，不靠 3690 端口猜。
// 之后客户端回 capabilities、服务端要认证、客户端提交凭据、服务端给最终 success/failure。
//
// 限制（如实写明）：svnserve 的 SASL CRAM-MD5 完整协商未实现，本版提交的是 ANONYMOUS/
// PLAIN 最小形态（口令以 base64 承载）。真机需按 svnserve.conf 的 SASL 配置补齐认证交换。
// lab 里登记了 svnserve 真服务用例，但本轮未在真机验证；hit/deny 双路径由进程内协议桩覆盖。

type svnCredAdapter struct{}

func (svnCredAdapter) Protocol() string { return "svn" }

func svnIsGreeting(b []byte) bool {
	low := strings.ToLower(string(b))
	return strings.Contains(low, "success") &&
		(strings.Contains(low, "edit-pipeline") || strings.Contains(low, "svn"))
}

func svnIsSuccess(b []byte) bool {
	return strings.HasPrefix(strings.TrimSpace(string(b)), "( success")
}

func svnIsFailure(b []byte) bool {
	low := strings.ToLower(string(b))
	return strings.Contains(low, "failure") || strings.Contains(low, "authentication failed") ||
		strings.Contains(low, "not authorized") || strings.Contains(low, "access denied")
}

func svnHello(ep CredEndpoint) string {
	url := "svn://" + ep.Host + ":" + strconv.Itoa(ep.Port) + "/"
	return "( 2 ( edit-pipeline svndiff1 ) " + strconv.Itoa(len(url)) + ":" + url + " ( ) )\n"
}

func svnCreds(cred Credential) string {
	raw := "\x00" + cred.Username + "\x00" + cred.Password
	return "( PLAIN " + base64.StdEncoding.EncodeToString([]byte(raw)) + " )\n"
}

func (a svnCredAdapter) Identify(ctx context.Context, ep CredEndpoint) (bool, string, error) {
	w, err := credDial(ctx, credAddr(ep))
	if err != nil {
		return false, "", err
	}
	defer w.close()
	line, err := w.readLine(8 << 10)
	if err != nil && len(line) == 0 {
		return false, "", err
	}
	if !svnIsGreeting(line) {
		return false, credPreview(line), nil
	}
	return true, "svnserve greeting：" + credPreview(line), nil
}

func (a svnCredAdapter) Try(ctx context.Context, ep CredEndpoint, cred Credential) (res CredAttempt, err error) {
	res = credNewAttempt(cred)
	w, err := credDial(ctx, credAddr(ep))
	if err != nil {
		return res.withErr(err)
	}
	defer w.close()
	defer func() { res.syncWire(w) }()

	greeting, err := w.readLine(8 << 10)
	if err != nil && len(greeting) == 0 {
		return res.withErr(err)
	}
	res.Banner = credPreview(greeting)
	if !svnIsGreeting(greeting) {
		res.Outcome = CredInconclusive
		res.Reason = "首包不是 svnserve greeting，不能按 SVN 协议下结论"
		return res, nil
	}
	if err = w.write([]byte(svnHello(ep))); err != nil {
		return res.withErr(err)
	}
	// 服务端要认证的那一轮（challenge / mech list），内容不参与判定，但字节要留证。
	if _, err = w.readLine(8 << 10); err != nil {
		return res.withErr(err)
	}
	if err = w.write([]byte(svnCreds(cred))); err != nil {
		return res.withErr(err)
	}
	final, err := w.readLine(8 << 10)
	if err != nil && len(final) == 0 {
		return res.withErr(err)
	}
	res.Banner = credPreview(final)
	switch {
	case svnIsSuccess(final):
		// 最终 success 才是握手层「接受」，greeting 里那个 success 不算。
		res.Outcome = CredHit
	case svnIsFailure(final):
		if credLockedText(strings.ToLower(string(final))) {
			res.Outcome = CredLocked
			res.Reason = "目标提示账号锁定或访问封禁，已停手"
			return res, nil
		}
		res.Outcome = CredDeny
	default:
		res.Outcome = CredInconclusive
		res.Reason = fmt.Sprintf("svnserve 最终应答既非 success 也非 failure，不能对这组凭据下结论：%s", credPreview(final))
	}
	return res, nil
}

func init() { RegisterCredAdapter(svnCredAdapter{}) }
