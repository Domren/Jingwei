package scanner

import (
	"context"
	"crypto/hmac"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

// svnserve (svn://) 登录探针。
//
// 服务端一连上就发 `( success ( 2 2 ( ) ( edit-pipeline ... ) ) )` 这种 S-expression
// greeting——「success + edit-pipeline/svn」是 svnserve 特有的，不靠 3690 端口猜。
//
// 认证按 svnserve 真实机制 CRAM-MD5 实现（对齐 subversion 1.14 客户端抓到的字节序列）：
//
//	客户端 → ( 2 ( edit-pipeline svndiff1 ) <len>:<url> <len>:<client> ( ) )
//	服务端 → ( success ( ( CRAM-MD5 ) <len>:<realm> ) )
//	客户端 → ( CRAM-MD5 ( ) )
//	服务端 → ( step ( <len>:<challenge> ) )
//	客户端 → <len>:<user> <hex-digest>          ← 裸字符串，不带括号
//	服务端 → ( success ( ) ) / ( failure ... )
//
// digest = HMAC-MD5(key = 口令, msg = challenge 原样字节含尖括号)，口径用真 svnserve
// 的抓包反推确认过（含 `<>` 才算对，去掉尖括号算出来的值对不上）。
//
// 仍在的限制（如实写明）：仓库路径靠 CredParamPath 传入（默认 "/"），svnserve 用 -r
// 虚拟根时路径写相对路径；SASL 型 svnserve（GSSAPI/PLAIN）未覆盖，只保留 PLAIN 分支
// 作为兼容，服务端不宣告任何可用机制时落 inconclusive 而不是猜。

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

// svnURL 拼被测仓库 URL。路径来自 CredParamPath（pentest 里 svn://host/repo 是常态，
// 只打根路径在 -r 虚拟根下会连到「没有仓库」而不是被测对象）。
func svnURL(ep CredEndpoint) string {
	path := strings.TrimSpace(CredParam(ep, CredParamPath, ""))
	if path != "" && !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	if path == "" {
		path = "/"
	}
	return "svn://" + ep.Host + ":" + strconv.Itoa(ep.Port) + path
}

// svnClientString 是 hello 里的客户端标识。真客户端必须带这一项：缺了它服务端解析
// 后续项会错位，表现为「发完 hello 服务端直接断连」（切实验证过）。
const svnClientString = "SVN/1.14.5 (x86_64-pc-linux-gnu) jingwei"

func svnHello(ep CredEndpoint) string {
	url := svnURL(ep)
	return "( 2 ( edit-pipeline svndiff1 ) " +
		strconv.Itoa(len(url)) + ":" + url + " " +
		strconv.Itoa(len(svnClientString)) + ":" + svnClientString + " ( ) ) "
}

// svnCreds 是 SASL PLAIN 形态（部分开 SASL 的 svnserve 会宣告 PLAIN）。
// 原生 svnserve 走的是 CRAM-MD5，见 svnCRAMStep。
func svnCreds(cred Credential) string {
	raw := "\x00" + cred.Username + "\x00" + cred.Password
	return "( PLAIN " + base64.StdEncoding.EncodeToString([]byte(raw)) + " )\n"
}

// svnLengthPrefixed 取 svn 协议里 "<len>:<bytes>" 形式的字符串。
// 返回字符串内容与剩余偏移；形状不对时 ok=false（不猜边界）。
func svnLengthPrefixed(b []byte, from int) (string, int, bool) {
	i := from
	for i < len(b) && b[i] == ' ' {
		i++
	}
	start := i
	for i < len(b) && b[i] >= '0' && b[i] <= '9' {
		i++
	}
	if i == start || i >= len(b) || b[i] != ':' {
		return "", from, false
	}
	n, err := strconv.Atoi(string(b[start:i]))
	if err != nil || n < 0 || i+1+n > len(b) {
		return "", from, false
	}
	return string(b[i+1 : i+1+n]), i + 1 + n, true
}

// svnChallenge 从 `( step ( <len>:<challenge> ) )` 里取出 challenge 原样字节。
// 原样很重要：HMAC 的 msg 就是这串字节（含尖括号），多一个或少一个都不对。
func svnChallenge(line []byte) (string, bool) {
	low := strings.ToLower(string(line))
	if !strings.Contains(low, "step") {
		return "", false
	}
	i := strings.Index(string(line), "(")
	if i < 0 {
		return "", false
	}
	// 跳过 "( step ( " 三个左括号里的前两个，定位到 challenge 的长度前缀。
	pos := strings.Index(string(line[i:]), "(")
	for n := 0; n < 2 && pos >= 0; n++ {
		rest := i + pos + 1
		if s, _, ok := svnLengthPrefixed(line, rest); ok {
			return s, true
		}
		next := strings.Index(string(line[rest:]), "(")
		if next < 0 {
			break
		}
		pos = pos + 1 + next
	}
	return "", false
}

// svnCRAMResponse 算 CRAM-MD5 应答：hex(HMAC-MD5(口令, challenge))。
func svnCRAMResponse(password, challenge string) string {
	m := hmac.New(md5.New, []byte(password))
	m.Write([]byte(challenge))
	return hex.EncodeToString(m.Sum(nil))
}

// svnAuthRequest 是客户端提交凭据的那一帧：裸字符串 `<len>:<user> <digest> `，
// 不带括号（真客户端就是这样发的）。
func svnAuthRequest(user, digest string) string {
	payload := user + " " + digest
	return strconv.Itoa(len(payload)) + ":" + payload + " "
}

// svnMechs 从 mech list 里取机制名。服务端可能给多个机制，逐个扫。
func svnMechs(line []byte) []string {
	up := strings.ToUpper(string(line))
	out := make([]string, 0, 4)
	for _, m := range []string{"CRAM-MD5", "PLAIN", "ANONYMOUS"} {
		if strings.Contains(up, m) {
			out = append(out, m)
		}
	}
	return out
}

// svnReadMsg 读一条 svn 报文。svn 的 S-expression 用空格分隔、**没有结尾换行**，
// 所以必须按「静默期」收一条，而不是等 '\n'：等换行会把每条报文的收尾都拖满首包耐心
// （6s），一轮 CRAM-MD5 有 4 条报文，直接吃光单次尝试的 20s 上限（真机验证时踩到，
// 表现为「dial tcp: i/o timeout」——其实是前一条读把 ctx 预算耗完了）。
func svnReadMsg(w *credWire) ([]byte, error) {
	wait := w.idle
	if wait <= 0 {
		wait = credReadIdle
	}
	return w.readLineWithin(64<<10, wait)
}

func (a svnCredAdapter) Identify(ctx context.Context, ep CredEndpoint) (bool, string, error) {
	w, err := credDial(ctx, credAddr(ep))
	if err != nil {
		return false, "", err
	}
	defer w.close()
	line, err := svnReadMsg(w)
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

	greeting, err := svnReadMsg(w)
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
	mechLine, err := svnReadMsg(w)
	if err != nil && len(mechLine) == 0 {
		return res.withErr(err)
	}
	if svnIsFailure(mechLine) {
		// 服务端直接回了 failure（例如仓库路径不对）：这是明确的拒绝，但拒绝的是
		// 「这次请求」而不是这组凭据，所以不能写成 deny。
		res.Banner = credPreview(mechLine)
		res.Outcome = CredInconclusive
		res.Reason = "svnserve 在认证前拒绝该请求（多见仓库路径不对）：" + credPreview(mechLine)
		return res, nil
	}

	mechs := svnMechs(mechLine)
	var finalLine []byte
	switch {
	case svnHasMech(mechs, "CRAM-MD5"):
		if finalLine, err = svnCRAMAuth(w, cred); err != nil {
			return res.withErr(err)
		}
	case svnHasMech(mechs, "PLAIN"):
		if err = w.write([]byte(svnCreds(cred))); err != nil {
			return res.withErr(err)
		}
		if finalLine, err = svnReadMsg(w); err != nil && len(finalLine) == 0 {
			return res.withErr(err)
		}
	default:
		res.Banner = credPreview(mechLine)
		res.Outcome = CredInconclusive
		res.Reason = fmt.Sprintf("svnserve 没有宣告可用的认证机制（仅 %s），本平台不实现该机制",
			strings.TrimSpace(credPreview(mechLine)))
		return res, nil
	}

	res.Banner = credPreview(finalLine)
	switch {
	case svnIsSuccess(finalLine):
		// CRAM-MD5 的 success 只在口令校验通过后才发，这就是握手层「接受」。
		res.Outcome = CredHit
	case svnIsFailure(finalLine):
		if credLockedText(strings.ToLower(string(finalLine))) {
			res.Outcome = CredLocked
			res.Reason = "目标提示账号锁定或访问封禁，已停手"
			return res, nil
		}
		res.Outcome = CredDeny
		res.Reason = "svnserve 拒绝该组凭据：" + credPreview(finalLine)
	default:
		res.Outcome = CredInconclusive
		res.Reason = fmt.Sprintf("svnserve 最终应答既非 success 也非 failure，不能对这组凭据下结论：%s", credPreview(finalLine))
	}
	return res, nil
}

func svnHasMech(mechs []string, want string) bool {
	for _, m := range mechs {
		if m == want {
			return true
		}
	}
	return false
}

// svnCRAMAuth 走一遍 CRAM-MD5：报机制 → 拿 challenge → 回 <user> <digest>。
func svnCRAMAuth(w *credWire, cred Credential) ([]byte, error) {
	if err := w.write([]byte("( CRAM-MD5 ( ) ) ")); err != nil {
		return nil, err
	}
	step, err := svnReadMsg(w)
	if err != nil && len(step) == 0 {
		return nil, err
	}
	challenge, ok := svnChallenge(step)
	if !ok {
		// 形状认不出就把这一帧原样交回去，由上层落 inconclusive（不硬猜 digest）。
		return step, nil
	}
	if err := w.write([]byte(svnAuthRequest(cred.Username, svnCRAMResponse(cred.Password, challenge)))); err != nil {
		return nil, err
	}
	final, err := svnReadMsg(w)
	if err != nil && len(final) == 0 {
		return nil, err
	}
	return final, nil
}

func init() { RegisterCredAdapter(svnCredAdapter{}) }
