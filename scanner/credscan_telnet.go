package scanner

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"regexp"
	"strings"
	"time"
)

// Telnet 认证探针。telnet 没有认证层——「登录成功」只能从提示语的形状判断，
// 所以这里的分类比别的协议更保守：认不出特征就是不可判定，不猜。
type telnetCredAdapter struct{}

func (telnetCredAdapter) Protocol() string { return "telnet" }

const (
	telnetIAC  = 255
	telnetWill = 251
	telnetWont = 252
	telnetDo   = 253
	telnetDont = 254
	// telnetPromptWait 是等一句提示语的上限。登录要走 PAM，比 banner 协议慢。
	telnetPromptWait = 4 * time.Second
	// telnetSessionWait 是「送出口令之后」总共愿意等多久看结果。
	telnetSessionWait = 9 * time.Second
)

var (
	telnetLoginPromptRe = regexp.MustCompile(`(?i)(login\s*:|username\s*:|user\s*name\s*:|user\s*:)`)
	telnetPassPromptRe  = regexp.MustCompile(`(?i)(password\s*:|passphrase\s*|验证口令)`)
	telnetDenyRe        = regexp.MustCompile(`(?i)(login\s+incorrect|login\s+failed|authentication\s+failed|access\s+denied|bad\s+password|invalid\s+user|login\s+not\s+valid)`)
	// 登录后特征：欢迎语、上次登录时间、或一个 shell 提示符。宁可漏报不可误报，
	// 所以只认这几类明确形状。
	telnetHitRe = regexp.MustCompile(`(?i)(last\s+login|welcome\s+to|success|system\s+ready|[\$#>]\s*$)`)
)

// Identify 认 telnet 的形状：带 IAC 协商，或者直接给登录提示。
// 两者都没有就不是这个协议——23 端口上跑的东西比想象中多。
func (a telnetCredAdapter) Identify(ctx context.Context, ep CredEndpoint) (bool, string, error) {
	addr := credAddr(ep)
	w, err := credDial(ctx, addr)
	if err != nil {
		return false, "", err
	}
	defer w.close()
	text, raw, err := telnetRead(w, telnetPromptWait)
	if err != nil {
		return false, text, err
	}
	if bytes.Contains(raw, []byte{telnetIAC}) || telnetLoginPromptRe.MatchString(text) {
		return true, text, nil
	}
	return false, text, nil
}

func (a telnetCredAdapter) Try(ctx context.Context, ep CredEndpoint, cred Credential) (res CredAttempt, err error) {
	addr := credAddr(ep)
	res = credNewAttempt(cred)
	w, err := credDial(ctx, addr)
	if err != nil {
		return res.withErr(err)
	}
	defer w.close()
	defer func() { res.syncWire(w) }()

	first, _, err := telnetRead(w, telnetPromptWait)
	if err != nil && first == "" {
		return res.withErr(err)
	}
	res.Banner = credPreview([]byte(first))
	if telnetDenyRe.MatchString(first) {
		res.Outcome = CredInconclusive
		res.Reason = "接通即给出失败提示，未见登录入口：" + credPreview([]byte(first))
		return res, nil
	}
	if !telnetLoginPromptRe.MatchString(first) && !strings.Contains(strings.ToLower(first), "login") {
		res.Outcome = CredInconclusive
		res.Reason = "没有等到登录提示，无法判断该往哪儿送账号：" + credPreview([]byte(first))
		return res, nil
	}
	user, userDirty := credSanitizeLine(cred.Username)
	pass, passDirty := credSanitizeLine(cred.Password)
	if userDirty || passDirty {
		res.Outcome = CredInconclusive
		res.Reason = "凭据含换行或 NUL，未发送（需要先清洗字典）"
		return res, nil
	}
	if err = w.writeLine(user); err != nil {
		return res.withErr(err)
	}
	afterUser, _, err := telnetRead(w, telnetPromptWait)
	if err != nil && afterUser == "" {
		return res.withErr(err)
	}
	if telnetPassPromptRe.MatchString(afterUser) {
		if err = w.writeLine(pass); err != nil {
			return res.withErr(err)
		}
		final := telnetReadUntil(w, telnetSessionWait, telnetSettled)
		return classifyTelnetSession(res, afterUser, final, pass), nil
	}
	// 没要口令就给结论：可能是 -a 模式（账号直通）或登录已失败。
	if telnetDenyRe.MatchString(afterUser) || telnetLoginPromptRe.MatchString(afterUser) {
		res.Outcome = CredDeny
		res.Reason = "服务端对这个账号未要求口令即给出失败/重新登录提示"
		return res, nil
	}
	if telnetHitRe.MatchString(afterUser) {
		if strings.TrimSpace(cred.Password) == "" {
			res.Outcome = CredHit
			res.Reason = "服务端未要求口令（等价于空口令可用）"
			return res, nil
		}
		res.Outcome = CredDeny
		res.Reason = "服务端未要求口令，非空口令不构成可用凭据"
		return res, nil
	}
	res.Outcome = CredInconclusive
	res.Reason = "送出账号后既没要口令也没给出可判定的提示：" + credPreview([]byte(afterUser))
	return res, nil
}

// telnetSettled 判断「这段回显已经可以定论了」。telnet 没有认证层，成功与失败只能从
// 回显形状读，所以这里宁可多等一段，也不要在只看了一段的时候就下结论。
func telnetSettled(text string) bool {
	return telnetHitRe.MatchString(text) || telnetDenyRe.MatchString(text) ||
		credLockedText(strings.ToLower(text))
}

// telnetReadUntil 持续读到出现可判定的形状、或对端不再说话。
//
// 成功登录的回显是一段一段来的（内核行、MOTD、发行版提示框，最后才是 shell 提示符），
// 段与段之间的间隔能超过一个静默期。只读一段就判「认不出特征」，等于把一次真实命中
// 写成不可判定——操作员会以为这台机器的登录提示被改过。
func telnetReadUntil(w *credWire, total time.Duration, done func(string) bool) string {
	lim := time.Now().Add(total)
	var text string
	for time.Now().Before(lim) {
		chunk, _, err := telnetRead(w, telnetPromptWait)
		text += chunk
		if done(text) {
			break
		}
		if chunk == "" {
			if err != nil {
				break
			}
			continue
		}
	}
	return text
}

// classifyTelnetSession 判结果。before 是「要口令那一段」，after 是「送出口令之后」——
// 必须分开看：before 里本来就带着 "Password:"，合在一起判会把我们自己应答过的那句
// 当成「又要了一次口令」，于是把 deny 记成 hit（真机验证里错过一次）。
func classifyTelnetSession(res CredAttempt, before, after, pass string) CredAttempt {
	switch {
	case credLockedText(strings.ToLower(after)):
		res.Outcome = CredLocked
		res.Reason = "目标提示账号锁定或访问被暂时封禁，已停手"
	case telnetDenyRe.MatchString(after):
		res.Outcome = CredDeny
	case telnetLoginPromptRe.MatchString(after) && !telnetHitRe.MatchString(after):
		// 又回到登录提示 = 这组口令没过。这是 telnet 最常见的拒绝形状（不会明确说失败）。
		res.Outcome = CredDeny
	case telnetHitRe.MatchString(after):
		res.Outcome = CredHit
	case strings.TrimSpace(after) == "":
		res.Outcome = CredInconclusive
		res.Reason = "送出凭据后对端没有再回显任何内容，判不了：" + credPreview([]byte(before))
	default:
		res.Outcome = CredInconclusive
		res.Reason = "送出凭据后回显里没有可判定的特征：" + credPreview([]byte(after))
	}
	if res.Outcome == CredHit {
		res.Reason = "登录后回显给出了 shell 提示或欢迎语（telnet 无认证层，判定只能靠回显形状）"
	}
	return res
}

// telnetRead 读到「没有新字节」或到点为止，返回去掉 IAC 的文本与原始字节。
// 协商字节要按标准应答回去（不应答时某些 telnetd 会一直等着，提示语就不来了），
// 应答本身也进 RawReq——证据里看得出它们排在凭据之前。
func telnetRead(w *credWire, wait time.Duration) (string, []byte, error) {
	lim := time.Now().Add(wait)
	idle := w.idle
	if idle <= 0 {
		idle = credReadIdle
	}
	var text, raw []byte
	buf := make([]byte, 1024)
	for {
		left := time.Until(lim)
		if left <= 0 {
			break
		}
		readWait := idle
		if readWait > left {
			readWait = left
		}
		_ = w.conn.SetReadDeadline(time.Now().Add(readWait))
		n, err := w.conn.Read(buf)
		if n > 0 {
			chunk := buf[:n]
			raw = append(raw, chunk...)
			text = append(text, telnetStrip(chunk)...)
			for _, reply := range telnetReplies(chunk) {
				if werr := w.write(reply); werr != nil {
					return string(text), raw, werr
				}
			}
			if len(raw) >= credReadMax {
				break
			}
			continue
		}
		if len(raw) > 0 {
			break // 读超时但有内容：telnet 的提示语就是「发到这里为止」
		}
		if err == nil {
			err = io.EOF
		}
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			err = nil // 对端一个字都不发：等到点，交回空文本让调用方判定
			break
		}
		return string(text), raw, err
	}
	w.recordRead(raw)
	return string(text), raw, nil
}

// telnetStrip 去掉 IAC 序列，只留数据。命令之间没有边界，所以按状态机走。
func telnetStrip(b []byte) []byte {
	out := make([]byte, 0, len(b))
	for i := 0; i < len(b); i++ {
		if b[i] == telnetIAC && i+2 < len(b) && (b[i+1] == telnetWill || b[i+1] == telnetWont ||
			b[i+1] == telnetDo || b[i+1] == telnetDont) {
			i += 2
			continue
		}
		if b[i] == telnetIAC && i+1 < len(b) && b[i+1] == telnetIAC {
			out = append(out, telnetIAC) // 转义的裸 0xFF
			i++
			continue
		}
		if b[i] == telnetIAC {
			continue // 半截协商（下一个包才补齐），丢掉比猜出来安全
		}
		out = append(out, b[i])
	}
	return out
}

// telnetReplies 对 DO 一律 WONT、对 WILL 一律 DONT：本平台不需要任何 telnet 选项，
// 应答的目的在于让对端别再等协商，好把提示语发出来。
func telnetReplies(b []byte) [][]byte {
	var out [][]byte
	for i := 0; i+2 < len(b); i++ {
		if b[i] != telnetIAC {
			continue
		}
		switch b[i+1] {
		case telnetDo:
			out = append(out, []byte{telnetIAC, telnetWont, b[i+2]})
		case telnetWill:
			out = append(out, []byte{telnetIAC, telnetDont, b[i+2]})
		}
		i += 2
	}
	return out
}

func init() { RegisterCredAdapter(telnetCredAdapter{}) }
