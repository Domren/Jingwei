package scanner

import (
	"context"
	"strconv"
	"strings"
)

// FTP 认证探针（RFC 959 的 USER/PASS）。
type ftpCredAdapter struct{}

func (ftpCredAdapter) Protocol() string { return "ftp" }

// Identify 不发包：FTP 服务器一接通就自己报 220。只认 220，别的码不算确认——
// 「端口有人应答」与「这个端口是 FTP」是两件事。
func (a ftpCredAdapter) Identify(ctx context.Context, ep CredEndpoint) (bool, string, error) {
	addr := credAddr(ep)
	w, err := credDial(ctx, addr)
	if err != nil {
		return false, "", err
	}
	defer w.close()
	raw, err := w.read()
	if err != nil {
		return false, "", err
	}
	return ftpCode(raw) == 220, credPreview(raw), nil
}

func (a ftpCredAdapter) Try(ctx context.Context, ep CredEndpoint, cred Credential) (res CredAttempt, err error) {
	addr := credAddr(ep)
	res = credNewAttempt(cred)
	w, err := credDial(ctx, addr)
	if err != nil {
		return res.withErr(err)
	}
	defer w.close()
	defer func() { res.syncWire(w) }()

	banner, err := w.read()
	if err != nil {
		return res.withErr(err)
	}
	res.Banner = credPreview(banner)
	switch code := ftpCode(banner); code {
	case 220:
	case 421, 430, 451, 530:
		// 还没给登录提示就拒绝：可能是地址被临时封（faillog/TCP wrappers），也可能是服务
		// 正下线。前者是 locked（必须停手），后者与凭据无关；两种都不能写成「口令被拒」。
		if credLockedText(strings.ToLower(string(banner))) {
			res.Outcome = CredLocked
			res.Reason = "目标在登录提示之前就拒绝该来源，符合访问封禁特征，已停手"
			return res, nil
		}
		res.Outcome = CredInconclusive
		res.Reason = "服务在给出登录提示前就拒绝（" + strconv.Itoa(code) + "），与凭据无关"
		return res, nil
	default:
		res.Outcome = CredInconclusive
		res.Reason = "首个回复不是 220 banner（" + strconv.Itoa(code) + "）"
		return res, nil
	}

	user, userDirty := credSanitizeLine(cred.Username)
	pass, passDirty := credSanitizeLine(cred.Password)
	if userDirty || passDirty {
		// 含换行的凭据不发送：那会把自己变成两条命令，之后的回复描述的就不是这组凭据了。
		res.Outcome = CredInconclusive
		res.Reason = "凭据含换行或 NUL，未发送（需要先清洗字典）"
		return res, nil
	}
	if err = w.writeLine("USER " + user); err != nil {
		return res.withErr(err)
	}
	reply, err := w.read()
	if err != nil {
		return res.withErr(err)
	}
	switch code := ftpCode(reply); code {
	case 230:
		// 免口令直接进（某些匿名配置）：这组凭据确实拿到了会话。
		res.Outcome = CredHit
		return res, nil
	case 331:
		if err = w.writeLine("PASS " + pass); err != nil {
			return res.withErr(err)
		}
		reply, err = w.read()
		if err != nil {
			return res.withErr(err)
		}
		return classifyFTPReply(res, reply), nil
	case 530, 500, 501, 555:
		res.Outcome = CredDeny
		res.Reason = "服务端不接受该账号：" + credPreview(reply)
		return res, nil
	default:
		res.Outcome = CredInconclusive
		res.Reason = "USER 之后收到非预期回复（" + strconv.Itoa(code) + "）：" + credPreview(reply)
		return res, nil
	}
}

// classifyFTPReply 只看 PASS 之后的回复码。230 是会话建立，530 系列是认证失败，
// 421/450 这类是服务状态——把服务状态写成「口令错」会让报告宣称已经排除过这组口令。
func classifyFTPReply(res CredAttempt, reply []byte) CredAttempt {
	msg := strings.ToLower(string(reply))
	switch code := ftpCode(reply); code {
	case 230:
		res.Outcome = CredHit
	case 530, 500, 501, 504, 555:
		if credLockedText(msg) {
			res.Outcome = CredLocked
			res.Reason = "服务端提示账号锁定或来源封禁，已停手"
			return res
		}
		res.Outcome = CredDeny
	case 421, 430, 450, 451:
		if credLockedText(msg) {
			res.Outcome = CredLocked
			res.Reason = "服务端提示账号锁定或来源封禁，已停手"
			return res
		}
		res.Outcome = CredInconclusive
		res.Reason = "服务状态变化（" + strconv.Itoa(code) + "），无法对这组凭据下结论"
	default:
		res.Outcome = CredInconclusive
		res.Reason = "PASS 之后收到非预期回复（" + strconv.Itoa(code) + "）：" + credPreview(reply)
	}
	return res
}

func ftpCode(reply []byte) int {
	if len(reply) < 3 {
		return 0
	}
	n, err := strconv.Atoi(string(reply[:3]))
	if err != nil {
		return 0
	}
	return n
}

func init() { RegisterCredAdapter(ftpCredAdapter{}) }
