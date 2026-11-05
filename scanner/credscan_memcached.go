package scanner

import (
	"context"
	"strings"
)

// Memcached：文本协议没有「用户名/口令」这一层，默认部署就是无认证。
// 所以这个适配器测的不是「哪组口令能登」，而是「这个端口认不认没有凭据的调用」——
// 和 Redis 未开认证同一种事实，只是 Redis 至少还有 AUTH 命令可发。
type memcachedCredAdapter struct{}

func (memcachedCredAdapter) Protocol() string { return "memcached" }

func (memcachedCredAdapter) Identify(ctx context.Context, ep CredEndpoint) (bool, string, error) {
	w, err := credDial(ctx, credAddr(ep))
	if err != nil {
		return false, "", err
	}
	defer w.close()
	line, err := memcachedProbe(w)
	if err != nil {
		return false, "", err
	}
	ok := strings.HasPrefix(line, "VERSION")
	return ok, strings.TrimSpace(line), nil
}

func (memcachedCredAdapter) Try(ctx context.Context, ep CredEndpoint, cred Credential) (res CredAttempt, err error) {
	res = credNewAttempt(cred)
	w, err := credDial(ctx, credAddr(ep))
	if err != nil {
		return res.withErr(err)
	}
	defer w.close()
	defer func() { res.syncWire(w) }()

	line, err := memcachedProbe(w)
	if err != nil {
		return res.withErr(err)
	}
	res.Banner = strings.TrimSpace(line)
	switch {
	case strings.HasPrefix(line, "VERSION"):
		if cred.Username == "" && cred.Password == "" {
			res.Outcome = CredHit
			res.Reason = "服务端未启用认证（无需任何凭据即可执行命令）"
		} else {
			res.Outcome = CredDeny
			res.Reason = "服务端未启用认证，非空口令不构成可用凭据"
		}
	case strings.HasPrefix(line, "CLIENT_ERROR"), strings.HasPrefix(line, "ERROR"),
		strings.HasPrefix(line, "SERVER_ERROR"):
		// 有些部署会拒绝未认证命令（SASL 或代理层）。这既不是「口令对」，也不是「口令错」。
		res.Outcome = CredInconclusive
		res.Reason = "服务端拒绝了未认证的探测命令：" + strings.TrimSpace(line)
	default:
		res.Outcome = CredInconclusive
		res.Reason = "响应不是 memcached 的协议报文"
	}
	return res, nil
}

func memcachedProbe(w *credWire) (string, error) {
	if err := w.write([]byte("version\r\n")); err != nil {
		return "", err
	}
	line, err := w.readLine(4096)
	if err != nil && len(line) == 0 {
		return "", err
	}
	return string(line), nil
}

// Zookeeper：四字命令 ruok 是否被应答，就是「有没有开认证/有没有开放管理口」的证据。
// 3.5+ 默认关闭四字命令；关闭时这里只能落「不可判定」，不会凭空判命中。
type zookeeperCredAdapter struct{}

func (zookeeperCredAdapter) Protocol() string { return "zookeeper" }

func (zookeeperCredAdapter) Identify(ctx context.Context, ep CredEndpoint) (bool, string, error) {
	w, err := credDial(ctx, credAddr(ep))
	if err != nil {
		return false, "", err
	}
	defer w.close()
	line, err := zookeeperProbe(w)
	if err != nil {
		return false, "", err
	}
	ok := strings.Contains(line, "imok")
	return ok, strings.TrimSpace(line), nil
}

func (zookeeperCredAdapter) Try(ctx context.Context, ep CredEndpoint, cred Credential) (res CredAttempt, err error) {
	res = credNewAttempt(cred)
	w, err := credDial(ctx, credAddr(ep))
	if err != nil {
		return res.withErr(err)
	}
	defer w.close()
	defer func() { res.syncWire(w) }()

	line, err := zookeeperProbe(w)
	if err != nil {
		return res.withErr(err)
	}
	res.Banner = strings.TrimSpace(line)
	switch {
	case strings.Contains(line, "imok"):
		if cred.Username == "" && cred.Password == "" {
			res.Outcome = CredHit
			res.Reason = "服务端应答未认证的四字命令（该端口未启用认证）"
		} else {
			res.Outcome = CredDeny
			res.Reason = "服务端未启用认证，非空口令不构成可用凭据"
		}
	case strings.Contains(line, "is not executed"):
		res.Outcome = CredInconclusive
		res.Reason = "服务端关闭了四字命令（4lw.commands.whitelist），无法判定认证状态"
	default:
		res.Outcome = CredInconclusive
		res.Reason = "响应不是 Zookeeper 四字命令应答"
	}
	return res, nil
}

func zookeeperProbe(w *credWire) (string, error) {
	if err := w.write([]byte("ruok")); err != nil {
		return "", err
	}
	line, err := w.read()
	if err != nil && len(line) == 0 {
		return "", err
	}
	return string(line), nil
}

func init() {
	RegisterCredAdapter(memcachedCredAdapter{})
	RegisterCredAdapter(zookeeperCredAdapter{})
}
