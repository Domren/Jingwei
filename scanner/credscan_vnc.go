package scanner

import (
	"context"
	"crypto/des"
	"fmt"
	"strconv"
	"strings"
)

// VNC：RFB 握手 + VNC 认证（DES 挑战应答）。
//
// 口令作为 DES 密钥使用，而且每个字节要先按位反转——这是 RFB 规范里最容易被
// 记错的一步（不反转的话对着真服务永远认证失败，且看起来像「口令错」）。
// 服务端只允许「无认证」时，空凭据命中；只提供 VeNCrypt/TLS 等未实现的安全类型时
// 记「不可判定」而不是猜。
type vncCredAdapter struct{}

func (vncCredAdapter) Protocol() string { return "vnc" }

func (vncCredAdapter) readVersion(w *credWire) (string, error) {
	line, err := w.readLine(64)
	if err != nil && len(line) == 0 {
		return "", err
	}
	return strings.TrimRight(string(line), "\r\n"), nil
}

func (vncCredAdapter) Identify(ctx context.Context, ep CredEndpoint) (bool, string, error) {
	w, err := credDial(ctx, credAddr(ep))
	if err != nil {
		return false, "", err
	}
	defer w.close()
	ver, err := vncCredAdapter{}.readVersion(w)
	if err != nil {
		return false, "", err
	}
	confirmed := strings.HasPrefix(ver, "RFB ")
	return confirmed, ver, nil
}

// vncSecurityTypes 读取服务端的安全类型列表；minor>=7 是列表形式，3.3 是单个 32 位值。
func vncSecurityTypes(w *credWire, minor int) ([]byte, error) {
	if minor >= 7 {
		head, err := w.readN(1)
		if err != nil {
			return nil, err
		}
		n := int(head[0])
		if n == 0 {
			// 服务端拒绝：后面跟原因字符串
			lenBuf, _ := w.readN(4)
			if len(lenBuf) == 4 {
				l := int(lenBuf[0])<<24 | int(lenBuf[1])<<16 | int(lenBuf[2])<<8 | int(lenBuf[3])
				if l > 0 && l < 4096 {
					reason, _ := w.readN(l)
					return nil, fmt.Errorf("服务端拒绝连接：%s", strings.TrimSpace(string(reason)))
				}
			}
			return nil, fmt.Errorf("服务端拒绝连接")
		}
		return w.readN(n)
	}
	raw, err := w.readN(4)
	if err != nil {
		return nil, err
	}
	t := int(raw[0])<<24 | int(raw[1])<<16 | int(raw[2])<<8 | int(raw[3])
	if t == 0 {
		return nil, fmt.Errorf("服务端报告握手失败")
	}
	return []byte{byte(t)}, nil
}

// vncDESKey 把口令转成 VNC 的 DES 密钥：截断/补零到 8 字节，每字节按位反转。
func vncDESKey(password string) []byte {
	key := make([]byte, 8)
	copy(key, []byte(password))
	for i, b := range key {
		var r byte
		for bit := 0; bit < 8; bit++ {
			if b&(1<<bit) != 0 {
				r |= 1 << (7 - bit)
			}
		}
		key[i] = r
	}
	return key
}

func vncDESResponse(password string, challenge []byte) ([]byte, error) {
	if len(challenge) != 16 {
		return nil, fmt.Errorf("挑战长度 %d，应为 16", len(challenge))
	}
	block, err := des.NewCipher(vncDESKey(password))
	if err != nil {
		return nil, err
	}
	out := make([]byte, 16)
	block.Encrypt(out[:8], challenge[:8])
	block.Encrypt(out[8:], challenge[8:])
	return out, nil
}

func (vncCredAdapter) Try(ctx context.Context, ep CredEndpoint, cred Credential) (res CredAttempt, err error) {
	res = credNewAttempt(cred)
	w, err := credDial(ctx, credAddr(ep))
	if err != nil {
		return res.withErr(err)
	}
	defer w.close()
	defer func() { res.syncWire(w) }()

	ver, err := vncCredAdapter{}.readVersion(w)
	if err != nil {
		return res.withErr(err)
	}
	res.Banner = ver
	// 版本行去掉 \r\n 后是 11 字节（"RFB 003.008"），按 12 判会把正常服务端误拒。
	if !strings.HasPrefix(ver, "RFB ") || len(ver) < 11 {
		res.Outcome = CredInconclusive
		res.Reason = "不是 RFB 版本行：" + ver
		return res, nil
	}
	minor := 8
	if parts := strings.Split(strings.TrimSpace(ver), "."); len(parts) == 2 {
		if n, err := strconv.Atoi(parts[1]); err == nil {
			minor = n
		}
	}
	if err := w.write([]byte("RFB 003.008\n")); err != nil {
		return res.withErr(err)
	}
	types, err := vncSecurityTypes(w, minor)
	if err != nil {
		res.Outcome = CredInconclusive
		res.Reason = err.Error()
		return res, nil
	}
	hasVNC, hasNone := false, false
	for _, t := range types {
		if t == 2 {
			hasVNC = true
		}
		if t == 1 {
			hasNone = true
		}
	}
	readSecurityResult := func() (int, error) {
		raw, err := w.readN(4)
		if err != nil {
			return -1, err
		}
		return int(raw[0])<<24 | int(raw[1])<<16 | int(raw[2])<<8 | int(raw[3]), nil
	}

	if !hasVNC {
		if hasNone {
			if cred.Username == "" && cred.Password == "" {
				res.Outcome = CredHit
				res.Reason = "服务端只要求「无认证」（该端口未启用认证）"
			} else {
				res.Outcome = CredDeny
				res.Reason = "服务端未启用认证，非空口令不构成可用凭据"
			}
			return res, nil
		}
		res.Outcome = CredInconclusive
		res.Reason = fmt.Sprintf("服务端只提供未实现的安全类型 %v（可能是 VeNCrypt/TLS）", types)
		return res, nil
	}

	if minor >= 7 {
		if err := w.write([]byte{2}); err != nil {
			return res.withErr(err)
		}
	}
	challenge, err := w.readN(16)
	if err != nil {
		return res.withErr(err)
	}
	response, err := vncDESResponse(cred.Password, challenge)
	if err != nil {
		return res.withErr(err)
	}
	if err := w.write(response); err != nil {
		return res.withErr(err)
	}
	result, err := readSecurityResult()
	if err != nil {
		return res.withErr(err)
	}
	switch result {
	case 0:
		if cred.Username == "" && cred.Password == "" {
			// 空口令能通过 VNC 认证本身就是极弱口令；仍然算命中。
			res.Outcome = CredHit
		} else {
			res.Outcome = CredHit
		}
	case 1:
		res.Outcome = CredDeny
		res.Reason = "VNC 认证失败（SecurityResult=1）"
	default:
		res.Outcome = CredInconclusive
		res.Reason = fmt.Sprintf("SecurityResult=%d", result)
	}
	return res, nil
}

func init() { RegisterCredAdapter(vncCredAdapter{}) }
