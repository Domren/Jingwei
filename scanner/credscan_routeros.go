package scanner

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"strings"
)

// RouterOS API (8728) 登录探针。
//
// API 的 word 是「变长长度 + 内容」，句子以 0x00 长度的空 word 结束；响应句子以
// !done / !trap / !re 开头、属性以 = 开头——这两个前缀就是协议特有证据，不靠端口猜。
// 兼容两代登录：先发带 password 的旧式 /login，若服务端回 =ret=<challenge>（6.43+），
// 再用 MD5(0x00 + password + challenge) 补一次 challenge-response；只有最终 !done
// 且不再带 =ret= 才算握手层接受。
//
// 未在真机验证：RouterOS 是专有设备/镜像，本平台没有该环境。hit/deny 双路径由
// scanner/credscan_adapters_test.go 的进程内协议桩验证，不写「已在真机跑通」。

type routerosCredAdapter struct{}

func (routerosCredAdapter) Protocol() string { return "routeros" }

func rosEncodeWord(s string) []byte {
	b := []byte(s)
	n := len(b)
	var head []byte
	switch {
	case n < 0x80:
		head = []byte{byte(n)}
	case n < 0x4000:
		head = []byte{0x80 | byte(n>>8), byte(n)}
	default:
		head = []byte{0xc0 | byte(n>>16), byte(n >> 8), byte(n)}
	}
	return append(head, b...)
}

func rosSentence(words ...string) []byte {
	var out []byte
	for _, w := range words {
		out = append(out, rosEncodeWord(w)...)
	}
	return append(out, 0x00)
}

func rosReadSentence(w *credWire) ([]string, error) {
	var words []string
	for {
		b1, err := w.readN(1)
		if err != nil {
			return words, err
		}
		n := int(b1[0])
		if n == 0 {
			return words, nil
		}
		if n&0x80 != 0 {
			if n&0xc0 == 0x80 {
				b2, err := w.readN(1)
				if err != nil {
					return words, err
				}
				n = int(n&0x3f)<<8 | int(b2[0])
			} else if n&0xe0 == 0xc0 {
				b2, err := w.readN(2)
				if err != nil {
					return words, err
				}
				n = int(n&0x1f)<<16 | int(b2[0])<<8 | int(b2[1])
			}
		}
		if n < 0 || n > credReadMax {
			return words, fmt.Errorf("RouterOS word 长度异常 %d", n)
		}
		data, err := w.readN(n)
		if err != nil {
			return words, err
		}
		words = append(words, string(data))
	}
}

func rosWord(words []string, prefix string) string {
	for _, w := range words {
		if strings.HasPrefix(w, prefix) {
			return strings.TrimPrefix(w, prefix)
		}
	}
	return ""
}

func rosHas(words []string, word string) bool {
	for _, w := range words {
		if w == word {
			return true
		}
	}
	return false
}

func rosMD5Response(pass, challengeHex string) string {
	ch, err := hex.DecodeString(challengeHex)
	if err != nil {
		ch = []byte(challengeHex)
	}
	h := md5.New()
	h.Write([]byte{0x00})
	h.Write([]byte(pass))
	h.Write(ch)
	return hex.EncodeToString(h.Sum(nil))
}

func rosLooksLikeAPI(words []string) bool {
	for _, w := range words {
		if strings.HasPrefix(w, "!done") || strings.HasPrefix(w, "!trap") ||
			strings.HasPrefix(w, "!re") || strings.HasPrefix(w, "!fatal") ||
			strings.HasPrefix(w, "=ret=") {
			return true
		}
	}
	return false
}

func (a routerosCredAdapter) Identify(ctx context.Context, ep CredEndpoint) (bool, string, error) {
	w, err := credDial(ctx, credAddr(ep))
	if err != nil {
		return false, "", err
	}
	defer w.close()
	// 不含任何用户数据的无害命令，只用来问「你是不是 RouterOS API」。
	if err := w.write(rosSentence("/system/identity/print")); err != nil {
		return false, "", err
	}
	words, err := rosReadSentence(w)
	if err != nil {
		return false, credPreview(w.resp), err
	}
	if !rosLooksLikeAPI(words) {
		return false, credPreview(w.resp), nil
	}
	return true, "RouterOS API 响应：" + credPreview([]byte(strings.Join(words, " "))), nil
}

func (a routerosCredAdapter) Try(ctx context.Context, ep CredEndpoint, cred Credential) (res CredAttempt, err error) {
	res = credNewAttempt(cred)
	w, err := credDial(ctx, credAddr(ep))
	if err != nil {
		return res.withErr(err)
	}
	defer w.close()
	defer func() { res.syncWire(w) }()

	// 第一轮：旧式带口令登录。新版会给 =ret=<challenge> 要求补 response。
	if err = w.write(rosSentence("/login", "=name="+cred.Username, "=password="+cred.Password)); err != nil {
		return res.withErr(err)
	}
	words, err := rosReadSentence(w)
	if err != nil {
		return res.withErr(err)
	}
	if chal := rosWord(words, "=ret="); chal != "" {
		// 第二轮：challenge-response（6.43+ 的 API 登录）。
		response := "00" + rosMD5Response(cred.Password, chal)
		if err = w.write(rosSentence("/login", "=name="+cred.Username, "=response="+response)); err != nil {
			return res.withErr(err)
		}
		words, err = rosReadSentence(w)
		if err != nil {
			return res.withErr(err)
		}
	}
	res.Banner = "RouterOS API: " + credPreview([]byte(strings.Join(words, " | ")))
	switch {
	case rosHas(words, "!trap"):
		if credLockedText(strings.ToLower(strings.Join(words, " "))) {
			res.Outcome = CredLocked
			res.Reason = "目标提示账号锁定或访问封禁，已停手"
			return res, nil
		}
		res.Outcome = CredDeny
	case rosHas(words, "!done") && rosWord(words, "=ret=") == "":
		// 最终 !done 且不再要 challenge：服务端明确完成了这次登录。
		res.Outcome = CredHit
	default:
		res.Outcome = CredInconclusive
		res.Reason = "RouterOS API 应答既非 !done 也非 !trap，不能对这组凭据下结论"
	}
	return res, nil
}

func init() { RegisterCredAdapter(routerosCredAdapter{}) }
