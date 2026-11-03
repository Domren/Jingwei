package db

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"log"
	"strings"
)

// 落盘密封内核：值用 AES-256-GCM 加密后再入库，密钥由平台签名根密钥
// （platform_secret）按用途派生。用途标签固定且互不相同，一处泄露解不开另一处。
//
// 边界要说清楚：根密钥现在就在同一个库里，所以这层挡的是误查表、把整行序列化出去的
// 代码路径、以及共享转储时的顺手一览，不是「拿到数据库也读不出凭据」。它消除的是
// 「库里躺着明文内网口令」这件事本身。

const SealPrefix = "v1:"

// SealPurpose picks which derived key protects a column. Two purposes never share
// a key, so a leak in one use cannot decrypt another.
type SealPurpose string

const (
	SealPurposeShell      SealPurpose = "jingwei/webshell-secret/v1"
	SealPurposeCredential SealPurpose = "jingwei/intranet-credential/v1"
	SealPurposeLLMKey     SealPurpose = "jingwei/llm-api-key/v1"
)

var (
	// ErrSealEmpty is a missing value, which is not the same failure as a corrupt one.
	ErrSealEmpty = errors.New("要密封的值为空")
	// ErrSealFormat means the stored text is not a seal envelope.
	ErrSealFormat = errors.New("封装格式不受支持")
	// ErrSealKey means the envelope is well-formed but this platform key cannot
	// open it — a rotated signing root. Callers must surface it, not fall back to
	// handing back ciphertext: dialing SSH with a ciphertext reads as "wrong
	// password" on a host we used to own.
	ErrSealKey = errors.New("解封失败（平台签名密钥可能已更换）")
	// ErrSealNoKey is the same hazard from the other side: a handle without a
	// signing key (an older binary rolled back onto a sealed database) reading a
	// sealed row. Reporting it beats returning ciphertext as a password.
	ErrSealNoKey = errors.New("当前进程未加载平台签名密钥，无法读取已密封的值")
)

// SealDerive returns the per-purpose AES key.
func SealDerive(rootKey []byte, purpose SealPurpose) []byte {
	h := hmac.New(sha256.New, rootKey)
	h.Write([]byte(purpose))
	return h.Sum(nil)
}

// IsSealed reports whether a stored value is in seal form. Rows the migration has
// not reached are still plaintext and keep working, so readers branch on this.
func IsSealed(v string) bool {
	return strings.HasPrefix(strings.TrimSpace(v), SealPrefix)
}

func newSealGCM(rootKey []byte, purpose SealPurpose) (cipher.AEAD, error) {
	block, err := aes.NewCipher(SealDerive(rootKey, purpose))
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func encodeSealed(gcm cipher.AEAD, nonce []byte, plain string) string {
	body := gcm.Seal(nil, nonce, []byte(plain), []byte(SealPrefix))
	return SealPrefix + base64.RawURLEncoding.EncodeToString(append(append([]byte{}, nonce...), body...))
}

// Seal encrypts plain under the purpose-derived key. A random nonce makes two
// seals of the same value look unrelated.
func Seal(rootKey []byte, purpose SealPurpose, plain string) (string, error) {
	if plain == "" {
		return "", ErrSealEmpty
	}
	gcm, err := newSealGCM(rootKey, purpose)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	return encodeSealed(gcm, nonce, plain), nil
}

// SealDeterministic derives the nonce from the plaintext, so the same value always
// produces the same ciphertext. It exists for one reason: intranet_credentials has
// UNIQUE (host, username, password), and re-registering a hit must refresh the
// existing row rather than add a second one. With a random nonce every
// re-registration becomes a new row, the ledger starts reporting the same
// credential several times, and the SSH sessions bound to a credential id point at
// whichever row happened to be inserted first. The trade — a database reader can
// tell two identical passwords from two different ones — is already conceded by
// that constraint.
func SealDeterministic(rootKey []byte, purpose SealPurpose, plain string) (string, error) {
	if plain == "" {
		return "", ErrSealEmpty
	}
	gcm, err := newSealGCM(rootKey, purpose)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, SealDerive(rootKey, purpose))
	mac.Write([]byte("nonce:" + plain))
	return encodeSealed(gcm, mac.Sum(nil)[:gcm.NonceSize()], plain), nil
}

// Open decrypts. A value without the seal prefix is legacy plaintext and returned
// unchanged, so a row the startup migration has not reached still works; callers
// that must not accept plaintext (webshell keys) check IsSealed first.
func OpenSealed(rootKey []byte, purpose SealPurpose, stored string) (string, error) {
	stored = strings.TrimSpace(stored)
	if stored == "" {
		return "", ErrSealEmpty
	}
	if !IsSealed(stored) {
		return stored, nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(stored, SealPrefix))
	if err != nil {
		return "", ErrSealFormat
	}
	gcm, err := newSealGCM(rootKey, purpose)
	if err != nil {
		return "", err
	}
	if len(raw) < gcm.NonceSize() {
		return "", ErrSealFormat
	}
	plain, err := gcm.Open(nil, raw[:gcm.NonceSize()], raw[gcm.NonceSize():], []byte(SealPrefix))
	if err != nil {
		return "", ErrSealKey
	}
	return string(plain), nil
}

// UseSealKey turns on at-rest sealing for the credential ledger and the model
// profiles, then converges any rows still stored as plaintext. It is called once
// during startup, after the platform signing root is resolved; a handle without a
// key stores plaintext, which is what the isolated test harnesses want and what
// pre-sealing installs did.
func (d *DB) UseSealKey(key []byte) {
	if len(key) == 0 {
		return
	}
	d.sealKey = append([]byte{}, key...)
	d.migrateSecretsAtRest()
	if unreadable := d.auditSealedSecrets(); unreadable > 0 {
		log.Printf("[seal] 共 %d 条已密封的值用当前签名密钥解不开：平台签名密钥换过，"+
			"webshell 需重新投放载荷、内存马需重新注入、凭据与模型密钥需重新登记", unreadable)
	}
}

func (d *DB) seal(purpose SealPurpose, plain string) (string, bool) {
	if len(d.sealKey) == 0 || plain == "" {
		return plain, false
	}
	// Opening first makes this idempotent: a value that is already a seal of this
	// platform's key is re-sealed from its plaintext rather than wrapped twice.
	if cur, err := OpenSealed(d.sealKey, purpose, plain); err == nil {
		plain = cur
	}
	return plain, true
}

func (d *DB) sealCredential(plain string) string {
	if len(d.sealKey) == 0 || strings.TrimSpace(plain) == "" {
		return plain
	}
	value, _ := d.seal(SealPurposeCredential, plain)
	sealed, err := SealDeterministic(d.sealKey, SealPurposeCredential, value)
	if err != nil {
		// Storing plaintext beats refusing to register a credential the operator
		// just obtained; the next startup pass retries the conversion.
		log.Printf("[seal] 内网凭据密封失败，按明文登记：%v", err)
		return plain
	}
	return sealed
}

func (d *DB) openCredential(stored string) (string, error) {
	if !IsSealed(stored) {
		return stored, nil
	}
	if len(d.sealKey) == 0 {
		return "", ErrSealNoKey
	}
	plain, err := OpenSealed(d.sealKey, SealPurposeCredential, stored)
	if err != nil {
		return "", sealError("内网凭据", err)
	}
	return plain, nil
}

func (d *DB) sealLLMKey(plain string) string {
	if len(d.sealKey) == 0 || strings.TrimSpace(plain) == "" {
		return plain
	}
	value, _ := d.seal(SealPurposeLLMKey, plain)
	sealed, err := Seal(d.sealKey, SealPurposeLLMKey, value)
	if err != nil {
		log.Printf("[seal] API 密钥密封失败，按明文保存：%v", err)
		return plain
	}
	return sealed
}

func (d *DB) openLLMKey(stored string) (string, error) {
	if !IsSealed(stored) {
		return stored, nil
	}
	if len(d.sealKey) == 0 {
		return "", ErrSealNoKey
	}
	plain, err := OpenSealed(d.sealKey, SealPurposeLLMKey, stored)
	if err != nil {
		return "", sealError("模型 API 密钥", err)
	}
	return plain, nil
}

func sealError(what string, err error) error {
	if errors.Is(err, ErrSealKey) {
		return errors.New(what + "解封失败：平台签名密钥已更换，请重新登记")
	}
	return errors.Join(errors.New(what+"封装损坏"), err)
}

// settingSecretSealV1 marks the one-time conversion of pre-sealing plaintext rows.
// The flag is only written when the pass finished without failures, so an
// interrupted or partially failing pass retries on the next start instead of
// leaving a permanent mix of plaintext and sealed rows.
const settingSecretSealV1 = "secret_seal_v1"

func (d *DB) migrateSecretsAtRest() {
	if v, ok, err := d.GetSetting(settingSecretSealV1); err == nil && ok && v == "done" {
		return
	}
	creds, credFailed, err1 := d.migrateCredentialPasswords()
	profiles, profileFailed, err2 := d.migrateLLMAPIKeys()
	if err1 != nil {
		log.Printf("[seal] 内网凭据明文迁移失败：%v", err1)
	}
	if err2 != nil {
		log.Printf("[seal] 模型 API 密钥明文迁移失败：%v", err2)
	}
	if creds+profiles > 0 {
		log.Printf("[seal] 明文落盘迁移：凭据 %d 条、模型密钥 %d 个已改为密封", creds, profiles)
	}
	if err1 == nil && err2 == nil && credFailed == 0 && profileFailed == 0 {
		if err := d.SetSetting(settingSecretSealV1, "done"); err != nil {
			log.Printf("[seal] 迁移标记写入失败：%v", err)
		}
	}
}

type sealableRow struct {
	id   int64
	text string
}

// collectPlaintextRows reads the rows still stored as plaintext. They are collected
// before any UPDATE so the pass never iterates over a cursor it is also writing.
func (d *DB) collectPlaintextRows(query string) ([]sealableRow, error) {
	rows, err := d.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []sealableRow
	for rows.Next() {
		var r sealableRow
		if err := rows.Scan(&r.id, &r.text); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// migrateCredentialPasswords seals ledger rows written before sealing existed.
// Already-sealed values are skipped, so re-running is a no-op.
func (d *DB) migrateCredentialPasswords() (sealed, failed int, err error) {
	pending, err := d.collectPlaintextRows(`SELECT id, password FROM intranet_credentials
		WHERE password <> '' AND left(password, 3) <> '` + SealPrefix + `'`)
	if err != nil {
		return 0, 0, err
	}
	for _, r := range pending {
		value, serr := SealDeterministic(d.sealKey, SealPurposeCredential, r.text)
		if serr != nil {
			failed++
			log.Printf("[seal] 凭据 #%d 密封失败：%v", r.id, serr)
			continue
		}
		if _, uerr := d.Exec(`UPDATE intranet_credentials SET password=$2, updated_at=now() WHERE id=$1`, r.id, value); uerr != nil {
			failed++
			log.Printf("[seal] 凭据 #%d 写回失败：%v", r.id, uerr)
			continue
		}
		sealed++
	}
	return sealed, failed, nil
}

// migrateLLMAPIKeys does the same for model profile keys. api_key_hint already
// holds the last four characters of the plaintext, so the UI keeps something
// recognizable to show without reading the key.
func (d *DB) migrateLLMAPIKeys() (sealed, failed int, err error) {
	pending, err := d.collectPlaintextRows(`SELECT id, api_key FROM llm_profiles
		WHERE COALESCE(api_key, '') <> '' AND left(api_key, 3) <> '` + SealPrefix + `'`)
	if err != nil {
		return 0, 0, err
	}
	for _, r := range pending {
		value, serr := Seal(d.sealKey, SealPurposeLLMKey, r.text)
		if serr != nil {
			failed++
			log.Printf("[seal] 模型配置 #%d 密钥密封失败：%v", r.id, serr)
			continue
		}
		if _, uerr := d.Exec(`UPDATE llm_profiles SET api_key=$2 WHERE id=$1`, r.id, value); uerr != nil {
			failed++
			log.Printf("[seal] 模型配置 #%d 写回失败：%v", r.id, uerr)
			continue
		}
		sealed++
	}
	return sealed, failed, nil
}

// auditSealedSecrets counts stored values that this signing root cannot open and
// says so once, at startup. Discovering it one command at a time is how an
// operator loses an afternoon: every shell looks alive (the check passes) and
// every command fails to unseal, which reads like a target problem.
func (d *DB) auditSealedSecrets() (unreadableTotal int) {
	if len(d.sealKey) == 0 {
		return 0
	}
	checks := []struct {
		what    string
		query   string
		purpose SealPurpose
		fix     string
	}{
		{"webshell 密钥", `SELECT secret FROM webshells WHERE left(COALESCE(secret, ''), 3) = '` + SealPrefix + `'`, SealPurposeShell, "重新投放载荷"},
		{"内存马密钥", `SELECT secret FROM java_memshells WHERE left(COALESCE(secret, ''), 3) = '` + SealPrefix + `'`, SealPurposeShell, "重新注入内存马"},
		{"内网凭据口令", `SELECT password FROM intranet_credentials WHERE left(password, 3) = '` + SealPrefix + `'`, SealPurposeCredential, "重新登记凭据"},
		{"模型 API 密钥", `SELECT api_key FROM llm_profiles WHERE left(COALESCE(api_key, ''), 3) = '` + SealPrefix + `'`, SealPurposeLLMKey, "在系统设置里重新填写"},
	}
	for _, c := range checks {
		rows, err := d.Query(c.query)
		if err != nil {
			log.Printf("[seal] %s 自检查询失败：%v", c.what, err)
			continue
		}
		var unreadable int
		for rows.Next() {
			var v string
			if err := rows.Scan(&v); err != nil {
				continue
			}
			if _, oerr := OpenSealed(d.sealKey, c.purpose, v); oerr != nil {
				unreadable++
			}
		}
		rows.Close()
		// Per-kind counts are what make the fix actionable: a webshell is re-planted
		// by pushing a payload, a model key is re-entered in settings, and only the
		// operator knows which of the two they are looking at.
		if unreadable > 0 {
			log.Printf("[seal] %d 条%s用当前签名密钥解不开，需%s", unreadable, c.what, c.fix)
		}
		unreadableTotal += unreadable
	}
	return unreadableTotal
}
