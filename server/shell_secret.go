package server

import (
	"errors"
	"fmt"
	"strings"

	"github.com/Autumn-27/jingwei/db"
	"github.com/Autumn-27/jingwei/scanner"
)

// webshell v2 的密钥落盘保护：secret 字段用 AES-256-GCM 封装后再入库，密钥由平台
// 签名根密钥（platform_secret）按用途派生。挡的是误查表、把整行序列化出去的代码路径
// 与共享转储时的顺手一览——根密钥本身就在库里，所以这不是「拿到转储也解不开」。

// shellSecretPrefix is the seal envelope tag; see db/seal.go for the kernel.
const shellSecretPrefix = db.SealPrefix

// sealShellSecret wraps a webshell key for storage. The random nonce is fine here:
// nothing about a webshell secret is looked up by equality.
func sealShellSecret(jwtKey []byte, plain string) (string, error) {
	if strings.TrimSpace(plain) == "" {
		return "", errors.New("webshell 密钥为空")
	}
	return db.Seal(jwtKey, db.SealPurposeShell, plain)
}

// openShellSecret is deliberately stricter than db.Open: a webshell row whose
// secret is not in seal form is a legacy row, and handing its (possibly empty or
// password-shaped) column back as an AES key would fail deeper in the stack.
func openShellSecret(jwtKey []byte, sealed string) (string, error) {
	if !db.IsSealed(sealed) {
		return "", errors.New("webshell 密钥不是受支持的封装格式")
	}
	plain, err := db.OpenSealed(jwtKey, db.SealPurposeShell, sealed)
	switch {
	case err == nil:
		return plain, nil
	case errors.Is(err, db.ErrSealKey):
		return "", errors.New("webshell 密钥解封失败（JWT 密钥可能已更换，请重新投放载荷）")
	default:
		return "", err
	}
}

// newV2ShellMaterial generates a key/carrier/payload and the sealed form the DB
// keeps. keyVersion lets callers preserve the counter across re-renders.
func (s *Server) newV2ShellMaterial(shellType string, keyVersion int) (scanner.ShellPayload, string, error) {
	if keyVersion <= 0 {
		keyVersion = 1
	}
	key, err := scanner.GenerateShellKey()
	if err != nil {
		return scanner.ShellPayload{}, "", err
	}
	carrier, err := scanner.GenerateShellCarrier()
	if err != nil {
		return scanner.ShellPayload{}, "", err
	}
	payload, err := scanner.BuildShellPayloadV2(shellType, key, carrier)
	if err != nil {
		return scanner.ShellPayload{}, "", err
	}
	payload.KeyVersion = keyVersion
	sealed, err := sealShellSecret(s.jwtKey, scanner.EncodeShellKey(key))
	if err != nil {
		return scanner.ShellPayload{}, "", err
	}
	return payload, sealed, nil
}

// shellPayloadFor rebuilds the client-side payload from a stored shell. The
// secret is only decrypted in memory for the duration of a request.
func (s *Server) shellPayloadFor(shell *db.Webshell) (scanner.ShellPayload, error) {
	if shell == nil {
		return scanner.ShellPayload{}, errors.New("webshell 不存在")
	}
	if strings.EqualFold(shell.Protocol, scanner.ShellProtocolV2) {
		plain, err := openShellSecret(s.jwtKey, shell.Secret)
		if err != nil {
			return scanner.ShellPayload{}, err
		}
		key, err := scanner.DecodeShellKey(plain)
		if err != nil {
			return scanner.ShellPayload{}, err
		}
		var payload scanner.ShellPayload
		if strings.EqualFold(shell.Source, "php_prepend") {
			payload, err = scanner.BuildPHPSemiPersistPayloadV2(key, shell.Carrier)
		} else {
			payload, err = scanner.BuildShellPayloadV2(shell.ShellType, key, shell.Carrier)
		}
		if err != nil {
			return scanner.ShellPayload{}, err
		}
		if shell.KeyVersion > 0 {
			payload.KeyVersion = shell.KeyVersion
		}
		return payload, nil
	}
	if strings.TrimSpace(shell.Password) == "" {
		return scanner.ShellPayload{}, fmt.Errorf("旧版 webshell 未设置口令，请编辑后补充口令，或重新投放加密 v2 载荷")
	}
	return scanner.BuildShellPayload(shell.ShellType, shell.Password)
}

// renderShellPayloadFor returns the deployable source and fingerprint of a
// stored v2 shell. Used by the payload-download and rotate APIs.
func (s *Server) renderShellPayloadFor(shell *db.Webshell) (scanner.ShellPayload, error) {
	if shell == nil || !strings.EqualFold(shell.Protocol, scanner.ShellProtocolV2) {
		return scanner.ShellPayload{}, errors.New("只有加密 v2 webshell 可以导出载荷")
	}
	return s.shellPayloadFor(shell)
}
