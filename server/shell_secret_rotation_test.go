package server

import (
	"strings"
	"testing"
	"time"

	"github.com/Domren/jingwei/db"
)

// TestShellSecretRotationDual Decrypt 是 P16 的核心双向兼容夹具：
//   - 旧根密钥密封的存量 shell 密钥，用「新代码」（新根 + 过渡期旧根）能解；
//   - 新根密钥密封的新投 shell 密钥，同样能解；
//   - 过渡期结束后旧根失效——只有新根能解旧密文，解不开即 1.6.0 自检里那条
//     「webshell 密钥解封失败（JWT 密钥可能已更换，请重新投放载荷）」。
//
// 全程纯内存，不连数据库，也不需要真实靶机。
func TestShellSecretRotationDualDecrypt(t *testing.T) {
	oldRoot := []byte("old-signing-root-32-bytes-minimum!!")
	newRoot := []byte("new-signing-root-32-bytes-minimum!!")
	plain := "s.base64.shell.key.value"

	oldSealed, err := sealShellSecret(oldRoot, plain)
	if err != nil {
		t.Fatalf("用旧根密封: %v", err)
	}
	newSealed, err := sealShellSecret(newRoot, plain)
	if err != nil {
		t.Fatalf("用新根密封: %v", err)
	}

	// 过渡仍有效：rotatedAt 就在当下。
	inWindow := time.Now()
	if got, err := openShellSecretTransition(newRoot, oldRoot, inWindow, oldSealed); err != nil || got != plain {
		t.Fatalf("过渡期内旧根密文应可解，got=%q err=%v", got, err)
	}
	if got, err := openShellSecretTransition(newRoot, oldRoot, inWindow, newSealed); err != nil || got != plain {
		t.Fatalf("过渡期内新根密文应可解，got=%q err=%v", got, err)
	}
	// 只用新根（没有 prev）解旧密文必须失败——证明不是「碰巧两把都能解」。
	if _, err := openShellSecretTransition(newRoot, nil, inWindow, oldSealed); err == nil {
		t.Fatal("过渡期内也不该在没有旧根的情况下解开旧根密文")
	}

	// 过渡期结束后（rotatedAt 超过窗口），旧根密文不再回退，报出 1.6.0 自检口径的文案。
	expired := time.Now().Add(-dbSealWindowForTest() - time.Hour)
	_, err = openShellSecretTransition(newRoot, oldRoot, expired, oldSealed)
	if err == nil {
		t.Fatal("过渡期结束后旧根密文必须失效")
	}
	if !strings.Contains(err.Error(), "请重新投放载荷") {
		t.Fatalf("收口文案应走 1.6.0 自检口径，got=%q", err.Error())
	}
	// 新根密文在窗口结束后仍可解——轮换不能影响新投的壳。
	if got, err := openShellSecretTransition(newRoot, oldRoot, expired, newSealed); err != nil || got != plain {
		t.Fatalf("窗口结束后新根密文应仍可解，got=%q err=%v", got, err)
	}

	// 格式损坏不借过渡期伪装成密钥问题。
	if _, err := openShellSecretTransition(newRoot, oldRoot, inWindow, "v1:not-base64!!"); err == nil ||
		strings.Contains(err.Error(), "请重新投放载荷") {
		t.Fatalf("损坏封装应报格式错，不得误报密钥已更换，got=%v", err)
	}
}

// dbSealWindowForTest 返回过渡窗口长度，供测试把 rotatedAt 推到窗口之外；
// 与 db 包常量保持一致的语义（这里是测试里用的保守近似，确保 > 窗口即可）。
func dbSealWindowForTest() time.Duration {
	return 72 * time.Hour
}

// TestSealTransitionActive 钉住窗口判定的边界：零值、窗口内、窗口外。
func TestSealTransitionActive(t *testing.T) {
	now := time.Now()
	if db.SealTransitionActive(time.Time{}, now) {
		t.Fatal("从未轮换（零值）不应处于过渡期")
	}
	if !db.SealTransitionActive(now.Add(-time.Hour), now) {
		t.Fatal("窗口内的轮换应处于过渡期")
	}
	if db.SealTransitionActive(now.Add(-dbSealWindowForTest()-time.Minute), now) {
		t.Fatal("超出窗口的轮换不应再处于过渡期")
	}
}
