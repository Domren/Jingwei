package krbcrypt

// krbcrypt 单测：加解密自洽（RFC4757Encrypt 造密文 → Decrypt 还原/校验）+
// 口令→NT hash 的已知向量 + 字典破解闭环（含 hashcat 13100 行格式）。

import "testing"

func TestNTLMHashKnownVectors(t *testing.T) {
	// 已知向量（python ntlmhash 对拍）：
	//   NT("password") = 8846f7eaee8fb117ad06bdd830b7586c
	//   NT("")         = 31d6cfe0d16ae931b73c59d7e0c089c0
	// 注意 e52cac67419a9a224a3b108f3fa6cb6d 是 "password" 的 LM hash，别混。
	cases := []struct {
		pw   string
		want string
	}{
		{"password", "8846f7eaee8fb117ad06bdd830b7586c"},
		{"", "31d6cfe0d16ae931b73c59d7e0c089c0"},
		{"SvcPass123!", "9311e3b40d7f4ee4a5e6e0e6e0e6e0e6"}, // 占位非标准值，仅验 16 字节长度
	}
	for _, c := range cases {
		got := NTLMHash(c.pw)
		if len(got) != 16 {
			t.Fatalf("NTLMHash(%q) len=%d want 16", c.pw, len(got))
		}
		if c.pw == "SvcPass123!" {
			continue // 非标准向量，仅验长度
		}
		if hexS(got) != c.want {
			t.Fatalf("NTLMHash(%q) = %s want %s", c.pw, hexS(got), c.want)
		}
	}
}

func hexS(b []byte) string {
	const hexDigits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, v := range b {
		out = append(out, hexDigits[v>>4], hexDigits[v&0xf])
	}
	return string(out)
}

func TestRFC4757RoundTrip(t *testing.T) {
	key := NTLMHash("SvcPass123!")
	plain := []byte("0123456789abcdef0123456789abcdef") // 任意 ≥8 字节
	cipher, err := RFC4757Encrypt(key, plain, KeyUsageTicket)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	pt, ok := RFC4757Decrypt(key, cipher, KeyUsageTicket)
	if !ok {
		t.Fatalf("Decrypt with correct key: integrity check failed")
	}
	if string(pt) != string(plain) {
		t.Fatalf("round trip mismatch: got %q want %q", pt, plain)
	}
	// 错误密钥必须校验不过。
	wrong := NTLMHash("WrongPassword")
	if _, ok := RFC4757Decrypt(wrong, cipher, KeyUsageTicket); ok {
		t.Fatalf("Decrypt with wrong key unexpectedly succeeded")
	}
	// 篡改密文必须校验不过。
	tampered := append([]byte{}, cipher...)
	tampered[20] ^= 0x40
	if _, ok := RFC4757Decrypt(key, tampered, KeyUsageTicket); ok {
		t.Fatalf("Decrypt with tampered ciphertext unexpectedly succeeded")
	}
}

func TestCrackKRB5TGS23(t *testing.T) {
	key := NTLMHash("SvcPass123!")
	plain := []byte("fake-enc-ticketpart-der-blob-payload")
	cipher, err := RFC4757Encrypt(key, plain, KeyUsageTicket)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	cipherHex := hexS(cipher)

	// 纯 hex 输入。
	dict := []string{"Password1!", "letmein", "SvcPass123!", "admin"}
	got, ok, err := CrackKRB5TGS23(cipherHex, dict)
	if err != nil || !ok {
		t.Fatalf("Crack(hex) ok=%v err=%v", ok, err)
	}
	if got != "SvcPass123!" {
		t.Fatalf("Crack(hex) = %q want SvcPass123!", got)
	}

	// hashcat 13100 整行格式。
	line := "$krb5tgs$23$*svc-sql$JWLAB.LOCAL$MSSQLSvc/dc1.jwlab.local:1433*$" + cipherHex
	got, ok, err = CrackKRB5TGS23(line, dict)
	if err != nil || !ok || got != "SvcPass123!" {
		t.Fatalf("Crack(hashcat-line) got=%q ok=%v err=%v", got, ok, err)
	}

	// 不含正确口令的字典必须不命中。
	if _, ok, _ = CrackKRB5TGS23(cipherHex, []string{"a", "b", "c"}); ok {
		t.Fatalf("Crack(plain dict) unexpectedly succeeded")
	}
}

func TestCrackRejectsGarbage(t *testing.T) {
	if _, _, err := CrackKRB5TGS23("not-hex", []string{"a"}); err == nil {
		t.Fatalf("garbage hex should error")
	}
	if _, _, err := CrackKRB5TGS23("aabb", []string{"a"}); err == nil {
		t.Fatalf("short cipher should error")
	}
}
