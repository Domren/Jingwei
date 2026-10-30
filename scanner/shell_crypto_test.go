package scanner

import "testing"

func TestEncryptDecryptAES(t *testing.T) {
	password := "test-password-123"
	plaintext := "whoami && id && cat /etc/passwd"

	encrypted, err := EncryptAES(password, plaintext)
	if err != nil {
		t.Fatalf("EncryptAES failed: %v", err)
	}
	if encrypted == plaintext {
		t.Fatal("encrypted == plaintext, encryption not working")
	}

	decrypted, err := DecryptAES(password, encrypted)
	if err != nil {
		t.Fatalf("DecryptAES failed: %v", err)
	}
	if decrypted != plaintext {
		t.Fatalf("decrypt mismatch: got %q, want %q", decrypted, plaintext)
	}
}

func TestEncryptAESWrongPassword(t *testing.T) {
	password := "correct-password"
	wrong := "wrong-password"
	plaintext := "secret command"

	encrypted, err := EncryptAES(password, plaintext)
	if err != nil {
		t.Fatalf("EncryptAES failed: %v", err)
	}
	// Wrong password should either fail or produce garbage
	decrypted, err := DecryptAES(wrong, encrypted)
	if err == nil && decrypted == plaintext {
		t.Fatal("wrong password should not decrypt correctly")
	}
}

func TestBuildEncryptedShellPayload(t *testing.T) {
	// PHP variant
	php := BuildEncryptedShellPayload("php", "mypassword")
	if php.Type != "php" {
		t.Fatalf("expected php type, got %s", php.Type)
	}
	if php.Content == "" {
		t.Fatal("PHP payload content is empty")
	}
	if !contains(php.Content, "mypassword") {
		t.Fatal("PHP payload should contain password")
	}
	if !contains(php.Content, "openssl_decrypt") {
		t.Fatal("PHP payload should use openssl_decrypt")
	}

	// JSP variant
	jsp := BuildEncryptedShellPayload("jsp", "mypassword")
	if jsp.Type != "jsp" {
		t.Fatalf("expected jsp type, got %s", jsp.Type)
	}
	if jsp.Content == "" {
		t.Fatal("JSP payload content is empty")
	}
	if !contains(jsp.Content, "Cipher") {
		t.Fatal("JSP payload should use javax.crypto")
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 || indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
