package server

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Autumn-27/jingwei/db"
	"github.com/Autumn-27/jingwei/scanner"
)

func TestSealOpenShellSecret(t *testing.T) {
	jwtKey := []byte("test-jwt-signing-key-32-bytes!!")
	plain := base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	sealed, err := sealShellSecret(jwtKey, plain)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if !strings.HasPrefix(sealed, shellSecretPrefix) {
		t.Fatalf("sealed secret missing prefix: %q", sealed)
	}
	if strings.Contains(sealed, plain) {
		t.Fatal("sealed secret contains the plaintext key")
	}
	got, err := openShellSecret(jwtKey, sealed)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if got != plain {
		t.Fatalf("roundtrip mismatch: %q", got)
	}
	if _, err := openShellSecret([]byte("another-jwt-key"), sealed); err == nil {
		t.Fatal("wrong JWT key must not open the secret")
	}
	bad := []byte(sealed)
	// Flip a middle character: the last base64 character can carry only
	// unused padding bits, so changing it may decode identically.
	bad[len(bad)/2] ^= 0x01
	if _, err := openShellSecret(jwtKey, string(bad)); err == nil {
		t.Fatal("tampered sealed secret must fail")
	}
	if _, err := sealShellSecret(jwtKey, "  "); err == nil {
		t.Fatal("empty secret must be rejected")
	}
}

func TestNewV2ShellMaterialAndPayloadFor(t *testing.T) {
	s := &Server{jwtKey: []byte("test-jwt-signing-key-32-bytes!!")}
	payload, sealed, err := s.newV2ShellMaterial("php", 1)
	if err != nil {
		t.Fatalf("material: %v", err)
	}
	if payload.Protocol != scanner.ShellProtocolV2 || len(payload.Key) != 32 || payload.Carrier == "" {
		t.Fatalf("unexpected payload: %+v", payload)
	}
	shell := &db.Webshell{
		ID:         1,
		Protocol:   scanner.ShellProtocolV2,
		ShellType:  "php",
		Secret:     sealed,
		Carrier:    payload.Carrier,
		KeyVersion: 2,
	}
	rebuilt, err := s.shellPayloadFor(shell)
	if err != nil {
		t.Fatalf("shellPayloadFor: %v", err)
	}
	if string(rebuilt.Key) != string(payload.Key) {
		t.Fatal("rebuilt payload did not recover the stored key")
	}
	if rebuilt.KeyVersion != 2 {
		t.Fatalf("key version not preserved: %d", rebuilt.KeyVersion)
	}
	if !strings.Contains(rebuilt.Content, base64.StdEncoding.EncodeToString(payload.Key)) {
		t.Fatal("rebuilt payload does not embed the key")
	}
	raw, err := json.Marshal(shell)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(raw), sealed) || strings.Contains(string(raw), "\"secret\"") {
		t.Fatalf("webshell JSON leaks the sealed secret: %s", raw)
	}
}

func TestShellPayloadForLegacy(t *testing.T) {
	s := &Server{jwtKey: []byte("test-jwt-signing-key-32-bytes!!")}
	if _, err := s.shellPayloadFor(&db.Webshell{Protocol: scanner.ShellProtocolLegacy, ShellType: "php"}); err == nil {
		t.Fatal("legacy shell without password must be rejected")
	}
	legacy := &db.Webshell{Protocol: scanner.ShellProtocolLegacy, ShellType: "php", Password: "strong-password"}
	p, err := s.shellPayloadFor(legacy)
	if err != nil {
		t.Fatalf("legacy payload: %v", err)
	}
	if p.Protocol != scanner.ShellProtocolLegacy || p.Password != "strong-password" {
		t.Fatalf("unexpected legacy payload: %+v", p)
	}
	if _, err := s.renderShellPayloadFor(legacy); err == nil {
		t.Fatal("legacy shells must not be exportable as v2 payloads")
	}
}

func TestRenderShellPayloadForV2(t *testing.T) {
	s := &Server{jwtKey: []byte("test-jwt-signing-key-32-bytes!!")}
	payload, sealed, err := s.newV2ShellMaterial("jsp", 1)
	if err != nil {
		t.Fatalf("material: %v", err)
	}
	shell := &db.Webshell{Protocol: scanner.ShellProtocolV2, ShellType: "jsp", Secret: sealed, Carrier: payload.Carrier}
	rendered, err := s.renderShellPayloadFor(shell)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if rendered.Type != "jsp" || rendered.Content == "" || rendered.SHA256 == "" {
		t.Fatalf("unexpected render: %+v", rendered)
	}
}
