package server

import (
	"strings"
	"testing"

	"github.com/Autumn-27/artex/scanner"
)

func TestPickJavaChainsPreset(t *testing.T) {
	presets := []scanner.JavaChainsPreset{
		{ID: "java.fastjson.exec", Intent: "command-exec"},
		{ID: "java.fastjson.jndi", Intent: "outbound-jndi"},
	}
	if got := pickJavaChainsPreset(presets); got.ID != "java.fastjson.jndi" {
		t.Fatalf("expected jndi preset, got %s", got.ID)
	}
	if got := pickJavaChainsPreset(presets[0:1]); got.ID != "java.fastjson.exec" {
		t.Fatalf("expected exec fallback, got %s", got.ID)
	}
	if got := javaChainJNDIPayload(presets[1]); got != "" {
		t.Fatalf("missing candidate should yield empty payload, got %s", got)
	}
	presets[1].PayloadCandidates = []string{"JavaNativePayload", "JNDILDAPDeserializePayload"}
	if got := javaChainJNDIPayload(presets[1]); got != "JNDILDAPDeserializePayload" {
		t.Fatalf("unexpected payload %s", got)
	}
	if got := javaChainPresetPayload(presets[1]); got != "JavaNativePayload" {
		t.Fatalf("expected leading payload, got %s", got)
	}
	if got := javaChainPresetPayload(scanner.JavaChainsPreset{}); got != "JavaNativePayload" {
		t.Fatalf("expected default payload, got %s", got)
	}
	ordered := orderedJavaChainsPresets([]scanner.JavaChainsPreset{
		{ID: "other"},
		{ID: "java.fastjson.exec", Intent: "command-exec"},
		{ID: "java.fastjson.jndi", Intent: "outbound-jndi"},
	})
	if ordered[0].ID != "java.fastjson.jndi" || ordered[1].ID != "java.fastjson.exec" || ordered[2].ID != "other" {
		t.Fatalf("unexpected preset order: %+v", ordered)
	}
}

func TestJavaChainInputs(t *testing.T) {
	preset := scanner.JavaChainsPreset{}
	preset.RequiredInputs = append(preset.RequiredInputs, struct {
		Key string `json:"key"`
	}{Key: "cmd"})
	inputs, err := javaChainInputs(preset, "id")
	if err != nil || inputs["cmd"] != "id" {
		t.Fatalf("inputs=%v err=%v", inputs, err)
	}
	preset.RequiredInputs = append(preset.RequiredInputs, struct {
		Key string `json:"key"`
	}{Key: "url"})
	if _, err := javaChainInputs(preset, "id"); err == nil {
		t.Fatal("expected unsupported input error")
	}
}

func TestTokenFromLDAPURL(t *testing.T) {
	if got := tokenFromLDAPURL("ldap://10.0.0.5:50389/abc123"); got != "abc123" {
		t.Fatalf("got %q", got)
	}
	if got := strings.TrimSpace(tokenFromLDAPURL("ldap://host:50389/")); got != "" {
		t.Fatalf("got %q", got)
	}
}

func TestIsLoopbackHost(t *testing.T) {
	for _, h := range []string{"127.0.0.1", "localhost", "::1"} {
		if !isLoopbackHost(h) {
			t.Fatalf("%s should be loopback", h)
		}
	}
	if isLoopbackHost("10.0.0.5") {
		t.Fatal("10.0.0.5 should not be loopback")
	}
}
