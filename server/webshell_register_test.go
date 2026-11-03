package server

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Autumn-27/jingwei/db"
	"github.com/Autumn-27/jingwei/scanner"
	actool "github.com/Autumn-27/norma/tool"
)

// A round uploaded a dozen shells over raw HTTP and none of them entered the
// webshell ledger, because the only registration path was the manual REST call.
// buildWebshellMaterial is the shared core both paths use, so it is pinned here
// without a database: the columns it fills decide whether evacuation can speak
// to (and self-delete) the shell later.
func TestBuildWebshellMaterial(t *testing.T) {
	s := &Server{jwtKey: []byte("test-jwt-signing-key-32-bytes!!")}

	t.Run("空协议默认 v2 并封存密钥", func(t *testing.T) {
		in := db.WebshellInput{ShellType: "php"}
		payload, bad, err := s.buildWebshellMaterial(&in)
		if err != nil || bad {
			t.Fatalf("v2 material: bad=%v err=%v", bad, err)
		}
		if in.Protocol != scanner.ShellProtocolV2 || in.Password != "" {
			t.Fatalf("unexpected v2 columns: %+v", in)
		}
		if !strings.HasPrefix(in.Secret, shellSecretPrefix) || strings.Contains(in.Secret, string(payload.Key)) {
			t.Fatalf("secret not sealed: %q", in.Secret)
		}
		if in.Carrier == "" || in.PayloadSHA256 == "" || in.KeyVersion != 1 {
			t.Fatalf("material columns not filled: %+v", in)
		}
		if in.Carrier != payload.Carrier || in.PayloadSHA256 != payload.SHA256 {
			t.Fatal("stored fingerprint differs from the built payload")
		}
		plain, err := openShellSecret(s.jwtKey, in.Secret)
		if err != nil {
			t.Fatalf("open sealed secret: %v", err)
		}
		if plain != scanner.EncodeShellKey(payload.Key) {
			t.Fatal("sealed secret did not round-trip the payload key")
		}
		raw, err := json.Marshal(in)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if strings.Contains(string(raw), in.Secret) {
			t.Fatal("WebshellInput JSON exposes the sealed secret")
		}
	})

	t.Run("带口令时默认旧版协议", func(t *testing.T) {
		in := db.WebshellInput{ShellType: "php", Password: "legacy-password"}
		payload, bad, err := s.buildWebshellMaterial(&in)
		if err != nil || bad {
			t.Fatalf("legacy material: bad=%v err=%v", bad, err)
		}
		if in.Protocol != scanner.ShellProtocolLegacy || in.Secret != "" || in.Carrier != "" {
			t.Fatalf("unexpected legacy columns: %+v", in)
		}
		if payload.Password != "legacy-password" {
			t.Fatalf("legacy payload password: %q", payload.Password)
		}
	})

	t.Run("旧版缺口令是调用方错误", func(t *testing.T) {
		in := db.WebshellInput{ShellType: "php", Protocol: scanner.ShellProtocolLegacy}
		_, bad, err := s.buildWebshellMaterial(&in)
		if err == nil || !bad {
			t.Fatalf("legacy shell without password must be a 400-class error: bad=%v err=%v", bad, err)
		}
	})

	t.Run("未知协议是调用方错误", func(t *testing.T) {
		in := db.WebshellInput{ShellType: "php", Protocol: "ssh"}
		_, bad, err := s.buildWebshellMaterial(&in)
		if err == nil || !bad {
			t.Fatalf("unknown protocol must be a 400-class error: bad=%v err=%v", bad, err)
		}
	})
}

func TestWebshellRegisterToolGuards(t *testing.T) {
	s := &Server{jwtKey: []byte("test-jwt-signing-key-32-bytes!!")}
	var tool actool.CoreTool
	for _, t0 := range s.deepTools() {
		if t0.Name() == "webshell_register" {
			tool = t0
		}
	}
	if tool == nil {
		t.Fatal("webshell_register is not registered in deepTools()")
	}
	if !strings.Contains(tool.Description(), "撤离") || !strings.Contains(tool.Description(), "绑定任务") {
		t.Errorf("description misses the evacuation/task binding caveat: %q", tool.Description())
	}
	// Evacuation enumerates shells by task, so a registration that cannot name
	// one must fail closed instead of storing a shell no cleanup will ever walk.
	for _, tc := range []struct {
		input string
		want  string
	}{
		{`{"shell_type":"php"}`, "url 必填"},
		{`{"url":"  "}`, "url 必填"},
		{`{"url":"http://127.0.0.1:8080/shell.php"}`, "task_id 必填"},
	} {
		res, err := tool.Call(context.Background(), json.RawMessage(tc.input), nil)
		if err != nil {
			t.Fatalf("call %s: %v", tc.input, err)
		}
		text := ""
		if len(res.Content) > 0 {
			text = res.Content[0].Text
		}
		if !res.IsError || !strings.Contains(text, tc.want) {
			t.Errorf("input %s: want error %q, got is_error=%v %q", tc.input, tc.want, res.IsError, text)
		}
	}
}
