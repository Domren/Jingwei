package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/Autumn-27/jingwei/db"
	"github.com/Autumn-27/jingwei/scanner"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// 大马（文件管理）API 层测试：list/read/write/action 走真实加密 v2 通道，
// 验证分块语义、自我保护与请求校验，而不只是 scanner 单测。

type shellFileCall struct {
	t    *testing.T
	s    *Server
	id   string
	body string
}

func (c shellFileCall) do(method, path string, query url.Values, handler http.HandlerFunc, payload any) (int, map[string]any) {
	c.t.Helper()
	target := path
	if len(query) > 0 {
		target += "?" + query.Encode()
	}
	var rdr io.Reader
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			c.t.Fatal(err)
		}
		rdr = bytes.NewReader(b)
	} else if c.body != "" {
		rdr = strings.NewReader(c.body)
	}
	req := httptest.NewRequest(method, target, rdr)
	req.SetPathValue("id", c.id)
	rec := httptest.NewRecorder()
	handler(rec, req)
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		out = map[string]any{"raw": rec.Body.String()}
	}
	return rec.Code, out
}

func (c shellFileCall) list(query url.Values) (int, map[string]any) {
	return c.do(http.MethodGet, "/api/deep/webshells/"+c.id+"/files", query, c.s.listWebshellFiles, nil)
}

func (c shellFileCall) read(query url.Values) (int, map[string]any) {
	return c.do(http.MethodGet, "/api/deep/webshells/"+c.id+"/file", query, c.s.readWebshellFile, nil)
}

func (c shellFileCall) write(payload any) (int, map[string]any) {
	return c.do(http.MethodPost, "/api/deep/webshells/"+c.id+"/file", nil, c.s.writeWebshellFile, payload)
}

func (c shellFileCall) action(payload any) (int, map[string]any) {
	return c.do(http.MethodPost, "/api/deep/webshells/"+c.id+"/files/action", nil, c.s.actionWebshellFiles, payload)
}

// phpShellFileFixture serves a real encrypted v2 PHP shell through php -S and
// registers it as a webshell row. The returned dir holds the shell plus known
// fixture files so assertions can compare against the on-disk truth.
func phpShellFileFixture(t *testing.T) (*Server, *db.DB, *db.Webshell, string, string) {
	t.Helper()
	php, err := exec.LookPath("php")
	if err != nil {
		t.Skip("php CLI not installed")
	}
	if testing.Short() {
		t.Skip("skipping php runtime file-manager test in -short mode")
	}
	pg := prescanTestDB(t)
	s := &Server{ctx: context.Background(), m: &Manager{pg: pg}, jwtKey: []byte("webshell-files-api-test-key-32b!")}
	payload, sealed, err := s.newV2ShellMaterial("php", 1)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	shellPath := filepath.Join(dir, "shell.php")
	if err := os.WriteFile(shellPath, []byte(payload.Content), 0o600); err != nil {
		t.Fatal(err)
	}
	hello := "hello jingwei file manager"
	if err := os.WriteFile(filepath.Join(dir, "hello.txt"), []byte(hello), 0o644); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(dir, "sub")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	large := make([]byte, 600<<10)
	for i := range large {
		large[i] = byte((i * 7) % 251)
	}
	if err := os.WriteFile(filepath.Join(sub, "large.bin"), large, 0o600); err != nil {
		t.Fatal(err)
	}

	port := freeServerPort(t)
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	var logs bytes.Buffer
	cmd := exec.Command(php, "-S", addr, "-t", dir)
	cmd.Stdout = &logs
	cmd.Stderr = &logs
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		if t.Failed() {
			t.Logf("php -S output:\n%s", logs.String())
		}
	})
	waitServerTCP(t, addr)

	shell, err := pg.CreateWebshell(db.WebshellInput{
		Name: "files-api-fixture", URL: "http://" + addr + "/shell.php", ShellType: "php",
		Protocol: scanner.ShellProtocolV2, Secret: sealed, Carrier: payload.Carrier,
		PayloadSHA256: payload.SHA256, KeyVersion: 1, Target: "127.0.0.1", Source: "manual",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = pg.DeleteWebshell(shell.ID) })
	return s, pg, shell, dir, shellPath
}

func errText(out map[string]any) string {
	if e, ok := out["error"].(string); ok {
		return e
	}
	return fmt.Sprintf("%v", out)
}

func TestWebshellFileAPIRoundTripPHP(t *testing.T) {
	s, pg, shell, dir, shellPath := phpShellFileFixture(t)
	c := shellFileCall{t: t, s: s, id: strconv.FormatInt(shell.ID, 10)}

	code, list := c.list(url.Values{"path": {dir}})
	if code != http.StatusOK {
		t.Fatalf("list = %d %s", code, errText(list))
	}
	if list["path"] != dir {
		t.Fatalf("list path = %v want %q", list["path"], dir)
	}
	if want := float64(scanner.ShellFileChunkSize); list["chunk_size"] != want {
		t.Fatalf("chunk_size = %v want %v", list["chunk_size"], want)
	}
	if want := float64(scanner.ShellFileMaxRead); list["max_read"] != want {
		t.Fatalf("max_read = %v want %v", list["max_read"], want)
	}
	if list["parent"] != filepath.Dir(dir) {
		t.Fatalf("parent = %v want %q", list["parent"], filepath.Dir(dir))
	}
	entries, _ := list["entries"].([]any)
	names := map[string]bool{}
	for _, raw := range entries {
		e, _ := raw.(map[string]any)
		names[fmt.Sprint(e["name"])] = true
	}
	for _, want := range []string{"shell.php", "hello.txt", "sub"} {
		if !names[want] {
			t.Fatalf("list missing %q: %+v", want, entries)
		}
	}
	fresh, err := pg.GetWebshell(shell.ID)
	if err != nil {
		t.Fatal(err)
	}
	if fresh.Status != "alive" {
		t.Fatalf("file-manager use did not mark shell alive: %q", fresh.Status)
	}

	helloPath := filepath.Join(dir, "hello.txt")
	code, got := c.read(url.Values{"path": {helloPath}, "offset": {"0"}, "length": {"1024"}})
	if code != http.StatusOK {
		t.Fatalf("read = %d %s", code, errText(got))
	}
	data, _ := base64.StdEncoding.DecodeString(fmt.Sprint(got["data"]))
	if string(data) != "hello jingwei file manager" {
		t.Fatalf("read data = %q", data)
	}
	if got["eof"] != true || got["size"] != float64(len(data)) || got["bytes"] != float64(len(data)) {
		t.Fatalf("read chunk = %+v", got)
	}

	// 大文件按 UI 下载循环分块读取，必须能完整还原。
	largePath := filepath.Join(dir, "sub", "large.bin")
	onDisk, err := os.ReadFile(largePath)
	if err != nil {
		t.Fatal(err)
	}
	var assembled []byte
	var offset float64
	for i := 0; i < 8; i++ {
		code, chunk := c.read(url.Values{
			"path": {largePath}, "offset": {strconv.FormatInt(int64(offset), 10)},
			"length": {strconv.Itoa(scanner.ShellFileChunkSize)},
		})
		if code != http.StatusOK {
			t.Fatalf("chunked read %d = %d %s", i, code, errText(chunk))
		}
		part, derr := base64.StdEncoding.DecodeString(fmt.Sprint(chunk["data"]))
		if derr != nil {
			t.Fatalf("chunk %d base64: %v", i, derr)
		}
		if int64(offset) != int64(chunk["offset"].(float64)) {
			t.Fatalf("chunk %d offset = %v want %v", i, chunk["offset"], offset)
		}
		assembled = append(assembled, part...)
		offset += float64(len(part))
		if chunk["eof"] == true {
			break
		}
		if !bytes.Equal(onDisk[:int(offset)], assembled) {
			t.Fatalf("chunk %d diverged from disk at offset %v", i, offset)
		}
	}
	if !bytes.Equal(assembled, onDisk) {
		t.Fatalf("chunked read got %d bytes, want %d", len(assembled), len(onDisk))
	}

	// 上传：起始块截断，后续块按累计偏移追加。
	written := filepath.Join(dir, "uploaded.bin")
	first := []byte("chunk-one-")
	second := []byte{0x00, 0x10, 0xff, 'J', 'W'}
	code, res := c.write(map[string]any{
		"path": written, "offset": 0, "start": true,
		"data": base64.StdEncoding.EncodeToString(first),
	})
	if code != http.StatusOK {
		t.Fatalf("write head = %d %s", code, errText(res))
	}
	if res["written"] != float64(len(first)) || res["size"] != float64(len(first)) {
		t.Fatalf("write head result = %+v", res)
	}
	code, res = c.write(map[string]any{
		"path": written, "offset": len(first), "start": false,
		"data": base64.StdEncoding.EncodeToString(second),
	})
	if code != http.StatusOK {
		t.Fatalf("write tail = %d %s", code, errText(res))
	}
	if want := append(append([]byte{}, first...), second...); !bytes.Equal(mustReadFile(t, written), want) {
		t.Fatalf("uploaded file = %q want %q", mustReadFile(t, written), want)
	}

	code, moved := c.action(map[string]any{"action": "mkdir", "path": filepath.Join(dir, "newdir", "child")})
	if code != http.StatusOK {
		t.Fatalf("mkdir = %d %s", code, errText(moved))
	}
	if _, err := os.Stat(filepath.Join(dir, "newdir", "child")); err != nil {
		t.Fatalf("mkdir did not create the tree: %v", err)
	}
	renamed := filepath.Join(dir, "newdir", "child", "uploaded.bin")
	code, out := c.action(map[string]any{"action": "rename", "path": written, "target": renamed})
	if code != http.StatusOK {
		t.Fatalf("rename = %d %s", code, errText(out))
	}
	if _, err := os.Stat(renamed); err != nil {
		t.Fatalf("renamed file missing: %v", err)
	}
	code, out = c.action(map[string]any{"action": "chmod", "path": renamed, "mode": "0600"})
	if code != http.StatusOK {
		t.Fatalf("chmod = %d %s", code, errText(out))
	}
	info, err := os.Stat(renamed)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("chmod applied as %v", info.Mode().Perm())
	}
	code, out = c.action(map[string]any{"action": "delete", "path": filepath.Join(dir, "newdir"), "recursive": true})
	if code != http.StatusOK {
		t.Fatalf("recursive delete = %d %s", code, errText(out))
	}
	if _, err := os.Stat(filepath.Join(dir, "newdir")); !os.IsNotExist(err) {
		t.Fatalf("recursive delete left %v", err)
	}

	// 已部署的 shell 文件受保护：写、删、改权限都必须被拒绝且原文件不变。
	before := mustReadFile(t, shellPath)
	for name, call := range map[string]func() (int, map[string]any){
		"write": func() (int, map[string]any) {
			return c.write(map[string]any{
				"path": shellPath, "offset": 0, "start": true,
				"data": base64.StdEncoding.EncodeToString([]byte("broken")),
			})
		},
		"delete": func() (int, map[string]any) {
			return c.action(map[string]any{"action": "delete", "path": shellPath})
		},
		"chmod": func() (int, map[string]any) {
			return c.action(map[string]any{"action": "chmod", "path": shellPath, "mode": "0777"})
		},
		"rename": func() (int, map[string]any) {
			return c.action(map[string]any{"action": "rename", "path": shellPath, "target": filepath.Join(dir, "gone.php")})
		},
	} {
		code, out := call()
		if code == http.StatusOK || !strings.Contains(errText(out), "protected") {
			t.Fatalf("protected shell %s allowed: %d %s", name, code, errText(out))
		}
	}
	if !bytes.Equal(mustReadFile(t, shellPath), before) {
		t.Fatal("shell file content changed after refused file operations")
	}

	code, out = c.read(url.Values{"path": {filepath.Join(dir, "missing.txt")}, "offset": {"0"}})
	if code == http.StatusOK {
		t.Fatalf("reading a missing file succeeded: %+v", out)
	}
	if !strings.Contains(errText(out), "文件读取失败") {
		t.Fatalf("missing file error = %s", errText(out))
	}
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestWebshellFileAPIValidationAndGuards checks that the API refuses legacy
// shells, blocked targets and malformed requests before touching the target.
func TestWebshellFileAPIValidationAndGuards(t *testing.T) {
	pg := prescanTestDB(t)
	s := &Server{ctx: context.Background(), m: &Manager{pg: pg}, jwtKey: []byte("webshell-files-guard-test-key-32")}
	payload, sealed, err := s.newV2ShellMaterial("php", 1)
	if err != nil {
		t.Fatal(err)
	}
	v2, err := pg.CreateWebshell(db.WebshellInput{
		Name: "guard-v2-dead", URL: "http://127.0.0.1:9/dead.php", ShellType: "php",
		Protocol: scanner.ShellProtocolV2, Secret: sealed, Carrier: payload.Carrier,
		PayloadSHA256: payload.SHA256, KeyVersion: 1, Target: "127.0.0.1", Source: "manual",
	})
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := pg.CreateWebshell(db.WebshellInput{
		Name: "guard-legacy", URL: "http://127.0.0.1:9/legacy.php", ShellType: "php",
		Protocol: "legacy", Password: "jingwei", Target: "127.0.0.1", Source: "manual",
	})
	if err != nil {
		t.Fatal(err)
	}
	noURL, err := pg.CreateWebshell(db.WebshellInput{
		Name: "guard-no-url", URL: "  ", ShellType: "php",
		Protocol: scanner.ShellProtocolV2, Secret: sealed, Carrier: payload.Carrier,
		PayloadSHA256: payload.SHA256, KeyVersion: 1, Target: "127.0.0.1", Source: "manual",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for _, id := range []int64{v2.ID, legacy.ID, noURL.ID} {
			_, _ = pg.DeleteWebshell(id)
		}
	})

	c := shellFileCall{t: t, s: s, id: strconv.FormatInt(v2.ID, 10)}

	t.Run("未知 id", func(t *testing.T) {
		unknown := shellFileCall{t: t, s: s, id: "999999999"}
		code, out := unknown.list(nil)
		if code != http.StatusNotFound {
			t.Fatalf("list unknown id = %d %s", code, errText(out))
		}
	})

	t.Run("旧版口令壳拒绝", func(t *testing.T) {
		old := shellFileCall{t: t, s: s, id: strconv.FormatInt(legacy.ID, 10)}
		code, out := old.list(nil)
		if code != http.StatusBadRequest || !strings.Contains(errText(out), "仅支持加密 v2") {
			t.Fatalf("legacy list = %d %s", code, errText(out))
		}
		code, out = old.action(map[string]any{"action": "mkdir", "path": "/tmp/jw"})
		if code != http.StatusBadRequest || !strings.Contains(errText(out), "仅支持加密 v2") {
			t.Fatalf("legacy action = %d %s", code, errText(out))
		}
	})

	t.Run("没有可用地址", func(t *testing.T) {
		blank := shellFileCall{t: t, s: s, id: strconv.FormatInt(noURL.ID, 10)}
		code, out := blank.list(nil)
		if code != http.StatusBadRequest || !strings.Contains(errText(out), "没有可用地址") {
			t.Fatalf("blank url list = %d %s", code, errText(out))
		}
	})

	t.Run("命中资产拦截规则", func(t *testing.T) {
		rule, err := pg.CreateAssetInterceptRule("exact_domain", "files-guard.example.test", "[测试] 拦截校验", true)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = pg.DeleteAssetInterceptRule(rule.ID) })
		blocked, err := pg.CreateWebshell(db.WebshellInput{
			Name: "guard-blocked", URL: "http://files-guard.example.test/shell.php", ShellType: "php",
			Protocol: scanner.ShellProtocolV2, Secret: sealed, Carrier: payload.Carrier,
			PayloadSHA256: payload.SHA256, KeyVersion: 1, Target: "files-guard.example.test", Source: "manual",
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _, _ = pg.DeleteWebshell(blocked.ID) })
		call := shellFileCall{t: t, s: s, id: strconv.FormatInt(blocked.ID, 10)}
		code, out := call.list(nil)
		if code != http.StatusBadRequest || !strings.Contains(errText(out), "资产拦截规则") {
			t.Fatalf("blocked list = %d %s", code, errText(out))
		}
		code, out = call.write(map[string]any{"path": "/tmp/x", "data": ""})
		if code != http.StatusBadRequest || !strings.Contains(errText(out), "资产拦截规则") {
			t.Fatalf("blocked write = %d %s", code, errText(out))
		}
	})

	t.Run("路径与参数校验", func(t *testing.T) {
		cases := []struct {
			name string
			call func() (int, map[string]any)
			want string
			code int
		}{
			{"目录路径含 NUL", func() (int, map[string]any) {
				return c.list(url.Values{"path": {"/tmp\x00evil"}})
			}, "非法字符", http.StatusBadRequest},
			{"读取空路径", func() (int, map[string]any) {
				return c.read(url.Values{"path": {"  "}})
			}, "文件路径不能为空", http.StatusBadRequest},
			{"读取偏移非法", func() (int, map[string]any) {
				return c.read(url.Values{"path": {"/tmp/a"}, "offset": {"abc"}})
			}, "偏移量无效", http.StatusBadRequest},
			{"读取长度非法", func() (int, map[string]any) {
				return c.read(url.Values{"path": {"/tmp/a"}, "length": {"0"}})
			}, "读取长度无效", http.StatusBadRequest},
			{"写入空路径", func() (int, map[string]any) {
				return c.write(map[string]any{"path": " ", "data": ""})
			}, "文件路径不能为空", http.StatusBadRequest},
			{"写入非 base64", func() (int, map[string]any) {
				return c.write(map[string]any{"path": "/tmp/a", "data": "!!!not base64!!!"})
			}, "不是有效的 base64", http.StatusBadRequest},
			{"写入超过分块上限", func() (int, map[string]any) {
				return c.write(map[string]any{
					"path": "/tmp/a", "data": base64.StdEncoding.EncodeToString(make([]byte, scanner.ShellFileChunkSize+1)),
				})
			}, "单次写入不能超过", http.StatusBadRequest},
			{"未知 action", func() (int, map[string]any) {
				return c.action(map[string]any{"action": "drop", "path": "/tmp/a"})
			}, "必须是 delete、rename、mkdir 或 chmod", http.StatusBadRequest},
			{"chmod 权限非法", func() (int, map[string]any) {
				return c.action(map[string]any{"action": "chmod", "path": "/tmp/a", "mode": "9999"})
			}, "文件操作失败", http.StatusBadGateway},
			{"请求体超过上限", func() (int, map[string]any) {
				big := shellFileCall{t: t, s: s, id: c.id, body: `{"path":"/tmp/a","data":"` + strings.Repeat("A", 3<<20) + `"}`}
				return big.write(nil)
			}, "请求格式错误", http.StatusBadRequest},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				code, out := tc.call()
				if code != tc.code {
					t.Fatalf("code = %d want %d body=%s", code, tc.code, errText(out))
				}
				if msg := errText(out); !strings.Contains(msg, tc.want) {
					t.Fatalf("error = %q want substring %q", msg, tc.want)
				}
			})
		}
	})

	t.Run("shell 不可达返回 502", func(t *testing.T) {
		code, out := c.list(nil)
		if code != http.StatusBadGateway || !strings.Contains(errText(out), "目录读取失败") {
			t.Fatalf("dead shell list = %d %s", code, errText(out))
		}
	})

	t.Run("密钥封存失败提示", func(t *testing.T) {
		broken, err := pg.CreateWebshell(db.WebshellInput{
			Name: "guard-bad-secret", URL: "http://127.0.0.1:9/broken.php", ShellType: "php",
			Protocol: scanner.ShellProtocolV2, Secret: "not-a-sealed-secret",
			Carrier: payload.Carrier, PayloadSHA256: payload.SHA256, KeyVersion: 1,
			Target: "127.0.0.1", Source: "manual",
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _, _ = pg.DeleteWebshell(broken.ID) })
		call := shellFileCall{t: t, s: s, id: strconv.FormatInt(broken.ID, 10)}
		code, out := call.list(nil)
		if code != http.StatusBadRequest {
			t.Fatalf("bad secret list = %d %s", code, errText(out))
		}
	})

	// 读超时/大响应必须受限：max_read 由后端下发给前端，用于分块下载。
	if scanner.ShellFileMaxRead <= scanner.ShellFileChunkSize {
		t.Fatalf("chunked download limits inverted: chunk=%d max=%d", scanner.ShellFileChunkSize, scanner.ShellFileMaxRead)
	}
}
