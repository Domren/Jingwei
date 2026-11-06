package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Autumn-27/jingwei/scanner"
)

// 工作台上的「exec() 语境形式」走的就是这个接口。它只做静态换算，所以断言里最要紧的一条是
// **给不出去时必须说清楚为什么**，而不是回一个看着能用、语义已经变掉的形式。
func TestExecFormEndpoint(t *testing.T) {
	s, _ := newCredTestServer(t)

	post := func(command, osKind string) (int, scanner.ExecForm, string) {
		t.Helper()
		body, err := json.Marshal(map[string]any{"command": command, "os_kind": osKind})
		if err != nil {
			t.Fatal(err)
		}
		rec := httptest.NewRecorder()
		s.execForm(rec, httptest.NewRequest(http.MethodPost, "/api/deep/exec-form", bytes.NewReader(body)))
		var form scanner.ExecForm
		if rec.Code == http.StatusOK {
			if err := json.Unmarshal(rec.Body.Bytes(), &form); err != nil {
				t.Fatalf("响应不是 JSON：%v / %s", err, rec.Body.String())
			}
			return rec.Code, form, ""
		}
		var errPayload map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &errPayload)
		msg, _ := errPayload["error"].(string)
		return rec.Code, form, msg
	}

	code, form, _ := post("cat /etc/passwd | grep root", "posix")
	if code != http.StatusOK {
		t.Fatalf("常见管道命令不该报错：%d", code)
	}
	if !form.NeedsShell || len(form.Argv) != 3 || form.Argv[0] != "/bin/sh" || form.Argv[1] != "-c" {
		t.Fatalf("argv 语境形式不对：%+v", form)
	}
	if form.Single == "" || !strings.HasPrefix(form.Single, "/bin/sh -c ") {
		t.Fatalf("单串形式缺失：%+v", form)
	}
	if strings.ContainsAny(strings.TrimPrefix(form.Single, "/bin/sh -c "), " \t\n") {
		t.Fatalf("单串形式的命令体里不该有空白：%q", form.Single)
	}
	if len(form.TypedTokens) < 4 {
		t.Fatalf("没有演示原命令会被切成什么：%v", form.TypedTokens)
	}

	// 重定向：给不出单串形式，但必须给出原因并指向 argv 语境。
	code, form, _ = post("cat /etc/passwd 2>/dev/null | head", "posix")
	if code != http.StatusOK {
		t.Fatalf("换算不该报错：%d", code)
	}
	if form.Single != "" {
		t.Fatalf("重定向不该有单串形式：%q", form.Single)
	}
	if !strings.Contains(form.Reason, "重定向") || !strings.Contains(form.Reason, "argv") {
		t.Fatalf("拒绝原因没点名重定向或没指向 argv 语境：%q", form.Reason)
	}
	if len(form.Argv) != 3 {
		t.Fatalf("拒绝单串不等于拒绝给 argv 形式：%q", form.Argv)
	}

	// Windows：只给 cmd.exe 的 argv，不猜 CreateProcess 那两层切分。
	_, form, _ = post(`dir /s /b "C:\Program Files"`, "windows")
	if form.OS != "windows" || len(form.Argv) != 3 || form.Argv[0] != "cmd.exe" || form.Single != "" {
		t.Fatalf("Windows 侧形式不对：%+v", form)
	}

	// 空命令与解析不了的命令都是 400，并把原因带回去（不是套话）。
	if code, _, msg := post("   ", "posix"); code != http.StatusBadRequest || !strings.Contains(msg, "空") {
		t.Fatalf("空命令应当 400 并说明：%d %q", code, msg)
	}
	if code, _, msg := post("echo '未闭合", "posix"); code != http.StatusBadRequest || msg == "" {
		t.Fatalf("解析不了应当 400 并给出原因：%d %q", code, msg)
	}
}

// 接口注册在 mux 上由 routes_wired_test.go 的点名表兜住（它还会扫 api.ts 全量路径）。
// 这里只补一条「换算不依赖数据库」的证据：没有登录态、没有目标，也能算。
func TestPrepareExecFormNeedsNoTarget(t *testing.T) {
	form, err := scanner.PrepareExecForm("whoami", "posix")
	if err != nil {
		t.Fatal(err)
	}
	if form.NeedsShell || len(form.Argv) != 1 || form.Argv[0] != "whoami" {
		t.Fatalf("纯字面命令应当直接是 argv：%+v", form)
	}
	if form.Single != "/bin/sh -c whoami" {
		t.Fatalf("单串形式不对：%q", form.Single)
	}
}
