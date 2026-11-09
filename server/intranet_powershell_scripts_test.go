package server

import (
	"bytes"
	"context"
	"log"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/jingwei/db"
	"github.com/Autumn-27/jingwei/scanner"
)

// A2 遗留的端到端证据：用仓库已有的进程内 SSH 靶机（逐脚本应答）建出一个
// PowerShell 会话，然后证明上传/下载/权限维持不再把 cmd 语法脚本投递过去，
// 且都是明确失败而非静默成功。依赖测试库；未配置 JINGWEI_PG_DSN 时按项目
// 惯例由 prescanTestDB 直接 Skip（见验收报告「Skip 原因」）。

func newPowerShellGuardFixture(t *testing.T) (*Server, *db.DB, *db.IntranetSession, *labPowerShellShell) {
	t.Helper()
	pg := prescanTestDB(t)
	task, err := pg.CreateTask("powershell cmd-script guard fixture", "10.99.0.31", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	purgeTaskFixture(t, pg, task.ID)
	sshFixtureCleanup(t, pg, task.ID)
	if _, err := pg.Assets().AddAgentScope(task.ID, "ip", "10.99.0.0/24", "fixture", "manual"); err != nil {
		t.Fatal(err)
	}
	cred, err := pg.UpsertIntranetCredential(db.IntranetCredentialInput{
		Host: "10.99.0.31", Port: 22, Protocol: "ssh",
		Username: "labuser", Password: "lab-pass-ps", Source: "weakpass", TaskID: task.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	shell := &labPowerShellShell{pwd: `C:\Users\labuser`, exitCode: 0}
	srv := newLabSSHServer(t, "labuser", "lab-pass-ps", shell.exec)
	s := &Server{m: &Manager{pg: pg}}
	sess, _, err := s.intranetOpenSSHSession(context.Background(), pg, intranetSSHSessionRequest{
		Name: "ps guard", TaskID: task.ID, Host: "10.99.0.31", Port: 22,
		CredentialID: cred.ID, DialHost: "127.0.0.1", DialPort: srv.port(),
	})
	if err != nil {
		t.Fatalf("PowerShell 主机必须能建成会话: %v", err)
	}
	if sess.Metadata["shell"] != intranetShellPowerShell {
		t.Fatalf("会话解释器应为 powershell，实得 %#v", sess.Metadata)
	}
	return s, pg, sess, shell
}

func TestPowerShellSessionRefusesCmdTransferAndPersist(t *testing.T) {
	s, pg, sess, shell := newPowerShellGuardFixture(t)
	ctx := context.Background()

	// 下游会把 outcome.Note 改写成泛化文案；守卫日志必须留下点名原因。
	var buf bytes.Buffer
	old := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(old)

	before := len(shell.all())

	// 上传：仍是 cmd 形态的分块/certutil 脚本，必须明确失败。
	upOut, upErr := s.intranetUpload(ctx, pg, sess, `C:\Users\labuser\x.txt`, []byte("hello jingwei"))
	if upErr == nil || !upOut.IsError {
		t.Fatalf("PowerShell 会话的上传必须明确失败，不能静默成功: out=%+v err=%v", upOut, upErr)
	}

	// 下载：仍是 cmd 形态的 for/certutil 脚本，必须明确失败。
	_, _, _, dlOut := s.intranetDownload(ctx, pg, sess, `C:\Users\labuser\x.txt`, 0)
	if !dlOut.IsError {
		t.Fatalf("PowerShell 会话的下载必须明确失败，不能静默成功: %+v", dlOut)
	}

	// 权限维持：入口直接点名拒绝，不生成、不投递、不落库。
	_, _, _, _, pErr := s.intranetPersist(ctx, pg, intranetPersistInput{
		SessionID: sess.ID, Kind: db.IntranetArtifactSchtasks,
		Command: "whoami", Schedule: "onlogon",
	})
	if pErr == nil {
		t.Fatal("PowerShell 会话的权限维持必须明确失败")
	}
	for _, want := range []string{"PowerShell", "cmd.exe", "未静默成功"} {
		if !strings.Contains(pErr.Error(), want) {
			t.Fatalf("维持拒绝原因要点名 %q，实得 %q", want, pErr.Error())
		}
	}

	// 核心断言：守卫之后靶机一条 cmd 语法脚本都没收到。
	sent := shell.all()
	if len(sent) < before {
		t.Fatal("靶机命令记录异常")
	}
	cmdMarkers := []string{
		"if exist ", "certutil ", "schtasks /", "reg add ", "sc create ",
		"for %I in (", "cmd /c exit 0", ">nul 2>&1", ">>C:\\", "move /y ",
	}
	for _, sc := range sent[before:] {
		for _, m := range cmdMarkers {
			if strings.Contains(sc, m) {
				t.Fatalf("PowerShell 靶机收到了 cmd 语法脚本（命中 %q）: %s", m, sc)
			}
		}
	}

	logged := buf.String()
	if !strings.Contains(logged, "PowerShell") || !strings.Contains(logged, "cmd.exe") {
		t.Fatalf("守卫的点名原因没有写明到服务端日志: %q", logged)
	}
}

// TestPowerShellSSHTransportNeverSeesCmdScripts 用同一个进程内 SSH 靶机
// （逐脚本应答）在传输层把三态都跑一遍，且不需要测试库：守卫是唯一改动点，
// 因此「靶机实际收到什么」就是不依赖 Postgres 也能复核的端到端证据。
func TestPowerShellSSHTransportNeverSeesCmdScripts(t *testing.T) {
	srv := newLabSSHServer(t, "lab", "pw", func(script string) (string, int) {
		if strings.Contains(script, "$ErrorActionPreference") {
			return psTrailer("LAB-OUT", `C:\Users\lab`, 0), 0
		}
		return markerEcho("LAB-OUT", `C:\Users\lab`, 0), 0
	})
	send := func(ctx context.Context, script string, timeout time.Duration) (string, error) {
		return scanner.RunSSHCommand(ctx, scanner.SSHCommandTarget{
			Addr: srv.addr(), User: "lab", Password: "pw", Timeout: timeout,
		}, script)
	}
	ctx := context.Background()
	cmdScript := `if exist "C:\x.txt" (echo JW_FILE_EXISTS) else (echo JW_FILE_NEW)`

	// PowerShell 会话：守卫在投递前拒绝，靶机一次 exec 都不该收到。
	res := shellExec(ctx, send, `C:\Users\lab`, intranetOSWindows,
		intranetShellPowerShell, cmdScript, 5*time.Second)
	if !res.IsError || res.MarkerOK {
		t.Fatalf("cmd 脚本必须明确失败: %+v", res)
	}
	if got := srv.commands(); len(got) != 0 {
		t.Fatalf("PowerShell 靶机收到了 cmd 语法脚本: %v", got)
	}

	// cmd 会话：原样投递 cmd 包装，不回归。
	res = shellExec(ctx, send, `C:\Users\lab`, intranetOSWindows,
		intranetShellCmd, cmdScript, 5*time.Second)
	if res.IsError || !res.MarkerOK {
		t.Fatalf("cmd 会话被守卫误伤: %+v", res)
	}
	got := srv.commands()
	if len(got) != 1 || !strings.Contains(got[0], "chcp 65001") || !strings.Contains(got[0], cmdScript) {
		t.Fatalf("cmd 会话没有按原样投递: %v", got)
	}

	// sh 会话：POSIX 包装照旧，不回归。
	res = shellExec(ctx, send, "/tmp", intranetOSPosix, intranetShellSh, "id", 5*time.Second)
	if res.IsError || !res.MarkerOK {
		t.Fatalf("sh 会话被守卫误伤: %+v", res)
	}
	if got := srv.commands(); len(got) != 2 || !strings.Contains(got[1], "trap") {
		t.Fatalf("sh 会话没有按 POSIX 包装投递: %v", got)
	}

	// PowerShell 原生命令：靶机收到且确实是 PowerShell 包装，不回归。
	res = shellExec(ctx, send, `C:\Users\lab`, intranetOSWindows,
		intranetShellPowerShell, "Get-Process", 5*time.Second)
	if res.IsError || !res.MarkerOK {
		t.Fatalf("PowerShell 原生命令被误拒: %+v", res)
	}
	if got := srv.commands(); len(got) != 3 || !strings.Contains(got[2], "$ErrorActionPreference") {
		t.Fatalf("PowerShell 原生命令没有用 PS 包装投递: %v", got)
	}
}
