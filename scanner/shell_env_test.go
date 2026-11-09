package scanner

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// E3 A 段：PHP 运行时环境探测结果 → 能力判定。纯函数部分先钉死语义，
// 真 PHP 运行时再证明探测真的读到了 disable_functions。

func TestAssessShellEnvClean(t *testing.T) {
	env := AssessShellEnv(ShellInfo{
		OS: "Linux", SAPI: "fpm-fcgi", PHPVersion: "8.2.20", User: "www-data",
		ServerSoftware: "nginx/1.24.0",
	})
	if !env.ExecAvailable || !env.FileAvailable {
		t.Fatalf("clean env = %+v", env)
	}
	if len(env.DisabledFunctions) != 0 || len(env.Warnings) != 0 {
		t.Fatalf("clean env should have no warnings: %+v", env)
	}
	if env.PHPVersion != "8.2.20" || env.SAPI != "fpm-fcgi" {
		t.Fatalf("env fields = %+v", env)
	}
}

func TestAssessShellEnvDisabledFunctions(t *testing.T) {
	env := AssessShellEnv(ShellInfo{
		OS: "Linux", SAPI: "apache2handler", PHPVersion: "7.4.33",
		DisableFuncs: " shell_exec , exec,system, passthru , popen,proc_open,scandir ",
		OpenBasedir:  "/var/www/html:/tmp",
	})
	if env.ExecAvailable {
		t.Fatal("all exec functions disabled but ExecAvailable=true")
	}
	if env.FileAvailable {
		t.Fatal("scandir disabled but FileAvailable=true")
	}
	if len(env.DisabledFunctions) != 7 {
		t.Fatalf("disabled = %v", env.DisabledFunctions)
	}
	if len(env.FileBlocked) != 1 || env.FileBlocked[0] != "scandir" {
		t.Fatalf("file blocked = %v", env.FileBlocked)
	}
	joined := strings.Join(env.Warnings, "|")
	for _, want := range []string{"命令执行", "文件操作", "open_basedir=/var/www/html:/tmp"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("warnings missing %q: %s", want, joined)
		}
	}
}

func TestAssessShellEnvPartialExec(t *testing.T) {
	// 只禁 shell_exec 时，payload 的 E op 会失败，但环境仍有其它执行函数；
	// 报告要如实说「shell_exec 被禁」，而不是笼统说不能执行。
	env := AssessShellEnv(ShellInfo{DisableFuncs: "shell_exec,dl"})
	if !env.ExecAvailable {
		t.Fatal("other exec functions remain; expected ExecAvailable=true")
	}
	if !env.FileAvailable {
		t.Fatal("file functions untouched; expected FileAvailable=true")
	}
	if len(env.Warnings) != 0 {
		t.Fatalf("warnings = %v", env.Warnings)
	}
}

func TestPHPSourceNote(t *testing.T) {
	if _, ok := PHPSourceNote(`{"ok":true}`); ok {
		t.Fatal("JSON body must not be treated as PHP source")
	}
	note, ok := PHPSourceNote(`<?php /* payload */ echo "x";`)
	if !ok || !strings.Contains(note, "不解析 PHP") {
		t.Fatalf("note = %q ok=%v", note, ok)
	}
}

// 真 PHP 运行时：探测必须读到真实版本；用 -d disable_functions 起服务时，
// 必须读到被禁函数并把「命令执行不可用」判出来。
func TestQueryShellInfoPHPRuntime(t *testing.T) {
	php, err := exec.LookPath("php")
	if err != nil {
		t.Skip("php CLI not installed")
	}
	if testing.Short() {
		t.Skip("skipping runtime shell test in -short mode")
	}
	key, err := GenerateShellKey()
	if err != nil {
		t.Fatal(err)
	}
	carrier, err := GenerateShellCarrier()
	if err != nil {
		t.Fatal(err)
	}
	payload, err := BuildShellPayloadV2("php", key, carrier)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "env.php"), []byte(payload.Content), 0o600); err != nil {
		t.Fatal(err)
	}
	addr := startPHPServer(t, php, dir)
	url := fmt.Sprintf("http://%s/env.php", addr)
	client := NewDeepClient(5 * time.Second)

	info, err := QueryShellInfo(context.Background(), client, url, payload)
	if err != nil {
		t.Fatalf("query shell info: %v", err)
	}
	if !strings.HasPrefix(info.PHPVersion, "8") && !strings.HasPrefix(info.PHPVersion, "7") {
		t.Fatalf("unexpected php version %q", info.PHPVersion)
	}
	env := AssessShellEnv(info)
	if !env.ExecAvailable || !env.FileAvailable {
		t.Fatalf("default php -S should allow exec and file ops: %+v", env)
	}
	if env.SAPI == "" {
		t.Fatalf("sapi missing: %+v", env)
	}
}

func TestQueryShellInfoPHPRuntimeDisabledExec(t *testing.T) {
	php, err := exec.LookPath("php")
	if err != nil {
		t.Skip("php CLI not installed")
	}
	if testing.Short() {
		t.Skip("skipping runtime shell test in -short mode")
	}
	key, err := GenerateShellKey()
	if err != nil {
		t.Fatal(err)
	}
	carrier, err := GenerateShellCarrier()
	if err != nil {
		t.Fatal(err)
	}
	payload, err := BuildShellPayloadV2("php", key, carrier)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "env2.php"), []byte(payload.Content), 0o600); err != nil {
		t.Fatal(err)
	}
	addr := startPHPServer(t, php, dir, "-d",
		"disable_functions=shell_exec,exec,system,passthru,popen,proc_open")
	url := fmt.Sprintf("http://%s/env2.php", addr)
	client := NewDeepClient(5 * time.Second)

	info, err := QueryShellInfo(context.Background(), client, url, payload)
	if err != nil {
		t.Fatalf("query shell info: %v", err)
	}
	env := AssessShellEnv(info)
	if env.ExecAvailable {
		t.Fatalf("exec should be reported unavailable: %+v (disable_functions=%q)", env, info.DisableFuncs)
	}
	if !env.FileAvailable {
		t.Fatalf("file ops untouched: %+v", env)
	}
	if !strings.Contains(strings.Join(env.Warnings, "|"), "命令执行") {
		t.Fatalf("warnings = %v", env.Warnings)
	}
}
