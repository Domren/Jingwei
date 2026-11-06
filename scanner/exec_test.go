package scanner

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// E4 的验收是「同一命令在 shell 与 exec() 两种语境下都能得到预期输出」，所以这个文件里
// 最重要的一个用例不是断言字符串长什么样，而是**真的把三种语境各跑一遍**比对输出。

func TestPrepareExecFormLiteralArgv(t *testing.T) {
	cases := []struct {
		command string
		argv    []string
	}{
		{"id", []string{"id"}},
		{"grep -c root /etc/passwd", []string{"grep", "-c", "root", "/etc/passwd"}},
		// 带空格的参数**不是**需要 shell 的理由：引号只是分组，任何 exec 都能表达。
		{`cat "/tmp/a b"`, []string{"cat", "/tmp/a b"}},
		{`printf '%s\n' "x y"`, []string{"printf", `%s\n`, "x y"}},
		{`echo  a    b`, []string{"echo", "a", "b"}},
	}
	for _, c := range cases {
		form, err := PrepareExecForm(c.command, "linux")
		if err != nil {
			t.Fatalf("%q: %v", c.command, err)
		}
		if form.NeedsShell {
			t.Errorf("%q 被判成需要 shell：%v", c.command, form.Constructs)
		}
		if strings.Join(form.Argv, "|") != strings.Join(c.argv, "|") {
			t.Errorf("%q 的 argv = %q, want %q", c.command, form.Argv, c.argv)
		}
		if form.Single == "" {
			t.Errorf("%q 应当也能给出单串形式", c.command)
		}
	}
}

func TestPrepareExecFormNeedsShell(t *testing.T) {
	// 这些构件一旦出现在 argv 语境里就必须显式包一层解释器；判成「不需要 shell」
	// 等于把 `|` 当成参数递给程序。
	for _, c := range []struct {
		command    string
		constructs string
	}{
		{"cat /etc/passwd | grep root", "管道 |"},
		{"echo one && echo two", "短路与 &&"},
		{"echo one; echo two", ""},
		{"ls > /tmp/out.txt", "重定向 >"},
		{"echo $HOME", "变量展开"},
		{"echo $(id -u)", "命令替换"},
		{"ls /etc/p*.conf", "通配符"},
		{"cat <<< heredoc", "Here-String"},
		{"sleep 1 &", "后台执行"},
		{"FOO=1 env", "变量赋值"},
	} {
		form, err := PrepareExecForm(c.command, "linux")
		if err != nil {
			t.Fatalf("%q: %v", c.command, err)
		}
		if !form.NeedsShell {
			t.Errorf("%q 没被判成需要 shell", c.command)
			continue
		}
		if strings.Join(form.Argv, " ") != execPosixShell+" -c "+strings.TrimSpace(c.command) {
			t.Errorf("%q 的 argv 没有退回解释器包装：%q", c.command, form.Argv)
		}
		if c.constructs != "" && !strings.Contains(strings.Join(form.Constructs, "、"), c.constructs) {
			t.Errorf("%q 的构件判错：%q，期望含 %q", c.command, form.Constructs, c.constructs)
		}
	}
}

// 单串形式必须「除参数分隔外不含任何空白」，否则 Java 的 StringTokenizer 会把我们
// 编码出来的东西再切一次，等于白编码。
func TestPrepareExecFormSingleStringShape(t *testing.T) {
	form, err := PrepareExecForm("cat /etc/passwd | grep root", "linux")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(form.Single, execPosixShell+" -c ") {
		t.Fatalf("单串形式没有显式带上解释器：%q", form.Single)
	}
	token := strings.TrimPrefix(form.Single, execPosixShell+" -c ")
	if ContainsExecWhitespace(token) {
		t.Errorf("单串形式的命令体里仍有空白：%q", token)
	}
	if !strings.Contains(token, "${IFS}") {
		t.Errorf("参数分隔没有换成 ${IFS}：%q", token)
	}
	if got := ExecStringTokens(form.Single); len(got) != 3 || got[2] != token {
		t.Errorf("被 exec(String) 切碎后不是预期的 3 段：%q", got)
	}
	if got := ExecStringTokens(form.Command); len(got) != 5 {
		t.Errorf("原命令被切成 %d 段（%q），这条用例的前提变了", len(got), got)
	}
}

func TestPrepareExecFormRefusesUnencodable(t *testing.T) {
	// 拒绝而不是硬拼：拼错的命令会真的跑起来并返回 0。
	for _, c := range []string{
		"for i in 1 2; do id; done",
		"if true; then echo yes; fi",
		"cat <<EOF\nbody\nEOF",
		"A=1 env",
		"sleep 1 &",
		"(cd /tmp; pwd)",
		"a=(1 2); echo ${a[0]}",
	} {
		form, err := PrepareExecForm(c, "linux")
		if err != nil {
			t.Fatalf("%q: %v", c, err)
		}
		if form.Single != "" {
			t.Errorf("%q 不该给出单串形式，却给了 %q", c, form.Single)
		}
		if form.Reason == "" || !strings.Contains(form.Reason, "argv") {
			t.Errorf("%q 的拒绝没有说明原因或没有指向 argv 语境：%q", c, form.Reason)
		}
		if len(form.Argv) == 0 {
			t.Errorf("%q 没有给出 argv 语境的形式", c)
		}
	}
	if _, err := PrepareExecForm("echo '未闭合", "linux"); err == nil {
		t.Error("解析不了的命令应当报错，而不是给一个猜测形式")
	}
}

func TestPrepareExecFormWindows(t *testing.T) {
	form, err := PrepareExecForm(`dir /s /b "C:\Program Files"`, "windows")
	if err != nil {
		t.Fatal(err)
	}
	if form.OS != "windows" || len(form.Argv) != 3 || form.Argv[0] != execWindowsShell || form.Argv[1] != "/c" {
		t.Fatalf("Windows 侧形式不对：%+v", form)
	}
	if form.Single != "" || !strings.Contains(form.Reason, "Windows") {
		t.Errorf("Windows 侧不该有单串形式，且必须说明原因：%+v", form)
	}
}

// TestExecFormsAgreeUnderRealProcesses 是 E4 的验收本体：同一条命令，
// (a) 交给 shell、(b) 按 argv 直接 exec（无 shell）、(c) 按单串形式贴进
// `Runtime.exec(String)` 并用同一套切碎规则还原 argv——三条路的输出必须一致；
// 而对需要 shell 的构件，(b') 直接把原命令按空白切碎必须**不一致**，
// 那才是这个缺陷本来的样子（进程起来了、退出码 0、输出是错的）。
func TestExecFormsAgreeUnderRealProcesses(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("/bin/sh 不在，无法按 exec 语境实跑")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "data.txt"), []byte("root:x:0:0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "a one.txt"), []byte("one\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	envFile := filepath.Join(dir, "empty.txt")
	if err := os.WriteFile(envFile, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	// noSingle：这条命令在单串语境里表达不了，助手必须**拒绝**并说明原因，而不是给一个
	// 语义已经变了的形式。重定向是唯一一条「看着能写、其实造不出解析期词边界」的。
	for _, shell := range []string{"/bin/sh", "/bin/bash"} {
		if _, err := os.Stat(shell); err != nil {
			continue
		}
		for _, c := range []struct {
			command  string
			want     string
			noSingle string
		}{
			{"echo hello world", "hello world", ""},
			{`printf %s "a b c"`, "a b c", ""},
			{`cat ` + shellQuoteArg(filepath.Join(dir, "a one.txt")), "one", ""},
			{"cat " + shellQuoteArg(filepath.Join(dir, "data.txt")) + " | cut -d: -f1", "root", ""},
			{"echo one; echo two", "one\ntwo", ""},
			{"echo first && echo second", "first\nsecond", ""},
			{`echo 'tab here'`, "tab here", ""},
			{"cat " + shellQuoteArg(filepath.Join(dir, "data.txt")) + " | grep -c root", "1", ""},
			{"echo out 2>/dev/null", "out", "重定向"},
			{"tr a-z A-Z < " + shellQuoteArg(filepath.Join(dir, "data.txt")), "ROOT:X:0:0", "重定向"},
			{"wc -l < " + shellQuoteArg(envFile), "0", "重定向"},
		} {
			t.Run(c.command, func(t *testing.T) {
				form, err := PrepareExecForm(c.command, "linux")
				if err != nil {
					t.Fatalf("编码失败：%v", err)
				}
				viaShell := runLocal(t, shell, "-c", c.command)
				viaArgv := runArgv(t, form.Argv)
				// shell 与 argv 两种语境必须永远一致：argv 语境在最坏情况下也只是显式包一层解释器。
				for name, got := range map[string]string{"shell": viaShell, "argv": viaArgv} {
					if strings.TrimSpace(got) != strings.TrimSpace(viaShell) {
						t.Errorf("%s 语境与 shell 语境输出不同：\n got=%q\nshell=%q", name, got, viaShell)
					}
					if !strings.Contains(got, c.want) {
						t.Errorf("%s 语境输出里没有预期内容 %q：%q", name, c.want, got)
					}
				}
				if c.noSingle != "" {
					if form.Single != "" {
						t.Fatalf("重定向不该给出单串形式，却给了 %q", form.Single)
					}
					if !strings.Contains(form.Reason, c.noSingle) || !strings.Contains(form.Reason, "argv") {
						t.Fatalf("拒绝没有点名 %q 或没有指向 argv 语境：%q", c.noSingle, form.Reason)
					}
					// 反面证据：硬拼出来的形式确实会静默改掉语义（这里刻意不拼，所以只断言拒绝）。
					return
				}
				if form.Single == "" {
					t.Fatalf("这条命令应当能编成单串形式，原因：%s", form.Reason)
				}
				if form.NeedsBash {
					// 参数内部需要空白时用 `$'\x20'` 表达，那是 bash 专有写法（dash 会当字面量，
					// 输出一串 $\x20 却仍返回 0）：单串形式于是声明「必须 bash」。本机没有 bash 就别假装验过。
					if _, err := os.Stat("/bin/bash"); err != nil {
						t.Skip("需要 bash 但本机没有")
					}
					if !strings.HasPrefix(form.Single, "bash -c ") {
						t.Errorf("NeedsBash 的形式没有落在 bash 上：%q", form.Single)
					}
				} else if strings.Contains(form.Single, `$'\x20'`) {
					t.Errorf("没有标 NeedsBash 却用了 bash 专有的 ANSI-C 写法：%q", form.Single)
				}
				viaSingle := runArgv(t, ExecStringTokens(form.Single))
				if strings.TrimSpace(viaSingle) != strings.TrimSpace(viaShell) {
					t.Errorf("单串语境与 shell 语境输出不同：\n single=%q\nshell=%q\nform=%q", viaSingle, viaShell, form.Single)
				}
				if !strings.Contains(viaSingle, c.want) {
					t.Errorf("单串语境输出里没有预期内容 %q：%q", c.want, viaSingle)
				}
				if strings.ContainsAny(c.command, "|") {
					naive := runArgv(t, ExecStringTokens(c.command))
					if strings.TrimSpace(naive) == strings.TrimSpace(viaShell) {
						t.Errorf("这条命令按空白切碎后居然与 shell 一致，用例前提需要重看：%q", naive)
					}
				}
			})
		}
	}
}

// 展开类构件（变量、通配）在单串语境里靠内层 shell 完成，这里也真的跑一遍。
func TestExecFormExpansionUnderRealProcess(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"p1.conf", "p2.conf"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(name+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("JW_E4_DIR", dir)
	for _, c := range []string{
		"echo $JW_E4_DIR",
		"ls " + dir + "/p*.conf",
		"echo $(pwd)",
		`echo "${JW_E4_DIR}/x y"`,
	} {
		form, err := PrepareExecForm(c, "linux")
		if err != nil {
			t.Fatalf("%q: %v", c, err)
		}
		if !form.NeedsShell {
			t.Errorf("%q 需要 shell 展开却没判出来", c)
		}
		if form.Single == "" {
			t.Errorf("%q 没能编成单串形式：%s", c, form.Reason)
			continue
		}
		viaShell := runLocal(t, execPosixShell, "-c", c)
		viaSingle := runArgv(t, ExecStringTokens(form.Single))
		if strings.TrimSpace(viaShell) != strings.TrimSpace(viaSingle) {
			t.Errorf("%q 两种语境不同：shell=%q single=%q", c, viaShell, viaSingle)
		}
	}
}

func TestSplitCommandLineForToolBinaries(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"nuclei", []string{"nuclei"}},
		{"python3 /app/tools/webcrack/main.py", []string{"python3", "/app/tools/webcrack/main.py"}},
		{`"/opt/my tools/run.sh" --slow`, []string{"/opt/my tools/run.sh", "--slow"}},
	}
	for _, c := range cases {
		got, err := SplitCommandLine(c.in)
		if err != nil {
			t.Fatalf("%q: %v", c.in, err)
		}
		if strings.Join(got, "|") != strings.Join(c.want, "|") {
			t.Errorf("%q 切成 %q, want %q", c.in, got, c.want)
		}
	}
	// 带 shell 构件的配置值必须报错，而不是悄悄切成一个错误的 argv。
	for _, bad := range []string{"echo hi | cat", "rm -rf /tmp/x && echo done", ""} {
		if _, err := SplitCommandLine(bad); err == nil {
			t.Errorf("%q 本该报错", bad)
		} else if bad != "" && !strings.Contains(err.Error(), "列表") && !strings.Contains(err.Error(), "shell") {
			t.Errorf("%q 的报错没说清楚：%v", bad, err)
		}
	}
}

func TestPrepareExecFormLengthGuard(t *testing.T) {
	if _, err := PrepareExecForm("echo "+strings.Repeat("x", maxExecCommandLen), "linux"); err == nil {
		t.Error("超长命令应当报错")
	}
	if _, err := PrepareExecForm("   ", "linux"); err == nil {
		t.Error("空命令应当报错")
	}
}

func runLocal(t *testing.T, name string, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = os.TempDir()
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("%s %v 超时：%v", name, args, err)
	}
	return string(out)
}

// runArgv 就是「没有 shell 的执行」：第一个元素当可执行文件，其余原样是参数。
func runArgv(t *testing.T, argv []string) string {
	t.Helper()
	if len(argv) == 0 {
		t.Fatal("argv 为空")
	}
	return runLocal(t, argv[0], argv[1:]...)
}

func shellQuoteArg(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
