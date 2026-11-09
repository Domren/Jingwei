package scanner

import (
	"strings"
)

// ShellEnv is the runtime environment a deployed PHP shell reported, reduced to
// the facts that decide what the operator can actually do with it. It is stored
// as evidence instead of being inferred from the shell type.
type ShellEnv struct {
	OS                string   `json:"os,omitempty"`
	SAPI              string   `json:"sapi,omitempty"`
	PHPVersion        string   `json:"php_version,omitempty"`
	User              string   `json:"user,omitempty"`
	Server            string   `json:"server,omitempty"`
	OpenBasedir       string   `json:"open_basedir,omitempty"`
	DisabledFunctions []string `json:"disabled_functions,omitempty"`
	ExecAvailable     bool     `json:"exec_available"`
	FileAvailable     bool     `json:"file_available"`
	FileBlocked       []string `json:"file_blocked,omitempty"`
	Warnings          []string `json:"warnings,omitempty"`
}

// phpExecFunctions are the functions the shell's E op can fall back to. The
// payload calls shell_exec; the others are reported so the operator knows
// whether a different route exists.
var phpExecFunctions = []string{"shell_exec", "exec", "system", "passthru", "popen", "proc_open"}

// phpFileFunctions are the functions the file-manager op needs. If any of them
// is disabled the op degrades, so it is reported per function instead of a
// blanket "file manager broken".
var phpFileFunctions = []string{"scandir", "fopen", "fwrite", "unlink", "rename", "mkdir", "chmod"}

// AssessShellEnv turns a probe result into capability facts. Only what the
// target actually reported is used: an unreadable disable_functions list stays
// empty rather than being guessed as "nothing disabled".
func AssessShellEnv(info ShellInfo) ShellEnv {
	env := ShellEnv{
		OS:          strings.TrimSpace(info.OS),
		SAPI:        strings.TrimSpace(info.SAPI),
		PHPVersion:  strings.TrimSpace(info.PHPVersion),
		User:        strings.TrimSpace(info.User),
		Server:      strings.TrimSpace(info.ServerSoftware),
		OpenBasedir: strings.TrimSpace(info.OpenBasedir),
	}
	disabled := map[string]bool{}
	for _, fn := range strings.Split(info.DisableFuncs, ",") {
		fn = strings.ToLower(strings.TrimSpace(fn))
		if fn == "" {
			continue
		}
		disabled[fn] = true
		env.DisabledFunctions = append(env.DisabledFunctions, fn)
	}

	for _, fn := range phpExecFunctions {
		if !disabled[fn] {
			env.ExecAvailable = true
			break
		}
	}
	if !env.ExecAvailable {
		env.Warnings = append(env.Warnings,
			"disable_functions 禁用了全部命令执行函数（"+strings.Join(phpExecFunctions, "/")+
				"），命令执行类操作会失败；壳仍可用于文件读写")
	}

	for _, fn := range phpFileFunctions {
		if disabled[fn] {
			env.FileBlocked = append(env.FileBlocked, fn)
		}
	}
	env.FileAvailable = len(env.FileBlocked) == 0
	if !env.FileAvailable {
		env.Warnings = append(env.Warnings,
			"disable_functions 禁用了文件操作函数（"+strings.Join(env.FileBlocked, "/")+
				"），文件管理功能不可用或受限")
	}
	if env.OpenBasedir != "" {
		env.Warnings = append(env.Warnings,
			"open_basedir="+env.OpenBasedir+"：文件管理只能在这些路径内操作，超出会被 PHP 拒绝")
	}
	return env
}

// PHPSourceNote explains a response that came back as unparsed PHP source. It is
// returned only when the body really looks like our payload source; otherwise
// the caller keeps the generic "not a jingwei payload" note.
func PHPSourceNote(body string) (string, bool) {
	t := strings.TrimSpace(body)
	if !strings.Contains(t, "<?php") {
		return "", false
	}
	preview := []rune(t)
	if len(preview) > 60 {
		preview = append(preview[:60], []rune("…")...)
	}
	return "落地地址返回了 PHP 源码而不是执行结果（" + string(preview) +
		"）：该上传点/目录不解析 PHP（后缀未被当作脚本，或目录未配置 PHP 处理器）。" +
		"请换用可执行 PHP 的落地点或改用对应语言的载荷", true
}
