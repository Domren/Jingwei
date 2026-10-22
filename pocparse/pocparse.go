// Package pocparse extracts the fields Jingwei needs from a nuclei YAML template.
package pocparse

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// Template is the normalized view of a nuclei template. Content keeps the
// original YAML so execution never depends on a lossy round trip.
type Template struct {
	TemplateID  string
	Name        string
	Severity    string
	Protocol    string
	CVEID       string
	CWEID       string
	CVSSScore   *float64
	Tags        []string
	Author      string
	Description string
	References  []string
	Digest      string
	Content     string
}

type stringList []string

func (l *stringList) UnmarshalYAML(node *yaml.Node) error {
	switch node.Kind {
	case yaml.ScalarNode:
		raw := strings.TrimSpace(node.Value)
		if raw == "" {
			*l = nil
			return nil
		}
		parts := strings.Split(raw, ",")
		out := make([]string, 0, len(parts))
		for _, p := range parts {
			if p = strings.TrimSpace(p); p != "" {
				out = append(out, p)
			}
		}
		*l = out
		return nil
	case yaml.SequenceNode:
		var out []string
		if err := node.Decode(&out); err != nil {
			return err
		}
		*l = out
		return nil
	default:
		return fmt.Errorf("expected string or list, got yaml kind %d", node.Kind)
	}
}

type flexFloat struct {
	Value float64
	Set   bool
}

func (f *flexFloat) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.ScalarNode {
		return nil
	}
	raw := strings.TrimSpace(node.Value)
	if raw == "" || raw == "null" {
		return nil
	}
	var v float64
	if _, err := fmt.Sscanf(raw, "%f", &v); err != nil {
		return nil
	}
	f.Value, f.Set = v, true
	return nil
}

type rawTemplate struct {
	ID   string `yaml:"id"`
	Info struct {
		Name           string     `yaml:"name"`
		Author         stringList `yaml:"author"`
		Severity       string     `yaml:"severity"`
		Description    string     `yaml:"description"`
		Tags           stringList `yaml:"tags"`
		Reference      stringList `yaml:"reference"`
		Classification struct {
			CVEID     stringList `yaml:"cve-id"`
			CWEID     stringList `yaml:"cwe-id"`
			CVSSScore flexFloat  `yaml:"cvss-score"`
		} `yaml:"classification"`
	} `yaml:"info"`
}

var templateIDUnsafe = regexp.MustCompile(`[^a-z0-9._-]+`)

// Parse normalizes one nuclei YAML document. fallbackID is used when the
// template has no id (for imports this is the historical row name).
func Parse(content []byte, fallbackID string) (*Template, error) {
	clean := sanitizeText(strings.TrimPrefix(string(content), "\ufeff"))
	if strings.TrimSpace(clean) == "" {
		return nil, fmt.Errorf("模板内容为空")
	}
	var raw rawTemplate
	if err := yaml.Unmarshal([]byte(clean), &raw); err != nil {
		return nil, fmt.Errorf("YAML 解析失败: %w", err)
	}
	name := sanitizeText(strings.TrimSpace(raw.Info.Name))
	if name == "" {
		return nil, fmt.Errorf("缺少 info.name")
	}
	id := sanitizeText(strings.TrimSpace(raw.ID))
	if id == "" {
		id = sanitizeText(strings.TrimSpace(fallbackID))
	}
	if id == "" {
		id = slug(name)
	}
	digest := sha256.Sum256([]byte(clean))

	tpl := &Template{
		TemplateID:  id,
		Name:        name,
		Severity:    normalizeSeverity(raw.Info.Severity),
		Protocol:    detectProtocol(clean),
		CVEID:       strings.Join(cleanList(raw.Info.Classification.CVEID), ","),
		CWEID:       strings.Join(cleanList(raw.Info.Classification.CWEID), ","),
		Tags:        cleanList(raw.Info.Tags),
		Author:      strings.Join(cleanList(raw.Info.Author), ","),
		Description: sanitizeText(strings.TrimSpace(raw.Info.Description)),
		References:  cleanList(raw.Info.Reference),
		Digest:      hex.EncodeToString(digest[:]),
		Content:     clean,
	}
	if raw.Info.Classification.CVSSScore.Set {
		v := raw.Info.Classification.CVSSScore.Value
		tpl.CVSSScore = &v
	}
	return tpl, nil
}

func normalizeSeverity(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "info", "informational":
		return "info"
	case "low":
		return "low"
	case "medium", "moderate":
		return "medium"
	case "high":
		return "high"
	case "critical":
		return "critical"
	default:
		return "unknown"
	}
}

func detectProtocol(content string) string {
	var root map[string]any
	if err := yaml.Unmarshal([]byte(content), &root); err != nil {
		return ""
	}
	for _, key := range []string{"http", "requests", "tcp", "udp", "network", "dns", "file", "headless", "ssl", "websocket", "whois", "code", "javascript", "workflows"} {
		if _, ok := root[key]; ok {
			switch key {
			case "requests":
				return "http"
			case "tcp", "udp":
				return "network"
			case "workflows":
				return "workflow"
			default:
				return key
			}
		}
	}
	return ""
}

// sanitizeText strips NUL (which PostgreSQL text rejects) and replaces
// invalid UTF-8. YAML escapes such as \0 decode into real control bytes even
// when the source file itself is clean.
func sanitizeText(s string) string {
	s = strings.ReplaceAll(s, "\x00", "")
	return strings.ToValidUTF8(s, "")
}

func cleanList(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, item := range in {
		item = sanitizeText(strings.TrimSpace(item))
		if item == "" {
			continue
		}
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}
	return out
}

func slug(name string) string {
	s := strings.ToLower(strings.TrimSpace(name))
	s = templateIDUnsafe.ReplaceAllString(s, "-")
	s = strings.Trim(s, "-.")
	if len(s) > 80 {
		s = s[:80]
	}
	sum := sha256.Sum256([]byte(name))
	if s == "" {
		return "poc-" + hex.EncodeToString(sum[:4])
	}
	return s + "-" + hex.EncodeToString(sum[:4])
}
