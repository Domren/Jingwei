package scanner

import (
	"sort"
	"strings"
)

// CredProtocolInfo 是协议选择器的一行。Supported=false 的协议在前端应当禁用，
// 显示为「暂不支持」——不给出这个清单，界面上就只能靠猜哪些勾了有用。
type CredProtocolInfo struct {
	Name        string `json:"name"`
	DefaultPort int    `json:"default_port"`
	Supported   bool   `json:"supported"`
}

// CredProtocolCatalog 列出所有出现在默认端口表或适配器注册表里的协议，并把
// 明确的「三档不支持」一并列出（它们可能不在端口表里）。已实现的排在前面。
func CredProtocolCatalog() []CredProtocolInfo {
	seen := map[string]bool{}
	out := make([]CredProtocolInfo, 0, len(credDefaultPorts)+len(credUnsupportedProtocols))
	add := func(name string) {
		name = normalizedProtocol(name)
		if name == "" || seen[name] {
			return
		}
		seen[name] = true
		out = append(out, CredProtocolInfo{
			Name:        name,
			DefaultPort: credDefaultPorts[name],
			Supported:   CredAdapterFor(name) != nil,
		})
	}
	for name := range credDefaultPorts {
		add(name)
	}
	credAdapterMu.RLock()
	for name := range credAdapters {
		add(name)
	}
	credAdapterMu.RUnlock()
	for name := range credUnsupportedProtocols {
		add(name)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Supported != out[j].Supported {
			return out[i].Supported
		}
		return out[i].Name < out[j].Name
	})
	return out
}

func normalizedProtocol(p string) string {
	return strings.ToLower(strings.TrimSpace(p))
}
