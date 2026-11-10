package scanner

import (
	"context"
	"errors"
	"strings"
)

// Kerberoaster 负责 Kerberoasting 的两步：枚举带 SPN 的域账号，以及为指定
// SPN 申请 TGS 票据。
//
// 完整实现放在 sidecar 里——MS-RPC / ASN.1 / RC4-HMAC 的细节很重，直接进主
// 进程会带进一大棵依赖树。这里只定义 credscan 与 topology 依赖的接口；生产
// 侧用 RegisterKerberoaster() 注册 sidecar 实现。默认实现是 stub，每个调用
// 都返回 ErrKerberosSidecarNotConfigured，让调用方把「sidecar 未接线」显式
// 报出来，而不是静默跳过可用的 Kerberoasting 机会。
type Kerberoaster interface {
	// GetTGS 为 spn 申请 user 的 TGS 票据。useHash 为真时 password 传 NT hash
	// （32 位 hex），否则传明文。返回 TGS-REP 的加密部分（ASN.1 hex），可直接
	// 喂给 hashcat mode 13100 / john --format=krb5tgs。
	GetTGS(ctx context.Context, user, password, spn string, useHash bool) (tgsHex string, err error)

	// DomainSPNs 通过 LDAP bind 枚举可见的 servicePrincipalName 属性。返回
	// 匹配到的账号、SPN，以及该账号是否可登录（禁用账号也可能挂 SPN，但
	// 对它做 Kerberoasting 拿不到有用的东西）。
	DomainSPNs(ctx context.Context, ldapEndpoint, ldapUser, ldapPassword string) ([]SPNRecord, error)
}

// SPNRecord 是 DomainSPNs 的一条命中。
type SPNRecord struct {
	User    string // sAMAccountName / 服务账号
	SPN     string // servicePrincipalName 值，例如 "HTTP/dc.jingwei.local"
	Enabled bool   // userAccountControl 的 0x0002 位为 0 表示启用
}

// ErrKerberosSidecarNotConfigured 由默认 stub 返回；调用方应按「Kerberoasting
// sidecar 未接线」记录，而不是把它当成「没有可打的 SPN」。
var ErrKerberosSidecarNotConfigured = errors.New("kerberoast sidecar not configured")

var kerberoaster Kerberoaster = stubKerberoaster{}

// RegisterKerberoaster 换入生产实现。注册是单向的：默认 stub 不会因为传 nil
// 而被恢复，sidecar 实现注册后对整个进程生命周期有效。
func RegisterKerberoaster(k Kerberoaster) {
	if k != nil {
		kerberoaster = k
	}
}

// DefaultKerberoaster 返回当前注册的实现。
func DefaultKerberoaster() Kerberoaster { return kerberoaster }

// stubKerberoaster 对每个调用都返回 ErrKerberosSidecarNotConfigured，这样
// 没有 sidecar 时调用链也能在测试里跑到。
type stubKerberoaster struct{}

func (stubKerberoaster) GetTGS(_ context.Context, _, _, _ string, _ bool) (string, error) {
	return "", ErrKerberosSidecarNotConfigured
}

func (stubKerberoaster) DomainSPNs(_ context.Context, _, _, _ string) ([]SPNRecord, error) {
	return nil, ErrKerberosSidecarNotConfigured
}

// ParseSPNRow 把 LDAP 抽取器产出的 "sAMAccountName|servicePrincipalName|enabled"
// 行解析成 SPNRecord。解析不了就返回 false，调用方跳过该行即可，不必报错。
func ParseSPNRow(line string) (SPNRecord, bool) {
	parts := strings.SplitN(strings.TrimSpace(line), "|", 3)
	if len(parts) < 2 {
		return SPNRecord{}, false
	}
	user := strings.TrimSpace(parts[0])
	spn := strings.TrimSpace(parts[1])
	// 账号或 SPN 为空的行没有利用价值：少一个字段的脏数据不该被当成有效记录。
	if user == "" || spn == "" {
		return SPNRecord{}, false
	}
	enabled := true
	if len(parts) >= 3 {
		// LDAP 导出常把布尔写成 Disabled/FALSE/0 等大小写混杂的形式。
		switch strings.ToLower(strings.TrimSpace(parts[2])) {
		case "disabled", "false", "0":
			enabled = false
		}
	}
	return SPNRecord{User: user, SPN: spn, Enabled: enabled}, true
}
