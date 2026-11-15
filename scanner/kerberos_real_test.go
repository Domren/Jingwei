package scanner

// kerberos_real 纯函数单测：SPN→realm 推导、KDC 发现、krb5.conf 生成、
// NT hash keytab 手工编码（gokrb5 Unmarshal 能解出正确密钥）。

import (
	"context"
	"os"
	"testing"

	"github.com/jcmturner/gokrb5/v8/iana/etypeID"
	"github.com/jcmturner/gokrb5/v8/types"
)

func TestRealmFromSPN(t *testing.T) {
	cases := []struct {
		spn, wantRealm, wantHost string
		wantErr                  bool
	}{
		{"MSSQLSvc/dc1.jwlab.local:1433", "JWLAB.LOCAL", "dc1.jwlab.local", false},
		{"HTTP/dc.jingwei.local", "JINGWEI.LOCAL", "dc.jingwei.local", false},
		{"host/shortname", "", "shortname", true},        // NetBIOS 短名且无 env → 报错
		{"nohost", "", "", true},                          // 缺 host 部分
		{"cifs/dc1.jwlab.local.", "JWLAB.LOCAL", "dc1.jwlab.local", false}, // 尾点归一
	}
	for _, c := range cases {
		realm, host, err := realmFromSPN(c.spn)
		if c.wantErr {
			if err == nil {
				t.Fatalf("realmFromSPN(%q) 期望报错，得到 realm=%q host=%q", c.spn, realm, host)
			}
			continue
		}
		if err != nil {
			t.Fatalf("realmFromSPN(%q) err=%v", c.spn, err)
		}
		if realm != c.wantRealm || host != c.wantHost {
			t.Fatalf("realmFromSPN(%q) = (%q,%q) want (%q,%q)", c.spn, realm, host, c.wantRealm, c.wantHost)
		}
	}
	// NetBIOS 短名 + env 兜底。
	t.Setenv(envKerberosRealm, "JWLAB.LOCAL")
	realm, _, err := realmFromSPN("host/shortname")
	if err != nil || realm != "JWLAB.LOCAL" {
		t.Fatalf("短名+env 推导 err=%v realm=%q", err, realm)
	}
}

func TestDiscoverKDCEnvWins(t *testing.T) {
	t.Setenv(envKDCAddr, "172.23.0.7")
	got := discoverKDC("JWLAB.LOCAL", "dc1.jwlab.local")
	if got != "172.23.0.7:88" {
		t.Fatalf("discoverKDC = %q want 172.23.0.7:88", got)
	}
	// 带端口的环境变量原样保留。
	t.Setenv(envKDCAddr, "172.23.0.7:1088")
	if got := discoverKDC("JWLAB.LOCAL", "dc1.jwlab.local"); got != "172.23.0.7:1088" {
		t.Fatalf("discoverKDC = %q want 172.23.0.7:1088", got)
	}
}

func TestKrb5ConfigString(t *testing.T) {
	s := krb5ConfigString("JWLAB.LOCAL", "172.23.0.7:88")
	for _, want := range []string{"default_realm = JWLAB.LOCAL", "kdc = 172.23.0.7:88", ".jwlab.local = JWLAB.LOCAL"} {
		if !containsStr(s, want) {
			t.Fatalf("krb5.conf 缺 %q：\n%s", want, s)
		}
	}
}

func containsStr(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || stringsContains(s, sub))
}

func stringsContains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func TestKeytabFromNTHash(t *testing.T) {
	kt, err := keytabFromNTHash("svc-sql", "JWLAB.LOCAL", makeTestKey())
	if err != nil {
		t.Fatalf("keytabFromNTHash: %v", err)
	}
	// 多 kvno 覆盖（1..8）：AS_REP 回带的 kvno 要能精确匹配上。
	if len(kt.Entries) != 8 {
		t.Fatalf("entries=%d want 8（kvno 覆盖）", len(kt.Entries))
	}
	var hit bool
	for _, e := range kt.Entries {
		if e.KVNO == 2 && e.Principal.Realm == "JWLAB.LOCAL" &&
			len(e.Principal.Components) == 1 && e.Principal.Components[0] == "svc-sql" &&
			e.Key.KeyType == etypeID.RC4_HMAC && string(e.Key.KeyValue) == string(makeTestKey()) {
			hit = true
		}
	}
	if !hit {
		t.Fatalf("kvno=2 的 RC4 entry 未按预期编入 keytab")
	}
	// GetEncryptionKey 按 AS_REP 的 kvno 精确取回密钥。
	pn := types.PrincipalName{NameType: 1, NameString: []string{"svc-sql"}}
	key, kv, err := kt.GetEncryptionKey(pn, "JWLAB.LOCAL", 2, etypeID.RC4_HMAC)
	if err != nil {
		t.Fatalf("GetEncryptionKey(kvno=2): %v", err)
	}
	if kv != 2 || string(key.KeyValue) != string(makeTestKey()) {
		t.Fatalf("kv=%d key=%x", kv, key.KeyValue)
	}
}

func makeTestKey() []byte {
	k := make([]byte, 16)
	for i := range k {
		k[i] = byte(0xA0 + i)
	}
	return k
}

// TestRealKerberoasterImplementsStubSemantic：空参数直接报错，不空转。
func TestRealKerberoasterEmptyArgs(t *testing.T) {
	k := NewRealKerberoaster()
	if _, err := k.GetTGS(context.Background(), "", "p", "HTTP/x", false); err == nil {
		t.Fatalf("空 user 应报错")
	}
	if _, err := k.GetTGS(context.Background(), "u", "", "HTTP/x", false); err == nil {
		t.Fatalf("空 password 应报错")
	}
	if _, err := k.GetTGS(context.Background(), "u", "p", "", false); err == nil {
		t.Fatalf("空 spn 应报错")
	}
	if _, err := k.DomainSPNs(context.Background(), "", "u", "p"); err == nil {
		t.Fatalf("空 ldapEndpoint 应报错")
	}
	os.Unsetenv(envKerberosRealm)
}
