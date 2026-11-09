package scanner

import "testing"

// 字典的协议定向排序。规则只有一条：**只重排、不增删**。
// 少一条就等于报告里声称测过一组其实没测的口令；多一条则是凭空多打一次。

func credKey(c Credential) string { return c.Username + "\x00" + c.Password }

func TestCredOrderSNMPCommunityFirst(t *testing.T) {
	in := credBuiltin.Credentials
	out := OrderCredentialsForProtocol("snmp", in)

	if len(out) != len(in) {
		t.Fatalf("条目数变了：%d → %d（排序不许增删）", len(in), len(out))
	}
	// 多集必须一致：排序丢掉或复制了任何一条都会在这里露出来。
	count := map[string]int{}
	for _, c := range in {
		count[credKey(c)]++
	}
	for _, c := range out {
		count[credKey(c)]--
	}
	for k, n := range count {
		if n != 0 {
			t.Fatalf("条目 %q 的计数对不上（差 %d）", k, n)
		}
	}
	// SNMP 的凭据就是 community：public / private / community 必须排在最前。
	wantHead := []string{"public", "private", "community"}
	for i, pw := range wantHead {
		if out[i].Username != "" || out[i].Password != pw {
			t.Fatalf("第 %d 条应为纯口令 %q，实际 %+v", i+1, pw, out[i])
		}
	}
	// 其余条目的相对顺序保持原样（稳定分区）。
	seen := 0
	for _, c := range in {
		if snmpCommunityCred(c) {
			continue
		}
		for snmpCommunityCred(out[seen]) {
			seen++
		}
		if credKey(out[seen]) != credKey(c) {
			t.Fatalf("非 community 条目的相对顺序被改动：want %+v got %+v", c, out[seen])
		}
		seen++
	}
}

// snmpCommunityCred 判断一条是不是「纯口令」形态的 community。
// 用集合而不是逐个比较：vendor 档加一条 community 时，这条测试不该跟着改。
func snmpCommunityCred(c Credential) bool {
	if c.Username != "" {
		return false
	}
	for _, pw := range credProtocolCommunityFirst["snmp"] {
		if c.Password == pw {
			return true
		}
	}
	return false
}

func TestCredOrderOtherProtocolsUntouched(t *testing.T) {
	in := credBuiltin.Credentials
	for _, proto := range []string{"ssh", "mysql", "redis", "mssql", "svn", ""} {
		out := OrderCredentialsForProtocol(proto, in)
		if len(out) != len(in) {
			t.Fatalf("%s: 条目数变了", proto)
		}
		for i := range in {
			if credKey(in[i]) != credKey(out[i]) {
				t.Fatalf("%s 的顺序不该被改动：第 %d 条 %+v → %+v", proto, i, in[i], out[i])
			}
		}
	}
}

func TestCredOrderEdgeCases(t *testing.T) {
	for _, proto := range []string{"snmp", "ssh"} {
		if got := OrderCredentialsForProtocol(proto, nil); len(got) != 0 {
			t.Fatalf("%s: nil 输入不该产出条目: %+v", proto, got)
		}
		one := []Credential{{Username: "root", Password: "root"}}
		if got := OrderCredentialsForProtocol(proto, one); len(got) != 1 || got[0] != one[0] {
			t.Fatalf("%s: 单条输入被改动: %+v", proto, got)
		}
	}
}

// 操作员导入的字典可能只有 community 形态的条目：排序后 public 仍要先试，
// 且不能因为「没有用户名」这条规则把顺序整体翻掉。
func TestCredOrderImportedCommunityDict(t *testing.T) {
	in := []Credential{{Password: "wrong1"}, {Password: "public"}, {Username: "u", Password: "p"}}
	out := OrderCredentialsForProtocol("snmp", in)
	if len(out) != 3 {
		t.Fatalf("条目数变了: %+v", out)
	}
	if out[0].Password != "public" {
		t.Fatalf("public 应排在最前: %+v", out)
	}
	if out[2].Username != "u" {
		t.Fatalf("带用户名的条目应排在 community 形态之后: %+v", out)
	}
}
