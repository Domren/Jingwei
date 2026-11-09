package scanner

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// 真机验证：每个协议都对着一个真实服务跑「命中」与「拒绝」两条路径。
//
// 开法：先跑 tools/e2e/credscan-lab/up.sh 起服务，再
//
//	JW_CRED_LAB=1 go test ./scanner -run TestCredLab -count=1 -v
//
// 为什么不用进程内靶子了事：适配器的错误大多只有在线上路得出来——包序号差一格、
// salt 少取两字节、SCRAM 的 nonce 拼错，自写靶子可能和适配器错得一模一样。
// 反过来，靶子内的真协议实现也不如真库可信：PG 16 的默认就是 scram-sha-256，
// MariaDB 的默认是 native，caching_sha2 的完整认证通道只有真 MySQL 8 才会逼你走。
//
// 口令来自 up.sh 现场生成的清单文件（600 权限，不进仓库、不打印）。
func TestCredLabProtocols(t *testing.T) {
	lab := loadCredLab(t)
	if lab == nil {
		t.Skip("没开 JW_CRED_LAB=1 或没有 /tmp/jw-cred-lab/lab.json；先跑 tools/e2e/credscan-lab/up.sh")
	}
	for _, c := range lab.Cases {
		c := c
		t.Run(c.Protocol+"/"+sanitizeName(c.Label), func(t *testing.T) {
			adapter := CredAdapterFor(c.Protocol)
			if adapter == nil {
				t.Fatalf("协议 %q 没有注册适配器", c.Protocol)
			}
			ep := c.endpoint()

			confirmed, banner, err := adapter.Identify(credLabCtx(t), ep)
			if err != nil {
				t.Fatalf("Identify 出错: %v", err)
			}
			if !confirmed {
				t.Fatalf("真实服务上没确认出协议（banner=%q）", banner)
			}
			if banner == "" {
				t.Fatal("确认了协议却没留下任何 banner，报告里就没法说明凭什么")
			}

			// 命中路径
			if c.ExpectGood != "" {
				got := runCredLab(t, ep, []Credential{{Username: c.Username, Password: c.Password}})
				if len(got) != 1 {
					t.Fatalf("该有 1 行结果: %+v", got)
				}
				if string(got[0].Outcome) != c.ExpectGood {
					t.Fatalf("正确凭据的结果 = %q want %q (reason=%q banner=%q)\nREQ=%q RESP=%q",
						got[0].Outcome, c.ExpectGood, got[0].Reason, got[0].Banner,
						string(got[0].RawReq), string(got[0].RawResp))
				}
				if c.ExpectTLS != nil && got[0].TLS != *c.ExpectTLS {
					t.Fatalf("TLS 通道状态 = %v want %v（服务端支持 TLS 时适配器必须升上去，走明文不能被 outcome 反映）",
						got[0].TLS, *c.ExpectTLS)
				}
				assertCredEvidence(t, got[0])
				t.Logf("命中: outcome=%s tls=%v banner=%.120s", got[0].Outcome, got[0].TLS, got[0].Banner)
			}

			// 拒绝路径：这条必须存在——只验命中等于没验「拒绝长什么样」，
			// 而 deny 是报告里唯一能说「这组口令被排除」的态。
			if c.ExpectBad != "" && c.WrongPassword != "" {
				got := runCredLab(t, ep, []Credential{{Username: c.Username, Password: c.WrongPassword}})
				if len(got) != 1 {
					t.Fatalf("该有 1 行结果: %+v", got)
				}
				if string(got[0].Outcome) != c.ExpectBad {
					t.Fatalf("错误凭据的结果 = %q want %q (reason=%q)", got[0].Outcome, c.ExpectBad, got[0].Reason)
				}
				assertCredEvidence(t, got[0])
				t.Logf("拒绝: outcome=%s reason=%.120s", got[0].Outcome, got[0].Reason)
			}
		})
	}
}

// 协议不能靠端口号猜：把所有适配器逐个按在 HTTP 端口上，任何一个确认成功都是缺陷。
// 这一条是对「默认端口表只决定测哪个端口」那个硬约束的真机版——单测里用假适配器能测，
// 真机上更要测，因为真实 banner 的形状千奇百怪。
func TestCredLabNoProtocolGuessing(t *testing.T) {
	addr := os.Getenv("JW_CRED_LAB_HTTP")
	if addr == "" {
		addr = "127.0.0.1:8080"
	}
	if _, err := net.DialTimeout("tcp", addr, 2*time.Second); err != nil {
		t.Skipf("没有可比的 HTTP 端口（%s: %v），起一个靶场服务再跑", addr, err)
	}
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(portStr)
	for _, proto := range []string{"redis", "postgresql", "mysql", "mongodb", "ftp", "telnet", "socks5", "ssh",
		// 1.6.0 补的二档/三档里，非 HTTP 形态的那些也要过这一关：它们在真机上
		// 最容易「看见端口开着就认下协议」，而这一条正是要拦那种实现。
		"mssql", "smb", "svn", "rdp", "snmp", "routeros"} {
		adapter := CredAdapterFor(proto)
		if adapter == nil {
			t.Fatalf("协议 %q 没注册", proto)
		}
		ep := CredEndpoint{Host: host, Port: port, Protocol: proto, ProtocolConfirmed: false,
			ProtocolSource: CredProtocolSourceDefaultPort}
		confirmed, banner, err := adapter.Identify(credLabCtx(t), ep)
		if err != nil {
			continue // 连不上/超时也算「没确认」，交给下一条断言
		}
		if confirmed {
			t.Fatalf("%s 适配器把 HTTP 端口认成了自己（banner=%q）", proto, banner)
		}
		t.Logf("%-11s 正确地拒绝确认: %.80s", proto, banner)
	}
}

// 空凭据在真实服务上不能变成命中：MySQL 允许匿名账号、Redis 可能没开认证，
// 字典里混进空条目时最容易在这里产出假命中。
func TestCredLabEmptyCredentialNotHit(t *testing.T) {
	lab := loadCredLab(t)
	if lab == nil {
		t.Skip("未开真机验证")
	}
	for _, c := range lab.Cases {
		switch c.Protocol {
		case "redis", "postgresql", "ldap", "ldaps", "memcached", "zookeeper":
			// 这几类的「无认证 / trust / 匿名绑定」就是空口令本身的事实，
			// 另有专门用例；拿空凭据去测它们，本来就该命中。
			continue
		}
		ep := c.endpoint()
		got := runCredLab(t, ep, []Credential{{}})
		if len(got) == 1 && got[0].Outcome == CredHit && c.Password != "" {
			t.Fatalf("%s/%s 上空凭据被判成命中: %+v", c.Protocol, c.Label, got[0])
		}
	}
}

type credLabFile struct {
	Cases []credLabCase `json:"cases"`
}

type credLabCase struct {
	Protocol      string            `json:"protocol"`
	Label         string            `json:"label"`
	Host          string            `json:"host"`
	Port          int               `json:"port"`
	Username      string            `json:"username"`
	Password      string            `json:"password"`
	WrongPassword string            `json:"wrong_password"`
	ExpectGood    string            `json:"expect_good"`
	ExpectBad     string            `json:"expect_bad"`
	Params        map[string]string `json:"params,omitempty"`
	// ExpectTLS 断言「这一条是在 TLS 通道里认证的」——服务端开着 TLS 时适配器必须升上去，
	// 悄悄走明文也是一种错误，只是不会反映在 outcome 上，只能靠显式断言拦。
	// 用指针：没写的用例是「不关心」，写了 false 才是「断言它必须走明文」。
	ExpectTLS *bool `json:"expect_tls,omitempty"`
}

func (c credLabCase) endpoint() CredEndpoint {
	params := map[string]string{}
	for k, v := range c.Params {
		params[k] = v
	}
	return CredEndpoint{Host: c.Host, Port: c.Port, Protocol: c.Protocol,
		ProtocolSource: CredProtocolSourceExplicit, ProtocolConfirmed: false, Params: params}
}

func loadCredLab(t *testing.T) *credLabFile {
	t.Helper()
	if os.Getenv("JW_CRED_LAB") != "1" {
		return nil
	}
	path := os.Getenv("JW_CRED_LAB_MANIFEST")
	if path == "" {
		path = "/tmp/jw-cred-lab/lab.json"
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("JW_CRED_LAB=1 但读不到清单 %s: %v（先跑 tools/e2e/credscan-lab/up.sh）", path, err)
	}
	lab := &credLabFile{}
	if err = json.Unmarshal(raw, lab); err != nil {
		t.Fatalf("清单格式错误: %v", err)
	}
	if len(lab.Cases) == 0 {
		t.Fatal("清单里一条用例都没有")
	}
	return lab
}

// credLabCtx 给每条用例一个独立的超时：真机上没有预算耗尽这一说，但服务卡住时
// 测试必须失败在「这条用例」而不是整个包。
func credLabCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// runCredLab 用引擎本身跑，而不是直接调适配器：预算、限速、单次上限、六态收尾
// 都得在真机上一起过一遍，否则测的只是适配器。
func runCredLab(t *testing.T, ep CredEndpoint, creds []Credential) []CredAttempt {
	t.Helper()
	var out []CredAttempt
	err := CredRun(credLabCtx(t), []CredEndpoint{ep}, creds, CredOptions{
		Concurrency: 1, Budget: 60 * time.Second, StopLossAfter: 2,
	}, func(a CredAttempt) { out = append(out, a) })
	if err != nil && !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
		t.Fatalf("引擎返回错误: %v", err)
	}
	return out
}

func assertCredEvidence(t *testing.T, a CredAttempt) {
	t.Helper()
	ev := a.Evidence()
	if strings.TrimSpace(ev) == "" {
		t.Fatalf("结果没有证据，进不了报告: %+v", a)
	}
	switch a.Outcome {
	case CredHit, CredDeny:
		if len(a.RawReq) == 0 && len(a.RawResp) == 0 {
			t.Fatalf("%s 结论必须留下可复现的字节: reason=%q", a.Outcome, a.Reason)
		}
		if !strings.Contains(ev, "凭据:") {
			t.Fatalf("证据里没有凭据行，读者无法确认测的是哪组口令: %s", ev)
		}
		if a.TLS && !strings.Contains(strings.ToUpper(ev), "TLS") {
			// 不标出来，读者照着复现命令发一条裸 socket，必然拿不到同样的响应。
			t.Fatalf("TLS 通道内的明文必须在证据里标明: %s", ev)
		}
	}
}

func sanitizeName(s string) string {
	return strings.NewReplacer(" ", "-", "/", "-", "（", "(", "）", ")").Replace(s)
}
