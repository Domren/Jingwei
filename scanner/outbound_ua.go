package scanner

import (
	"os"
	"strings"
	"sync"
)

// 出站报文的 User-Agent 统一来源（欠账 R20）。
//
// 背景：过去各处各写一串——credscan 写死 "Jingwei-CredScan"、dirfuzz 写死
// "Jingwei-DirScan"、sqlmap/nuclei/dalfox 用它们自己的默认 UA、请求重发在报文里
// 没有 UA 时被 Go 客户端补成 "Go-http-client/1.1"。这既把自研品牌暴露在报文头里，
// 也让"这是一个人在操作"这个前提不成立：同一台目标上出现三种工具指纹，等于自报家门。
//
// 口径（三条，别再各自发挥）：
//
//  1. 默认用 BrowserUA()：一串可配置的 Chrome UA，与 deepuse 的浏览器串同口径；
//  2. 需要"原生无头"时用 JINGWEI_OUTBOUND_UA=none，此时**整条 UA 头都不发**，
//     而不是发一个空值（空值比没有更显眼）；
//  3. 任何构造出站 HTTP 的地方都从这里取，不再写字面量。
//
// 注：这里不做"随机轮换"。同一任务内换 UA 会让目标侧的会话关联更难，那是
// 另一件事（guard/ua_pool.go 按任务固定分配），不能混进报文构造层。
const (
	// outboundUADefault 与 scanner.deepUserAgent 保持一致，避免同一平台出现两种浏览器串。
	outboundUADefault = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"

	// outboundUANone 表示"不发 UA 头"。
	outboundUANone = "none"
)

var (
	outboundUAOnce sync.Once
	outboundUA     string
)

// BrowserUA 返回出站请求应带的 User-Agent；返回空串表示这条请求不应带 UA 头。
//
// 可用 JINGWEI_OUTBOUND_UA 覆盖：
//
//	留空 / 未设置 → 内置浏览器串
//	none / off / - → 不发 UA 头（原生）
//	其它值        → 原样使用（便于对齐客户既有流量画像）
func BrowserUA() string {
	outboundUAOnce.Do(func() {
		raw := strings.TrimSpace(os.Getenv("JINGWEI_OUTBOUND_UA"))
		switch {
		case raw == "":
			outboundUA = outboundUADefault
		case strings.EqualFold(raw, outboundUANone), strings.EqualFold(raw, "off"), raw == "-":
			outboundUA = ""
		default:
			// 头字段里不能有换行；非法值退回默认，而不是带着 CRLF 去发包。
			if strings.ContainsAny(raw, "\r\n") {
				outboundUA = outboundUADefault
			} else {
				outboundUA = raw
			}
		}
	})
	return outboundUA
}

// ApplyBrowserUA 在 headers 上设置统一 UA；值为空时**删除**该头，
// 保证"不发 UA"是真空着，不会被后续代码补上一个默认值。
func ApplyBrowserUA(set func(string, string), del func(string)) {
	if ua := BrowserUA(); ua != "" {
		set("User-Agent", ua)
		return
	}
	del("User-Agent")
}

// uaHeaderLine 返回可直接拼进原始报文的一行（含 CRLF）；不发 UA 时返回空串。
// 供那些手工拼 HTTP/1.1 报文的地方（credscan、dirfuzz 的取证副本）使用。
func uaHeaderLine() string {
	if ua := BrowserUA(); ua != "" {
		return "User-Agent: " + ua + "\r\n"
	}
	return ""
}
