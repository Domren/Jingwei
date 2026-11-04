package scanner

import (
	"encoding/hex"
	"fmt"
	"net"
	"strings"
)

const bannerCaptureNote = "采集方式: TCP 三次握手后被动读取服务端首发数据，扫描器未发送任何应用层请求字节"

// ProtocolBannerPacket renders the bytes a non-HTTP service actually sent to the
// scanner, as a hexdump plus (when printable) the verbatim text, with the
// commands needed to capture the same bytes again. This is what makes a
// service-exposure finding verifiable without wrapping it in HTTP; when nothing
// was read it says so instead of inventing a packet.
func ProtocolBannerPacket(proto, addr string, raw []byte) string {
	proto = strings.TrimSpace(proto)
	if proto == "" {
		proto = "tcp"
	}
	b := &strings.Builder{}
	fmt.Fprintf(b, "# 协议: %s (TCP)\n", strings.ToUpper(proto))
	fmt.Fprintf(b, "# 端点: %s\n", addr)
	fmt.Fprintf(b, "# %s\n", bannerCaptureNote)
	if len(raw) == 0 {
		b.WriteString("# 复现命令:\n")
		b.WriteString(bannerReproCommands(addr, 0))
		b.WriteString("\n\n未采集到服务端首发数据（该端口无 banner），只能确认端口可建立 TCP 连接。\n")
		return strings.TrimRight(b.String(), "\n")
	}
	fmt.Fprintf(b, "# 响应字节: %d\n", len(raw))
	b.WriteString("# 复现命令:\n")
	b.WriteString(bannerReproCommands(addr, len(raw)))
	b.WriteString(protocolPayloadSection("响应", raw))
	return strings.TrimRight(b.String(), "\n")
}

// bannerReproCommands gives two ways to grab the same bytes: nc for a quick
// look, python3 for a byte-exact dump where xxd is unavailable.
func bannerReproCommands(addr string, size int) string {
	host, port := addr, ""
	if h, p, err := net.SplitHostPort(addr); err == nil {
		host, port = h, p
	}
	quoted := host
	if strings.Contains(host, ":") {
		quoted = "[" + host + "]"
	}
	if port == "" {
		return fmt.Sprintf("#   nc -w 2 %s\n", quoted)
	}
	if size <= 0 {
		size = bannerMaxBytes
	}
	lines := size/16 + 2
	return fmt.Sprintf("#   nc -w 2 %s %s | xxd | head -%d\n"+
		"#   python3 -c 'import socket;print(repr(socket.create_connection((%q, %s), 3).recv(%d)))'\n",
		quoted, port, lines, host, port, size)
}

// ProtocolExchangePacket renders a request/response byte pair for a probe that
// spoke to the service (a credential attempt, a protocol query). It cannot reuse
// ProtocolBannerPacket's framing: that one says "未发送任何应用层请求字节", and a
// dictionary attempt did send bytes — recording the wrong capture method makes the
// evidence unreproducible, because the reader would connect and see a different
// response than the one on file.
func ProtocolExchangePacket(proto, addr string, req, resp []byte) string {
	proto = strings.TrimSpace(proto)
	if proto == "" {
		proto = "tcp"
	}
	b := &strings.Builder{}
	fmt.Fprintf(b, "# 协议: %s (TCP)\n", strings.ToUpper(proto))
	fmt.Fprintf(b, "# 端点: %s\n", addr)
	fmt.Fprintf(b, "# 采集方式: 主动发送下列请求字节后读取服务端响应，两侧字节都要一致才能复现\n")
	fmt.Fprintf(b, "# 请求字节: %d\n", len(req))
	fmt.Fprintf(b, "# 响应字节: %d\n", len(resp))
	b.WriteString("# 复现命令:\n")
	b.WriteString(exchangeReproCommand(addr, req))
	b.WriteString(protocolPayloadSection("请求", req))
	b.WriteString(protocolPayloadSection("响应", resp))
	return strings.TrimRight(b.String(), "\n")
}

// protocolPayloadSection prints verbatim text when it is printable, always hex,
// because an authentication response is usually binary and the text view alone
// would silently drop the bytes that carry the verdict.
func protocolPayloadSection(label string, raw []byte) string {
	if len(raw) == 0 {
		return fmt.Sprintf("\n# ---- 原始%s数据 ----\n（无字节）\n", label)
	}
	b := &strings.Builder{}
	if isPrintablePayload(raw) {
		fmt.Fprintf(b, "\n# ---- 原始%s数据（逐字节文本，行尾已标注）----\n", label)
		b.WriteString(escapeControlLines(string(raw)))
	}
	fmt.Fprintf(b, "\n# ---- 原始%s数据（hexdump，与抓包字节一致）----\n", label)
	b.WriteString(hexdump(raw))
	return b.String()
}

// exchangeReproCommand sends the exact request bytes and prints the reply. The
// request goes as hex so that \0, \r\n and non-UTF8 protocol fields survive a
// copy-paste; a quoted shell string would not.
func exchangeReproCommand(addr string, req []byte) string {
	host, port := addr, ""
	if h, p, err := net.SplitHostPort(addr); err == nil {
		host, port = h, p
	}
	if port == "" {
		return "#   （端点缺少端口号，无法给出可执行的复现命令）\n"
	}
	return fmt.Sprintf("#   python3 -c 'import socket;s=socket.create_connection((%q, %s), 5);"+
		"s.sendall(bytes.fromhex(%q));print(repr(s.recv(65535)))'\n",
		host, port, hex.EncodeToString(req))
}

func isPrintablePayload(raw []byte) bool {
	for _, c := range raw {
		if c >= 0x20 && c <= 0x7e {
			continue
		}
		if c != '\r' && c != '\n' && c != '\t' {
			return false
		}
	}
	return len(raw) > 0
}

// escapeControlLines keeps the payload verbatim but makes line endings visible,
// so copying the text back onto the wire is unambiguous.
func escapeControlLines(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case '\r':
			if i+1 < len(s) && s[i+1] == '\n' {
				b.WriteString("\\r\\n\n")
				i++
			} else {
				b.WriteString("\\r\n")
			}
		case '\n':
			b.WriteString("\\n\n")
		case '\t':
			b.WriteString("\\t")
		default:
			if c >= 0x20 && c <= 0x7e {
				b.WriteByte(c)
			} else {
				fmt.Fprintf(&b, "\\x%02x", c)
			}
		}
	}
	return b.String()
}

// hexdump is the classic offset / hex / ASCII layout produced by xxd -g 1.
func hexdump(raw []byte) string {
	b := &strings.Builder{}
	for off := 0; off < len(raw); off += 16 {
		end := off + 16
		if end > len(raw) {
			end = len(raw)
		}
		chunk := raw[off:end]
		fmt.Fprintf(b, "%08x  ", off)
		for i := 0; i < 16; i++ {
			if i == 8 {
				b.WriteByte(' ')
			}
			if i < len(chunk) {
				fmt.Fprintf(b, "%02x ", chunk[i])
			} else {
				b.WriteString("   ")
			}
		}
		b.WriteString(" |")
		for _, c := range chunk {
			if c >= 0x20 && c <= 0x7e {
				b.WriteByte(c)
			} else {
				b.WriteByte('.')
			}
		}
		if len(chunk) < 16 {
			b.WriteString(strings.Repeat(" ", 16-len(chunk)))
		}
		b.WriteString("|\n")
	}
	return b.String()
}
