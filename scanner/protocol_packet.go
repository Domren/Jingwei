package scanner

import (
	"encoding/hex"
	"fmt"
	"net"
	"strings"
)

const bannerCaptureNote = "采集方式: TCP 三次握手后被动读取服务端首发数据，扫描器未发送任何应用层请求字节"

const bannerCaptureNoteUDP = "采集方式: 向 UDP 端口发送数据报后读取服务端应答（数据报通道，无三次握手）"

// udpProtocols 列出走数据报通道的协议。证据渲染据此把标签写成 (UDP)、复现命令
// 换成 SOCK_DGRAM；照 TCP 版用 create_connection 复现 UDP 端口必然连不上。
// 用协议名路由而不是给 CredAttempt 加字段，是为了不动引擎那侧的结构与 JSON 形状。
var udpProtocols = map[string]bool{"snmp": true}

func isUDPProtocol(proto string) bool {
	return udpProtocols[strings.ToLower(strings.TrimSpace(proto))]
}

// ProtocolBannerPacket renders the bytes a non-HTTP service actually sent to the
// scanner, as a hexdump plus (when printable) the verbatim text, with the
// commands needed to capture the same bytes again. This is what makes a
// service-exposure finding verifiable without wrapping it in HTTP; when nothing
// was read it says so instead of inventing a packet.
func ProtocolBannerPacket(proto, addr string, raw []byte) string {
	return bannerPacket(proto, addr, raw, false)
}

// ProtocolBannerPacketUDP 是 UDP 版被动采集证据。SNMP 这类数据报协议也可用它，
// 复现命令用 SOCK_DGRAM，不能用 create_connection。
func ProtocolBannerPacketUDP(proto, addr string, raw []byte) string {
	return bannerPacket(proto, addr, raw, true)
}

func bannerPacket(proto, addr string, raw []byte, udp bool) string {
	proto = strings.TrimSpace(proto)
	if proto == "" {
		proto = "tcp"
	}
	if isUDPProtocol(proto) {
		udp = true
	}
	transport, note := "(TCP)", bannerCaptureNote
	if udp {
		transport, note = "(UDP)", bannerCaptureNoteUDP
	}
	b := &strings.Builder{}
	fmt.Fprintf(b, "# 协议: %s %s\n", strings.ToUpper(proto), transport)
	fmt.Fprintf(b, "# 端点: %s\n", addr)
	fmt.Fprintf(b, "# %s\n", note)
	if len(raw) == 0 {
		b.WriteString("# 复现命令:\n")
		b.WriteString(bannerReproCommands(addr, 0, udp))
		b.WriteString("\n\n未采集到服务端首发数据（该端口无 banner），只能确认端口可达。\n")
		return strings.TrimRight(b.String(), "\n")
	}
	fmt.Fprintf(b, "# 响应字节: %d\n", len(raw))
	b.WriteString("# 复现命令:\n")
	b.WriteString(bannerReproCommands(addr, len(raw), udp))
	b.WriteString(protocolPayloadSection("响应", raw))
	return strings.TrimRight(b.String(), "\n")
}

// bannerReproCommands gives two ways to grab the same bytes: nc for a quick
// look, python3 for a byte-exact dump where xxd is unavailable. UDP 版只能用
// SOCK_DGRAM + sendto——数据报通道没有三次握手可读。
func bannerReproCommands(addr string, size int, udp bool) string {
	host, port := addr, ""
	if h, p, err := net.SplitHostPort(addr); err == nil {
		host, port = h, p
	}
	quoted := host
	if strings.Contains(host, ":") {
		quoted = "[" + host + "]"
	}
	if udp {
		if port == "" {
			return fmt.Sprintf("#   python3 -c 'import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(3);s.sendto(b\"\",(%q, 0));print(repr(s.recv(65535)))'\n", host)
		}
		return fmt.Sprintf("#   python3 -c 'import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(3);s.sendto(b\"\",(%q, %s));print(repr(s.recv(65535)))'\n",
			host, port)
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
	return exchangePacket(proto, addr, req, resp, false)
}

// ProtocolExchangePacketUDP 是 UDP 版交互证据（SNMP 的 GetRequest/GetResponse）：
// 标签 (UDP)、复现命令用 SOCK_DGRAM + sendto + recv，绝不能用 create_connection。
func ProtocolExchangePacketUDP(proto, addr string, req, resp []byte) string {
	return exchangePacket(proto, addr, req, resp, true)
}

func exchangePacket(proto, addr string, req, resp []byte, udp bool) string {
	proto = strings.TrimSpace(proto)
	if proto == "" {
		proto = "tcp"
	}
	if isUDPProtocol(proto) {
		udp = true
	}
	transport, capture := "(TCP)", "主动发送下列请求字节后读取服务端响应，两侧字节都要一致才能复现"
	if udp {
		transport, capture = "(UDP)", "向 UDP 端口发送下列请求数据报后读取应答数据报，两侧字节都要一致才能复现"
	}
	b := &strings.Builder{}
	fmt.Fprintf(b, "# 协议: %s %s\n", strings.ToUpper(proto), transport)
	fmt.Fprintf(b, "# 端点: %s\n", addr)
	fmt.Fprintf(b, "# 采集方式: %s\n", capture)
	fmt.Fprintf(b, "# 请求字节: %d\n", len(req))
	fmt.Fprintf(b, "# 响应字节: %d\n", len(resp))
	b.WriteString("# 复现命令:\n")
	b.WriteString(exchangeReproCommand(addr, req, udp))
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
// copy-paste; a quoted shell string would not. UDP 版用 SOCK_DGRAM + sendto。
func exchangeReproCommand(addr string, req []byte, udp bool) string {
	host, port := addr, ""
	if h, p, err := net.SplitHostPort(addr); err == nil {
		host, port = h, p
	}
	if port == "" {
		return "#   （端点缺少端口号，无法给出可执行的复现命令）\n"
	}
	if udp {
		return fmt.Sprintf("#   python3 -c 'import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);"+
			"s.settimeout(3);s.sendto(bytes.fromhex(%q),(%q, %s));print(repr(s.recv(65535)))'\n",
			hex.EncodeToString(req), host, port)
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
