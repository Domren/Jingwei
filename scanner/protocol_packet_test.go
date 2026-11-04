package scanner

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestProtocolBannerPacketBinaryPayload(t *testing.T) {
	raw := append([]byte{0x68, 0x00, 0x00, 0x00, 0xff, 0x69}, []byte("Host '192.0.2.13' is blocked")...)
	got := ProtocolBannerPacket("mysql", "192.0.2.4:3306", raw)

	for _, want := range []string{
		"# 协议: MYSQL (TCP)",
		"# 端点: 192.0.2.4:3306",
		"# 响应字节: 34",
		"#   nc -w 2 192.0.2.4 3306 | xxd | head -4",
		"socket.create_connection((\"192.0.2.4\", 3306), 3)",
		"00000000  68 00 00 00 ff 69 48 6f  73 74 20 27 31 39 32 2e  |h....iHost '192.|",
		"00000020  65 64                                             |ed              |",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("packet missing %q\n----\n%s", want, got)
		}
	}
	if strings.Contains(got, "逐字节文本") {
		t.Errorf("binary payload must not claim a text view:\n%s", got)
	}
	if !utf8.ValidString(got) {
		t.Errorf("packet is not valid UTF-8 and would break the findings write")
	}
}

func TestProtocolBannerPacketPrintablePayload(t *testing.T) {
	got := ProtocolBannerPacket("ssh", "192.0.2.4:22", []byte("SSH-2.0-OpenSSH_9.6\r\n"))
	for _, want := range []string{
		"# ---- 原始响应数据（逐字节文本，行尾已标注）----",
		`SSH-2.0-OpenSSH_9.6\r\n`,
		"00000000  53 53 48 2d 32 2e 30 2d  4f 70 65 6e 53 53 48 5f  |SSH-2.0-OpenSSH_|",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("packet missing %q\n----\n%s", want, got)
		}
	}
}

func TestProtocolBannerPacketWithoutBanner(t *testing.T) {
	got := ProtocolBannerPacket("redis", "192.0.2.1:6379", nil)
	if !strings.Contains(got, "未采集到服务端首发数据") {
		t.Errorf("missing honest no-banner note:\n%s", got)
	}
	if !strings.Contains(got, "nc -w 2 192.0.2.1 6379") {
		t.Errorf("no repro command without banner:\n%s", got)
	}
	if strings.Contains(got, "hexdump") {
		t.Errorf("must not render an empty hexdump:\n%s", got)
	}
}

func TestProtocolBannerPacketIPv6(t *testing.T) {
	got := ProtocolBannerPacket("redis", "[fd00::1]:6379", []byte("-ERR\r\n"))
	if !strings.Contains(got, "nc -w 2 [fd00::1] 6379") {
		t.Errorf("ipv6 address not bracketed:\n%s", got)
	}
	if !strings.Contains(got, `("fd00::1", 6379)`) {
		t.Errorf("python repro lost the ipv6 host:\n%s", got)
	}
}

func TestHexdumpEmpty(t *testing.T) {
	if got := hexdump(nil); got != "" {
		t.Errorf("hexdump(nil)=%q, want empty", got)
	}
}

// 认证尝试发过请求字节，就不能套 banner 格式（那句「未发送任何应用层请求字节」会变成假记录），
// 而且复现命令要能真的把同一串字节再发一遍——请求里的 \r\n 与非 ASCII 字节必须存活。
func TestProtocolExchangePacketSendsRequestBytes(t *testing.T) {
	req := []byte("AUTH p\x00ss\r\n")
	got := ProtocolExchangePacket("redis", "192.0.2.7:6379", req, []byte("-WRONGPASS\r\n"))
	for _, want := range []string{"# 协议: REDIS", "192.0.2.7:6379", "原始请求数据", "原始响应数据", "-WRONGPASS"} {
		if !strings.Contains(got, want) {
			t.Errorf("exchange packet lost %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, bannerCaptureNote) {
		t.Errorf("主动请求不能记成被动采集:\n%s", got)
	}
	// 复现命令里的 hex 必须与请求字节逐字节一致，否则照抄命令得到的是另一个请求。
	h := hex.EncodeToString(req)
	if !strings.Contains(got, `bytes.fromhex("`+h+`")`) {
		t.Errorf("repro command lost the exact request bytes:\n%s", got)
	}
	back, err := hex.DecodeString(h)
	if err != nil || !bytes.Equal(back, req) {
		t.Errorf("hex round trip broke the request: %v %q", err, back)
	}
	if !strings.Contains(ProtocolExchangePacket("redis", "[fd00::1]:6379", req, nil), `("fd00::1", 6379)`) {
		t.Errorf("ipv6 host lost:\n%s", ProtocolExchangePacket("redis", "[fd00::1]:6379", req, nil))
	}
}
