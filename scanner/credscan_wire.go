package scanner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// 各协议适配器的公共管道。这里的每个决定都会改变报告里的一行，所以集中写、只写一遍：
// 拨号超时、单次尝试的墙钟上限、字节记录、以及「连不上」与「没测出来」的分界。

const (
	// credDialTimeout 只覆盖 TCP 建连：SYN 没人应答是端口的事，不是凭据的事。
	credDialTimeout = 5 * time.Second
	// credAttemptTimeout 是一组凭据一次的硬上限。不设上限时一个半开连接能把整个任务
	// 预算拖干，剩下的端点全部记成「预算耗尽」——那些行和这台机器没关系。
	credAttemptTimeout = 20 * time.Second
	// credReadIdle 是「读到一段没有新字节」的静默期：FTP/Telnet 的提示语没有固定长度，
	// 只能靠静默判断读完，读到超时为止会白等。
	credReadIdle = 900 * time.Millisecond
	// credFirstReadWait 是「一个字节都还没等到」时的耐心。FTP 服务器可能先做反向解析
	// 才发 banner（vsftpd 默认如此），拿静默期当首包耐心会把「慢」判成「不回话」，
	// 于是一条 deny 都没拿到，却写成不可判定。
	credFirstReadWait = 6 * time.Second
	// credReadMax 限制单次尝试记录的字节数；认证握手远小于这个值，超出即截断。
	credReadMax = 64 << 10
)

// credWire 是一条 TCP 连接加两侧的字节记录。记录写在 Read/Write 上而不是调用方手里，
// 因为漏记一次请求字节的证据就无法复现——而复现能力是这条结果进报告的资格。
type credWire struct {
	conn net.Conn
	// deadline 是本次尝试的绝对上限；每次设读超时都要与它取更早的那个，
	// 否则 SetReadDeadline 会把上限覆盖掉，单次尝试就不封顶了。
	deadline time.Time
	req      []byte
	resp     []byte
	// idle 覆盖静默期判定，慢协议（Telnet 的 IAC 协商）可以适当放宽。
	idle time.Duration
	// udp 标记这条连接走数据报通道（SNMP）：读取语义是「一个完整数据报」而非
	// TCP 字节流，超时还要单独区分「静默丢弃」与「端口不通」。
	udp bool
}

// credDial 建连接并把上层的取消与单次上限叠成一个 deadline。
func credDial(ctx context.Context, addr string) (*credWire, error) {
	d := net.Dialer{Timeout: credDialTimeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	w := &credWire{conn: conn, idle: credReadIdle, deadline: time.Now().Add(credAttemptTimeout)}
	if dl, ok := ctx.Deadline(); ok && dl.Before(w.deadline) {
		w.deadline = dl
	}
	_ = conn.SetDeadline(w.deadline)
	return w, nil
}

// credDialUDP 为 SNMP 这类数据报协议建一条「已连接」的 UDP 通道，复用 credWire
// 的字节记录与单次尝试上限。DialContext("udp") 不握手，Timeout 只防止 ctx 没带
// deadline 时拨号卡住；真正等应答的截止仍统一由 w.deadline 封顶。
func credDialUDP(ctx context.Context, addr string) (*credWire, error) {
	d := net.Dialer{Timeout: credDialTimeout}
	conn, err := d.DialContext(ctx, "udp", addr)
	if err != nil {
		return nil, err
	}
	w := &credWire{conn: conn, idle: credReadIdle, udp: true,
		deadline: time.Now().Add(credAttemptTimeout)}
	if dl, ok := ctx.Deadline(); ok && dl.Before(w.deadline) {
		w.deadline = dl
	}
	_ = conn.SetDeadline(w.deadline)
	return w, nil
}

// credAddr 把端点拼成 dial 用的 host:port。端口为 0 是编程错误而不是「用默认端口」：
// 拿 0 去拨号会连到一个随机端口上，然后把结果记在这台机器的行上。
func credAddr(ep CredEndpoint) string {
	return net.JoinHostPort(ep.Host, strconv.Itoa(ep.Port))
}

func (w *credWire) close() { _ = w.conn.Close() }

// readLine 读一行（含结尾的 \n）。SSH 的版本标识是变长文本，长度字段帮不上，只能按行读；
// 上限用来防一个一直吐字节的对端把内存吃掉。读到的字节同样进证据——SSH 的认证结论
// 只有这一段是明文，漏记它就等于「拒绝」这一行没有任何可复现的东西。
func (w *credWire) readLine(max int) ([]byte, error) {
	return w.readLineWithin(max, credFirstReadWait)
}

// readLineWithin 与 readLine 相同，但可以指定首字节的耐心。邮件服务的 SASL
// 认证往往要经过一个外部 auth 进程，第一字节可能比 banner 慢得多——拿 banner 的
// 6 秒去等 AUTH 应答，会把「慢」判成「不回话」。
func (w *credWire) readLineWithin(max int, wait time.Duration) ([]byte, error) {
	if max <= 0 {
		max = 512
	}
	if wait <= 0 {
		wait = credFirstReadWait
	}
	out := make([]byte, 0, 64)
	one := make([]byte, 1)
	defer func() { w.recordRead(out) }()
	for len(out) < max {
		_ = w.conn.SetReadDeadline(w.readDeadline(wait))
		n, err := w.conn.Read(one)
		if n > 0 {
			out = append(out, one[0])
			if one[0] == 10 {
				return out, nil
			}
			continue
		}
		if err == nil {
			err = io.EOF
		}
		if len(out) > 0 {
			return out, err
		}
		return nil, err
	}
	return out, nil
}

// credPeek 把已经读走的字节接回流的开头。SSH 的适配器要先看版本行才能给出可信的
// banner，而 x/crypto 自己也要读这行——不接回去，它就永远等不到。
type credPeek struct {
	net.Conn
	buf []byte
}

func (c *credPeek) Read(b []byte) (int, error) {
	if len(c.buf) > 0 {
		n := copy(b, c.buf)
		c.buf = c.buf[n:]
		return n, nil
	}
	return c.Conn.Read(b)
}

func bytesIndexByte(b []byte, c byte) int {
	for i := 0; i < len(b); i++ {
		if b[i] == c {
			return i
		}
	}
	return -1
}

func (w *credWire) recordWrite(b []byte) {
	if len(b) == 0 || len(w.req) >= credReadMax {
		return
	}
	w.req = append(w.req, b...)
}

func (w *credWire) write(b []byte) error {
	if len(w.req) < credReadMax {
		w.req = append(w.req, b...)
	}
	_, err := w.conn.Write(b)
	return err
}

// writeLine 发一行行式协议命令（FTP/Telnet 这类）。字符串由调用方拼好，这里不再做
// 格式化——口令里的 % 被当成格式动词会变成另一条命令。
// 含 CR/LF 的参数一律拒发：那会把一条命令变成两条，而字典里出现换行说明词典本身有问题，
// 不是目标的配置有问题。
func (w *credWire) writeLine(line string) error {
	if strings.ContainsAny(line, "\r\n") {
		return fmt.Errorf("协议参数含换行，已拒绝发送")
	}
	return w.write([]byte(line + "\r\n"))
}

// read 读一批字节，读到静默期结束或 deadline 到。返回的 error 只在「一个字节都没读到」
// 时非空——读到了东西又超时是正常收尾，不能当失败，否则每个 banner 协议都会被判 unreachable。
func (w *credWire) read() ([]byte, error) {
	buf := make([]byte, 4096)
	var got []byte
	wait := credFirstReadWait
	for {
		_ = w.conn.SetReadDeadline(w.readDeadline(wait))
		wait = w.idle
		if wait <= 0 {
			wait = credReadIdle
		}
		n, err := w.conn.Read(buf)
		if n > 0 {
			got = append(got, buf[:n]...)
			if len(got) >= credReadMax {
				w.recordRead(got)
				return got, nil
			}
			continue
		}
		if len(got) > 0 {
			w.recordRead(got)
			return got, nil
		}
		if err == nil {
			err = io.EOF
		}
		w.recordRead(nil)
		return nil, err
	}
}

// readDatagram 读一个 UDP 数据报。UDP 不是字节流：一次 Read 就是一个完整报文，
// 不能套 TCP 的 read()/readLine()（它们靠静默期收尾，会把「没应答」误判成「读完了」）。
// 返回的 error 由调用方分两类处理：ECONNREFUSED 是端口没人听（ICMP 不可达），
// 超时是「有人听但不回话」——SNMP community 错正是被静默丢弃，两者必须分开。
func (w *credWire) readDatagram() ([]byte, error) {
	return w.readDatagramWithin(credFirstReadWait)
}

// readDatagramWithin 允许协议给单次数据报等待定一个节奏（SNMP 用较短的应答窗口），
// 但仍受 w.deadline 这个单次尝试硬上限约束，不构成「适配器自定全局超时」。
func (w *credWire) readDatagramWithin(wait time.Duration) ([]byte, error) {
	buf := make([]byte, credReadMax)
	_ = w.conn.SetReadDeadline(w.readDeadline(wait))
	n, err := w.conn.Read(buf)
	if n > 0 {
		w.recordRead(buf[:n])
		return buf[:n], nil
	}
	if err == nil {
		err = io.EOF
	}
	return nil, err
}

// readDeadline 把「等多久」换算成绝对时间，并且永远不越过本次尝试的上限。
func (w *credWire) readDeadline(d time.Duration) time.Time {
	at := time.Now().Add(d)
	if !w.deadline.IsZero() && w.deadline.Before(at) {
		return w.deadline
	}
	return at
}

// readN 读满 n 字节（二进制协议都带长度头，读多了会把下一条回复吃掉）。
// 记录是增量的：一次读到的字节只在自己的范围内进证据，超出 n 的部分不属于这条报文。
func (w *credWire) readN(n int) ([]byte, error) {
	if n <= 0 {
		return nil, nil
	}
	out := make([]byte, 0, n)
	for len(out) < n {
		_ = w.conn.SetReadDeadline(w.readDeadline(credAttemptTimeout))
		tmp := make([]byte, n-len(out))
		read, err := w.conn.Read(tmp)
		if read > 0 {
			out = append(out, tmp[:read]...)
			w.recordRead(tmp[:read])
		}
		if err != nil {
			if read == 0 && err == io.EOF {
				return out, io.ErrUnexpectedEOF
			}
			return out, err
		}
	}
	return out, nil
}

func (w *credWire) recordRead(b []byte) {
	if len(b) == 0 || len(w.resp) >= credReadMax {
		return
	}
	w.resp = append(w.resp, b...)
}

// text 是响应里的可读摘要，用于 banner 字段（证据字节另走 RawReq/RawResp）。
func (w *credWire) text() string {
	return credPreview(w.resp)
}

func credPreview(raw []byte) string {
	s := strings.TrimSpace(string(raw))
	if len(s) > 300 {
		s = s[:300] + "…"
	}
	return s
}

// credFailFromErr 把传输层错误分成「连不上」与「说不清」。分错这一刀，报告就会把
// 「没测出来」写成「这组口令不行」。
//
// unreachable：端口没人听、路由不通、连接被 RST——这是端口事实，与凭据无关。
// inconclusive：超时、握手到一半断了、TLS 没起来——无法对凭据下结论。
func credFailFromErr(err error) (CredOutcome, string) {
	if err == nil {
		return "", ""
	}
	switch {
	case errors.Is(err, context.Canceled):
		return CredInconclusive, "任务已取消"
	case errors.Is(err, os.ErrDeadlineExceeded), errors.Is(err, context.DeadlineExceeded):
		return CredInconclusive, "握手在单次尝试上限内没走完，未得出判定"
	case errors.Is(err, syscall.ECONNREFUSED):
		return CredUnreachable, "端口拒绝连接（没有服务在监听）"
	case errors.Is(err, syscall.EHOSTUNREACH), errors.Is(err, syscall.ENETUNREACH),
		errors.Is(err, syscall.ECONNRESET), errors.Is(err, syscall.EPIPE):
		return CredUnreachable, "传输层不通：" + err.Error()
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return CredInconclusive, "对端在握手完成前关闭连接"
	case errors.Is(err, errUnsupportedAuth):
		return CredUnsupported, err.Error()
	default:
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) {
			return CredUnreachable, "地址解析失败：" + dnsErr.Error()
		}
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			return CredInconclusive, "握手超时，未得出判定"
		}
		return CredUnreachable, err.Error()
	}
}

// errUnsupportedAuth 让适配器把「这个服务用的认证方式我不实现」说成 unsupported，
// 而不是含糊的失败——同一协议的不同认证机制区别很大（MySQL 的 sha256 与 native、
// Postgres 的 md5 与 SCRAM），不能共用一句「认证失败」。
var errUnsupportedAuth = errors.New("该服务要求的认证机制本平台不实现")

// credNewAttempt 只填凭据：Host/Port/Protocol 由引擎按端点覆写，适配器不自己拼，
// 免得两处形状不一致时结果行里出现第三个版本的地址。
func credNewAttempt(cred Credential) CredAttempt { return CredAttempt{Cred: cred} }

// withErr 把传输层错误翻成态与说明，同时把 error 原样交回引擎（引擎还会把错误串并进 Reason）。
func (a CredAttempt) withErr(err error) (CredAttempt, error) {
	if a.Outcome == "" {
		a.Outcome, a.Reason = credFailFromErr(err)
	}
	return a, err
}

// syncWire 取两侧字节快照。适配器把它放进 defer：中途失败时，已经发出去的那半截同样
// 是要写进报告的事实。
func (a *CredAttempt) syncWire(w *credWire) {
	if len(a.RawReq) == 0 && len(w.req) > 0 {
		a.RawReq = w.req
	}
	if len(a.RawResp) == 0 && len(w.resp) > 0 {
		a.RawResp = w.resp
	}
	if a.Banner == "" {
		a.Banner = w.text()
	}
}

// credSanitizeLine 去掉协议参数里的换行与控制字符，返回清洗后的值与是否被改过。
// 被改过就不能当成凭据结论：送去的目标收到的是另一串字节。
func credSanitizeLine(s string) (string, bool) {
	clean := strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == 0 {
			return -1
		}
		return r
	}, s)
	return clean, clean != s
}

// isCredUnsupported 认适配器抛出的「这个机制我不实现」。判错方向会让报告把
// 「我们不会算」写成「这组口令不行」——后者等于宣称已经排除过它。
func isCredUnsupported(err error) bool {
	return err != nil && errors.Is(err, errUnsupportedAuth)
}
