package scanner

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

// SNMP v1/v2c 的 community 弱口令探针。
//
// 为什么单独一条数据报通道：SNMP 走 UDP，community 错时服务端按 RFC 3412 静默丢弃
// 请求、一个字节都不回。这与「端口没人听」(ICMP 不可达 → ECONNREFUSED) 是两件不同的事，
// 更不能因为「试了没报错」就算命中。六态不新增第七态：静默丢弃用 CredInconclusive +
// 专属 Reason 表达，端口不通用 CredUnreachable（由 credFailFromErr 翻译）。
//
// BER 复用 credscan_ldap.go 里的最小组件（berTLV/berInt/berOctet/berReadTLV/concatBytes），
// 不引第三方 ASN.1 库：GetRequest/GetResponse 是固定形状，而且报告要的是 response 里的
// request-id / error-status，通用库会把它们藏进 error 里。
const (
	// snmpReplyWait 是等一个应答数据报的窗口。它只是「单次数据报等待节奏」，仍受
	// credWire.deadline（单次尝试硬上限）和传入 ctx 约束，不是适配器自定的全局超时。
	snmpReplyWait = 1500 * time.Millisecond
	// 请求 id 固定：每条 UDP socket 彼此隔离，固定 id 让证据字节可以逐字节复现。
	snmpRequestID = 0x4a575452 // "JWTR"
	snmpProbeID   = 0x4a574944 // "JWID"（Identify 用，和 Try 区分开）
)

type snmpCredAdapter struct{}

func (snmpCredAdapter) Protocol() string { return "snmp" }

// sysDescr 的 OID 1.3.6.1.2.1.1.1.0，编码后的内容字节（首两组合并成 0x2b）。
var snmpSysDescrOID = []byte{0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00}

// snmpGetRequest 组装 v2c (version=1) GetRequest：
//
//	SEQUENCE { INTEGER version, OCTET STRING community,
//	  [0] GetRequest { INTEGER request-id, INTEGER 0, INTEGER 0,
//	    SEQUENCE OF { SEQUENCE { OID sysDescr, NULL } } } }
func snmpGetRequest(community string, reqID int) []byte {
	varBind := berTLV(0x30, concatBytes(berTLV(0x06, snmpSysDescrOID), berTLV(0x05, nil)))
	varBinds := berTLV(0x30, varBind)
	pdu := berTLV(0xa0, concatBytes(berInt(reqID), berInt(0), berInt(0), varBinds))
	return berTLV(0x30, concatBytes(berInt(1), berOctet(community), pdu))
}

// snmpCommunity 取 community：字典里 SNMP 用纯口令条目（Password），也兼容只填用户名的写法。
func snmpCommunity(cred Credential) string {
	if cred.Password != "" {
		return cred.Password
	}
	return cred.Username
}

func berIntValue(v []byte) int {
	n := 0
	for _, b := range v {
		n = n<<8 | int(b)
	}
	return n
}

// snmpParseResponse 解析 GetResponse，只有 request-id 对得上才算「这次请求的应答」。
func snmpParseResponse(raw []byte, wantID int) (errStatus, version int, community string, ok bool) {
	tag, msg, _, ok := berReadTLV(raw, 0)
	if !ok || tag != 0x30 {
		return 0, 0, "", false
	}
	off := 0
	t, v, next, ok := berReadTLV(msg, off)
	if !ok || t != 0x02 {
		return 0, 0, "", false
	}
	version = berIntValue(v)
	off = next
	t, v, next, ok = berReadTLV(msg, off)
	if !ok || t != 0x04 {
		return 0, 0, "", false
	}
	community = string(v)
	off = next
	t, pdu, _, ok := berReadTLV(msg, off)
	if !ok || !snmpIsPDUTag(t) {
		return 0, 0, "", false
	}
	off = 0
	t, v, next, ok = berReadTLV(pdu, off)
	if !ok || t != 0x02 || berIntValue(v) != wantID {
		return 0, 0, "", false
	}
	off = next
	t, v, _, ok = berReadTLV(pdu, off)
	if !ok || t != 0x02 {
		return 0, 0, "", false
	}
	return berIntValue(v), version, community, true
}

// snmpIsPDUTag 认 SNMP 的上下文相关 PDU 标签 (GetRequest..Report, 0xa0..0xa8)。
func snmpIsPDUTag(t byte) bool { return t >= 0xa0 && t <= 0xa8 }

// snmpFrameShape 只看「是不是一个合法 SNMP 消息」：顶层 SEQUENCE + version INTEGER +
// community OCTET STRING + 合法 PDU。Identify 靠这个形态确认协议，不把 community 当结论。
func snmpFrameShape(raw []byte) (version int, pduTag byte, ok bool) {
	tag, msg, _, ok := berReadTLV(raw, 0)
	if !ok || tag != 0x30 {
		return 0, 0, false
	}
	t, v, next, ok := berReadTLV(msg, 0)
	if !ok || t != 0x02 {
		return 0, 0, false
	}
	version = berIntValue(v)
	t, _, next2, ok := berReadTLV(msg, next)
	if !ok || t != 0x04 {
		return 0, 0, false
	}
	t, _, _, ok = berReadTLV(msg, next2)
	if !ok || !snmpIsPDUTag(t) {
		return 0, 0, false
	}
	return version, t, true
}

func snmpVersionName(v int) string {
	switch v {
	case 0:
		return "v1"
	case 1:
		return "v2c"
	case 3:
		return "v3"
	default:
		return fmt.Sprintf("version=%d", v)
	}
}

func snmpIsTimeout(err error) bool {
	if errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// Identify 用协议公开的默认只读 community "public" 发一次 GetRequest。SNMP 没有 banner，
// 只能主动探测；"public" 是协议常量而不是被测凭据，这里只依据「应答是不是合法 SNMP 帧」
// 确认协议，不产生任何凭据结论。目标只允许非默认 community 时会静默丢弃 → 认不出，
// 由引擎整批落 inconclusive（不会把 HTTP 端口猜成 SNMP）。
func (a snmpCredAdapter) Identify(ctx context.Context, ep CredEndpoint) (bool, string, error) {
	w, err := credDialUDP(ctx, credAddr(ep))
	if err != nil {
		return false, "", err
	}
	defer w.close()
	if err := w.write(snmpGetRequest("public", snmpProbeID)); err != nil {
		return false, "", err
	}
	raw, err := w.readDatagramWithin(snmpReplyWait)
	if err != nil {
		if snmpIsTimeout(err) {
			// 静默丢弃既可能是不认 "public"，也可能是这个端口根本不是 SNMP：
			// 两种都不能确认协议，交给引擎以 inconclusive 收尾。
			return false, "", nil
		}
		return false, "", err
	}
	ver, pduTag, ok := snmpFrameShape(raw)
	if !ok {
		return false, credPreview(raw), nil
	}
	return true, fmt.Sprintf("SNMP %s 合法应答（PDU 0x%02x，%d 字节）", snmpVersionName(ver), pduTag, len(raw)), nil
}

func (a snmpCredAdapter) Try(ctx context.Context, ep CredEndpoint, cred Credential) (res CredAttempt, err error) {
	res = credNewAttempt(cred)
	community := snmpCommunity(cred)
	w, err := credDialUDP(ctx, credAddr(ep))
	if err != nil {
		return res.withErr(err)
	}
	defer w.close()
	defer func() { res.syncWire(w) }()

	req := snmpGetRequest(community, snmpRequestID)
	if err = w.write(req); err != nil {
		return res.withErr(err)
	}
	resp, err := w.readDatagramWithin(snmpReplyWait)
	if err != nil {
		if snmpIsTimeout(err) {
			// community 不被接受 → 静默丢弃。这既不是 deny（服务端没明确拒绝），
			// 也不是 unreachable（端口明明在应答别的人）。写清这一刀，报告才不会
			// 把「没测出来」写成「这组 community 不行」。
			res.Outcome = CredInconclusive
			res.Reason = "SNMP 目标无应答：community 不被接受时被静默丢弃（已与端口不通区分），无法据此判定该 community 可用"
			res.Banner = "未收到 SNMP 应答数据报"
			return res, nil
		}
		// ECONNREFUSED / 其它传输层错误交给统一翻译：端口不通 → unreachable。
		return res.withErr(err)
	}
	errStatus, ver, comm, ok := snmpParseResponse(resp, snmpRequestID)
	res.Banner = fmt.Sprintf("SNMP %s GetResponse（community=%q, error-status=%d）", snmpVersionName(ver), comm, errStatus)
	if !ok {
		res.Outcome = CredInconclusive
		res.Reason = "应答不是针对本次请求的合法 SNMP GetResponse（结构或 request-id 不符）"
		return res, nil
	}
	if errStatus != 0 {
		res.Outcome = CredInconclusive
		res.Reason = fmt.Sprintf("SNMP 应答 error-status=%d（非 noError），不能证明该 community 可用", errStatus)
		return res, nil
	}
	// 握手层「接受」信号：服务端用这个 community 处理了请求并回了 noError 的 GetResponse。
	// 只有这一步才算命中；前面任何一步没走完都是 inconclusive/unreachable。
	if strings.TrimSpace(community) == "" {
		res.Outcome = CredHit
		res.Reason = "目标接受空 community（未启用访问控制），空 community 即可读取"
		return res, nil
	}
	res.Outcome = CredHit
	return res, nil
}

func init() { RegisterCredAdapter(snmpCredAdapter{}) }
