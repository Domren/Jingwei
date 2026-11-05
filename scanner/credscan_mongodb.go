package scanner

import (
	"context"
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
)

// MongoDB 认证探针（OP_MSG + SCRAM）。
//
// 支持 SCRAM-SHA-256（4.0 起的默认）与 SCRAM-SHA-1。X509、LDAP、Kerberos、OIDC 报
// unsupported。两个机制的 SASL 数学同一组（HMAC-SHA-1 / HMAC-SHA-256），差别只在
// SHA-1 那一支的口令要先按 MongoDB 的规则预哈希——这一点是从 mongod 里存的 credential
// 反推出来的，不是照文档猜的。
//
// 不引官方驱动：镜像里为了一个 saslStart 装 5 MB 依赖不划算，而认证握手只需要
// 编几个字段、读几个字段。代价是自己写 BSON——所以未知类型一律报错而不是跳过：
// 跳过会把「ok=0」读成「没有 ok」，于是失败被写成不可判定。
type mongoCredAdapter struct{}

func (mongoCredAdapter) Protocol() string { return "mongodb" }

const (
	mongoOpMsg       = 2013
	mongoDefaultAuth = "admin"
	// mongoMinWireVersion 是本实现依赖 OP_MSG 的下限（4.0）。更老的服务器要 OP_QUERY，
	// 那类目标会得到一条明确的 unsupported，而不是一个假的 deny。
	mongoMinWireVersion = 13
)

var mongoReqID atomic.Uint32

func (a mongoCredAdapter) Identify(ctx context.Context, ep CredEndpoint) (bool, string, error) {
	w, err := credDial(ctx, credAddr(ep))
	if err != nil {
		return false, "", err
	}
	defer w.close()
	hello, err := mongoCommand(w, mongoDefaultAuth, "hello", int32(1))
	if err != nil {
		return false, "", err
	}
	_, hasWire := hello.Int("maxWireVersion")
	_, hasOk := hello.Get("ok")
	if !hasWire || !hasOk {
		return false, credPreview(w.resp), nil
	}
	v, _ := hello.Int("maxWireVersion")
	return true, fmt.Sprintf("MongoDB %s · maxWireVersion %d", hello.Str("version"), v), nil
}

func (a mongoCredAdapter) Try(ctx context.Context, ep CredEndpoint, cred Credential) (res CredAttempt, err error) {
	res = credNewAttempt(cred)
	w, err := credDial(ctx, credAddr(ep))
	if err != nil {
		return res.withErr(err)
	}
	defer w.close()
	defer func() { res.syncWire(w) }()

	authDB := CredParam(ep, CredParamAuthSource, mongoDefaultAuth)
	hello, err := mongoCommand(w, authDB, "hello", int32(1),
		"saslSupportedMechs", authDB+"."+cred.Username)
	if err != nil {
		return res.withErr(err)
	}
	v, _ := hello.Int("maxWireVersion")
	res.Banner = fmt.Sprintf("MongoDB %s · maxWireVersion %d", hello.Str("version"), v)
	if v < mongoMinWireVersion {
		res.Outcome = CredUnsupported
		res.Reason = fmt.Sprintf("目标 wire version %d 只支持 OP_QUERY（4.0 以前），本平台不实现", v)
		return res, nil
	}
	mechs := mongoSupportedMechs(hello)
	// 显式点名机制时不能用「服务端列表里的第一个」顶替：SHA-1 与 SHA-256 的哈希组
	// 不是一回事（MongoDB 的 SHA-1 实际用 MD5），只验一个就宣称都验过是说谎。
	if want := CredParam(ep, CredParamMechanism, ""); want != "" && !stringInSlice(want, mechs) {
		res.Outcome = CredUnsupported
		res.Reason = fmt.Sprintf("目标不提供 %s（可用：%s）", want, strings.Join(mechs, "/"))
		return res, nil
	}
	hs, mech, err := pickMongoScram(mechs, CredParam(ep, CredParamMechanism, ""))
	if err != nil {
		res.Outcome = CredUnsupported
		res.Reason = err.Error()
		return res, nil
	}

	sasl, err := newScramClient(hs, mongoScramKey(hs, cred))
	if err != nil {
		return res.withErr(err)
	}
	// 与 PG 的一个真实差异：MongoDB 的用户名要写进 SASL 的 client-first-bare。
	// 这里只改 bare；gs2 头（"n,,"）在发出去时再拼——auth-message 按 RFC 5802
	// 只用 bare 参与计算，把头算进去服务端就会回 Authentication failed，
	// 而口令已经被我们发出去了（真机验证抓的就是这一条）。
	sasl.clientFirst = "n=" + mongoEscapedUser(cred.Username) + ",r=" + sasl.clientNonce
	convo, err := mongoCommand(w, authDB, "saslStart", int32(1), "mechanism", mech,
		"payload", []byte("n,,"+sasl.clientFirst),
		"options", map[string]any{"skipEmptyExchange": true})
	if handled := mongoCheckReply(&res, convo); handled {
		return res, nil
	}
	cid, _ := convo.Int("conversationId")
	serverFirst := string(convo.Bin("payload"))
	clientFinal, err := sasl.HandleServerFirst(serverFirst)
	if err != nil {
		res.Outcome = CredInconclusive
		res.Reason = "SCRAM 服务端第一条消息不可用：" + err.Error()
		return res, nil
	}
	final, err := mongoCommand(w, authDB, "saslContinue", int32(1),
		"conversationId", mongoIntForBSON(cid), "payload", []byte(clientFinal))
	if handled := mongoCheckReply(&res, final); handled {
		return res, nil
	}
	serverFinal := string(final.Bin("payload"))
	if serverFinal != "" && !sasl.VerifyServerFinal(serverFinal) {
		// 口令已经发出去了但签名算不回来：不能报命中，也不能报拒绝。
		res.Outcome = CredInconclusive
		res.Reason = "SCRAM 服务端签名校验不过：对端身份无法确认，不据此下结论"
		return res, nil
	}
	if final.Bool("done") {
		res.Outcome = CredHit
		return res, nil
	}
	// 没做完就再走一轮空 payload（服务端没接受 skipEmptyExchange 时的标准收尾）。
	tail, err := mongoCommand(w, authDB, "saslContinue", int32(1),
		"conversationId", mongoIntForBSON(cid), "payload", []byte(nil))
	if err != nil {
		return res.withErr(err)
	}
	if handled := mongoCheckReply(&res, tail); handled {
		return res, nil
	}
	if tail.Bool("done") {
		res.Outcome = CredHit
		return res, nil
	}
	res.Outcome = CredInconclusive
	res.Reason = "SASL 会话没在三次交换内结束：" + tail.Str("errmsg")
	return res, nil
}

// mongoCheckReply 处理 ok=0 的回复。返回 true 表示已经写好结论。
func mongoCheckReply(res *CredAttempt, doc *bsonDoc) bool {
	if n, ok := doc.Int("ok"); ok && n == 1 {
		return false
	}
	code, _ := doc.Int("code")
	msg := doc.Str("errmsg")
	if msg == "" {
		msg = doc.Str("codeName")
	}
	res.Banner = msg
	lower := strings.ToLower(msg)
	switch {
	case code == 18 || strings.Contains(lower, "authentication failed") ||
		strings.Contains(lower, "could not find user") || strings.Contains(lower, "invalid credentials"):
		res.Outcome = CredDeny
	case credLockedText(lower):
		res.Outcome = CredLocked
		res.Reason = "服务端提示账号锁定或用户被禁用，已停手"
	case code == 13:
		// 认证过了但对这个库没有权限——口令本身的有效性服务端没表态，不能写成结论。
		res.Outcome = CredInconclusive
		res.Reason = "认证层通过、授权层被拒，凭据结论没走到：" + msg
	case code == 57 || strings.Contains(lower, "requires authentication"):
		res.Outcome = CredInconclusive
		res.Reason = "命令被认证要求挡住，握手没能开始：" + msg
	default:
		res.Outcome = CredInconclusive
		res.Reason = "服务端错误 " + strconv.FormatInt(code, 10) + "：" + msg
	}
	return true
}

// mongoSupportedMechs 从 hello 的 saslSupportedMechs 数组里取机制名。
// BSON 数组就是键为 "0"、"1"… 的嵌套文档。
func mongoSupportedMechs(hello *bsonDoc) []string {
	v, ok := hello.Get("saslSupportedMechs")
	if !ok {
		return nil
	}
	sub, ok := v.(*bsonDoc)
	if !ok {
		return nil
	}
	var out []string
	for i := 0; ; i++ {
		s, ok := sub.Get(strconv.Itoa(i))
		if !ok {
			break
		}
		if str, ok := s.(string); ok {
			out = append(out, str)
		}
	}
	return out
}

func pickMongoScram(mechs []string, want string) (scramHashes, string, error) {
	if want != "" {
		mechs = append([]string{want}, mechs...)
	}
	for _, m := range mechs {
		switch m {
		case "SCRAM-SHA-256":
			return ScramSHA256, m, nil
		case "SCRAM-SHA-1":
			// 机制名叫 SHA-1，哈希组也确实是 SHA-1；不同的是口令要先按 mongoScramKey 预哈希。
			return ScramSHA1, m, nil
		}
	}
	if len(mechs) == 0 {
		// 老服务器不返回这个字段时按 4.0 的默认走 SCRAM-SHA-256。
		return ScramSHA256, "SCRAM-SHA-256", nil
	}
	return ScramSHA256, "", fmt.Errorf("%w：服务端只支持 %s", errUnsupportedAuth, strings.Join(mechs, "/"))
}

// mongoEscapedUser 按 RFC 5802 把用户名里的 ',' 与 '=' 转义。
// 不做完整 SASLprep：那是另一个问题域，而且悄悄改写用户名比拒绝更糟。
func stringInSlice(s string, list []string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func mongoEscapedUser(user string) string {
	return strings.NewReplacer("=", "=3D", ",", "=2C").Replace(user)
}

// mongoCommand 发一条 OP_MSG 并读回一个文档。
//
// 参数按顺序给（不是 map）：BSON 文档里**第一个字段就是命令名**，而 $db 必须排在最后。
// 用 map 传参时真机直接回「no such command: 'mechanism'」——随机遍历把机制名顶到了第一位。
// 顺序固定还有个好处：同一条命令每次发出的字节一致，证据才可复现。
func mongoCommand(w *credWire, db string, kv ...any) (*bsonDoc, error) {
	if len(kv)%2 != 0 {
		return nil, errors.New("mongo 命令参数必须成对")
	}
	body := make([]any, 0, len(kv)+2)
	for i := 0; i < len(kv); i += 2 {
		key, ok := kv[i].(string)
		if !ok {
			return nil, fmt.Errorf("mongo 命令键必须是字符串，收到 %T", kv[i])
		}
		if key == "$db" {
			return nil, errors.New("$db 由 mongoCommand 统一放在最后，参数里不要再给")
		}
		body = append(body, key, mongoValue(kv[i+1]))
	}
	body = append(body, "$db", db)
	doc, err := bsonBuild(body...)
	if err != nil {
		return nil, err
	}
	id := mongoReqID.Add(1)
	msg := make([]byte, 0, len(doc)+21)
	msg = binary.LittleEndian.AppendUint32(msg, uint32(16+4+1+len(doc)))
	msg = binary.LittleEndian.AppendUint32(msg, id)
	msg = binary.LittleEndian.AppendUint32(msg, 0)
	msg = binary.LittleEndian.AppendUint32(msg, mongoOpMsg)
	msg = binary.LittleEndian.AppendUint32(msg, 0) // flagBits
	msg = append(msg, 0x00)                        // section kind 0 = 正文文档
	msg = append(msg, doc...)
	if err = w.write(msg); err != nil {
		return nil, err
	}
	return mongoReadReply(w, id)
}

// mongoScramKey 是喂给 SCRAM 派生的「口令」输入。
//
// SCRAM-SHA-1 那一支要先算 hex(md5(user + ":mongo:" + password))。这一条是拿 mongod
// 里存的 credential（salt/iterationCount/storedKey）反推的：hex 与裸摘要、完整 salt 与
// 后 10 字节、MD5 组与 SHA-1 组，只有「hex + 完整 salt + SHA-1」能让 storedKey 对上。
// 少了这步，服务端只回一句 Authentication failed，与「口令真的不对」长得一模一样——
// 所以这种事只能量，不能猜。SCRAM-SHA-256 用原口令。
func mongoScramKey(hs scramHashes, cred Credential) string {
	if hs.mech != "SCRAM-SHA-1" {
		return cred.Password
	}
	sum := md5.Sum([]byte(cred.Username + ":mongo:" + cred.Password))
	return hex.EncodeToString(sum[:])
}

func mongoValue(v any) any {
	if m, ok := v.(map[string]any); ok {
		inner := make([]any, 0, len(m)*2)
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			inner = append(inner, k, m[k])
		}
		raw, err := bsonBuild(inner...)
		if err != nil {
			return nil
		}
		sub, err := bsonParse(raw)
		if err != nil {
			return nil
		}
		return sub
	}
	return v
}

// mongoReadReply 读一个 OP_MSG 响应并取出正文文档。
func mongoReadReply(w *credWire, expectID uint32) (*bsonDoc, error) {
	hdr, err := w.readN(16)
	if err != nil && len(hdr) < 16 {
		return nil, err
	}
	size := int(binary.LittleEndian.Uint32(hdr[0:4]))
	if size < 16 || size > credReadMax {
		return nil, fmt.Errorf("MongoDB 报文长度不可信: %d", size)
	}
	rest, err := w.readN(size - 16)
	if err != nil {
		return nil, err
	}
	gotID := binary.LittleEndian.Uint32(hdr[4:8])
	responseTo := binary.LittleEndian.Uint32(hdr[8:12])
	opCode := binary.LittleEndian.Uint32(hdr[12:16])
	if responseTo != expectID {
		return nil, fmt.Errorf("响应序号对不上：期望 %d，收到 requestID=%d responseTo=%d", expectID, gotID, responseTo)
	}
	if opCode == 2001 { // OP_REPLY（老服务器）：正文在第二个文档里，本平台不实现
		return nil, fmt.Errorf("%w：目标用 OP_QUERY/OP_REPLY 应答（MongoDB 4.0 以前）", errUnsupportedAuth)
	}
	if opCode != mongoOpMsg {
		return nil, fmt.Errorf("不是 OP_MSG 应答（opcode %d）", opCode)
	}
	if len(rest) < 5 {
		return nil, fmt.Errorf("OP_MSG 正文过短: %d", len(rest))
	}
	// flagBits(4) + section kind(1) + 文档
	return bsonParse(rest[5:])
}

func mongoIntForBSON(v int64) any {
	if v >= 0 && v <= 0x7fffffff {
		return int32(v)
	}
	return v
}

func init() { RegisterCredAdapter(mongoCredAdapter{}) }
