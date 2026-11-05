package scanner

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
)

// 最小 BSON 读写（只覆盖认证握手用到的类型）。0x09（UTC 时间）与 0x11（时间戳）都是
// 8 字节整数：hello 的回复里带 localTime，不认它连「这是 MongoDB」都确认不了。
//
// 为什么不引驱动：认证只需要发几个字段、读几个字段，而引一个官方驱动会把一个 5 MB 的
// 依赖装进镜像，只为一次 saslStart。代价是这里必须自己把类型读对——所以未知类型一律
// 报错而不是跳过：跳过会让「ok=0」这种关键事实被读成不存在，把失败写成不可判定。
type bsonDoc struct {
	fields []bsonField
}

type bsonField struct {
	key string
	val any
	typ byte
	bin []byte // 二进制字段的原始字节
}

const (
	bsonDouble    = 0x01
	bsonString    = 0x02
	bsonEmbedded  = 0x03
	bsonArray     = 0x04
	bsonBinary    = 0x05
	bsonUndefined = 0x06
	bsonObjectID  = 0x07
	bsonBool      = 0x08
	bsonNull      = 0x0A
	bsonInt32     = 0x10
	bsonInt64     = 0x12
	bsonUTCDate   = 0x09
	bsonTimestamp = 0x11
	bsonRegex     = 0x0B
)

// bsonBuild 按键的插入顺序编码。文档值支持 int32/int64/int/bool/string/[]byte/*bsonDoc。
func bsonBuild(kv ...any) ([]byte, error) {
	if len(kv)%2 != 0 {
		return nil, errors.New("BSON 构造需要成对的键值")
	}
	var body []byte
	for i := 0; i < len(kv); i += 2 {
		key, ok := kv[i].(string)
		if !ok {
			return nil, fmt.Errorf("BSON 键必须是字符串，收到 %T", kv[i])
		}
		elem, err := bsonElement(key, kv[i+1])
		if err != nil {
			return nil, err
		}
		body = append(body, elem...)
	}
	out := make([]byte, 4+len(body)+1)
	binary.LittleEndian.PutUint32(out[:4], uint32(len(out)))
	copy(out[4:], body)
	out[len(out)-1] = 0
	return out, nil
}

func bsonElement(key string, v any) ([]byte, error) {
	k := append([]byte(key), 0)
	switch t := v.(type) {
	case int32:
		return append(append([]byte{bsonInt32}, k...), int32Bytes(t)...), nil
	case int:
		return append(append([]byte{bsonInt32}, k...), int32Bytes(int32(t))...), nil
	case int64:
		return append(append([]byte{bsonInt64}, k...), int64Bytes(t)...), nil
	case bool:
		b := byte(0)
		if t {
			b = 1
		}
		return append(append([]byte{bsonBool}, k...), b), nil
	case string:
		s := append(int32Bytes(int32(len(t)+1)), []byte(t)...)
		return append(append([]byte{bsonString}, k...), append(s, 0)...), nil
	case []byte:
		// 子类型 0 是通用二进制；SASL payload 用的就是它。
		out := append([]byte{bsonBinary}, k...)
		out = append(out, int32Bytes(int32(len(t)))...)
		out = append(out, 0x00)
		return append(out, t...), nil
	case *bsonDoc:
		raw, err := t.Encode()
		if err != nil {
			return nil, err
		}
		return append(append([]byte{bsonEmbedded}, k...), raw...), nil
	case nil:
		return append([]byte{bsonNull}, k...), nil
	default:
		return nil, fmt.Errorf("BSON 不支持的值类型 %T", v)
	}
}

func int32Bytes(v int32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, uint32(v))
	return b
}

func int64Bytes(v int64) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, uint64(v))
	return b
}

// Encode 把已解析的文档重新编码（测试与嵌套字段用）。
func (d *bsonDoc) Encode() ([]byte, error) {
	kv := make([]any, 0, len(d.fields)*2)
	for _, f := range d.fields {
		switch f.typ {
		case bsonBinary:
			kv = append(kv, f.key, f.bin)
		case bsonString:
			kv = append(kv, f.key, f.val)
		case bsonBool:
			kv = append(kv, f.key, f.val)
		case bsonInt32:
			kv = append(kv, f.key, f.val)
		case bsonInt64:
			kv = append(kv, f.key, f.val)
		case bsonDouble:
			kv = append(kv, f.key, f.val)
		case bsonEmbedded:
			kv = append(kv, f.key, f.val)
		case bsonNull:
			kv = append(kv, f.key, nil)
		default:
			return nil, fmt.Errorf("BSON 无法回编码类型 0x%x", f.typ)
		}
	}
	return bsonBuild(kv...)
}

// bsonParse 解析文档。未知类型直接报错——认证结论依赖 ok/code/errmsg 读得准。
func bsonParse(b []byte) (*bsonDoc, error) {
	if len(b) < 5 {
		return nil, errors.New("BSON 文档过短")
	}
	size := int(binary.LittleEndian.Uint32(b[:4]))
	if size != len(b) || size < 5 {
		return nil, fmt.Errorf("BSON 长度字段与实际字节数不符: 声明 %d 实收 %d", size, len(b))
	}
	if b[size-1] != 0 {
		return nil, errors.New("BSON 文档缺少结束符")
	}
	d := &bsonDoc{}
	pos := 4
	for pos < size-1 {
		typ := b[pos]
		pos++
		end := pos
		for end < size && b[end] != 0 {
			end++
		}
		if end >= size {
			return nil, errors.New("BSON 字段名未结束")
		}
		key := string(b[pos:end])
		pos = end + 1
		val, next, err := bsonReadValue(typ, b, pos)
		if err != nil {
			return nil, fmt.Errorf("字段 %q: %w", key, err)
		}
		d.fields = append(d.fields, bsonField{key: key, typ: typ, val: val, bin: binOf(val)})
		pos = next
	}
	return d, nil
}

func binOf(v any) []byte {
	if b, ok := v.([]byte); ok {
		return b
	}
	return nil
}

func bsonReadValue(typ byte, b []byte, pos int) (any, int, error) {
	switch typ {
	case bsonDouble:
		if pos+8 > len(b) {
			return nil, 0, errShort
		}
		return math.Float64frombits(binary.LittleEndian.Uint64(b[pos:])), pos + 8, nil
	case bsonString:
		if pos+4 > len(b) {
			return nil, 0, errShort
		}
		n := int(binary.LittleEndian.Uint32(b[pos:]))
		if n < 1 || pos+4+n > len(b) {
			return nil, 0, fmt.Errorf("字符串长度 %d 越界", n)
		}
		return string(b[pos+4 : pos+4+n-1]), pos + 4 + n, nil
	case bsonBinary:
		if pos+5 > len(b) {
			return nil, 0, errShort
		}
		n := int(int32(binary.LittleEndian.Uint32(b[pos:])))
		if n < 0 || pos+5+n > len(b) {
			return nil, 0, fmt.Errorf("二进制长度 %d 越界", n)
		}
		return append([]byte(nil), b[pos+5:pos+5+n]...), pos + 5 + n, nil
	case bsonBool:
		if pos+1 > len(b) {
			return nil, 0, errShort
		}
		return b[pos] != 0, pos + 1, nil
	case bsonNull, bsonUndefined:
		return nil, pos, nil
	case bsonInt32:
		if pos+4 > len(b) {
			return nil, 0, errShort
		}
		return int32(binary.LittleEndian.Uint32(b[pos:])), pos + 4, nil
	case bsonInt64, bsonTimestamp, bsonUTCDate:
		if pos+8 > len(b) {
			return nil, 0, errShort
		}
		return int64(binary.LittleEndian.Uint64(b[pos:])), pos + 8, nil
	case bsonEmbedded, bsonArray:
		size := int(binary.LittleEndian.Uint32(b[pos:]))
		if size <= 0 || pos+size > len(b) {
			return nil, 0, fmt.Errorf("嵌套文档长度 %d 越界", size)
		}
		sub, err := bsonParse(b[pos : pos+size])
		if err != nil {
			return nil, 0, err
		}
		return sub, pos + size, nil
	case bsonObjectID:
		if pos+12 > len(b) {
			return nil, 0, errShort
		}
		return append([]byte(nil), b[pos:pos+12]...), pos + 12, nil
	case bsonRegex:
		p := pos
		for p < len(b) && b[p] != 0 {
			p++
		}
		for p < len(b) && b[p] != 0 {
			p++
		}
		if p >= len(b) {
			return nil, 0, errShort
		}
		return nil, p + 1, nil
	default:
		return nil, 0, fmt.Errorf("不支持的 BSON 类型 0x%02x", typ)
	}
}

var errShort = errors.New("BSON 数据被截断")

// Get 按键取字段。
func (d *bsonDoc) Get(key string) (any, bool) {
	for _, f := range d.fields {
		if f.key == key {
			return f.val, true
		}
	}
	return nil, false
}

// Int 把 BSON 里可能是 double/int32/int64/bool 的数字读成 int64。
// 「ok」是 double、「code」是 int32、conversationId 在不同版本里三种都出现过，
// 只认一种就会把成功的会话读成失败。
func (d *bsonDoc) Int(key string) (int64, bool) {
	v, ok := d.Get(key)
	if !ok {
		return 0, false
	}
	switch t := v.(type) {
	case int32:
		return int64(t), true
	case int64:
		return t, true
	case float64:
		return int64(t), true
	case bool:
		if t {
			return 1, true
		}
		return 0, true
	case string:
		n, err := strconv.ParseInt(t, 10, 64)
		return n, err == nil
	}
	return 0, false
}

func (d *bsonDoc) Str(key string) string {
	v, ok := d.Get(key)
	if !ok {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func (d *bsonDoc) Bin(key string) []byte {
	v, ok := d.Get(key)
	if !ok {
		return nil
	}
	if b, ok := v.([]byte); ok {
		return b
	}
	return nil
}

func (d *bsonDoc) Bool(key string) bool {
	v, ok := d.Get(key)
	if !ok {
		return false
	}
	if b, ok := v.(bool); ok {
		return b
	}
	return false
}

// Keys 便于测试断言与错误信息。
func (d *bsonDoc) Keys() []string {
	out := make([]string, 0, len(d.fields))
	for _, f := range d.fields {
		out = append(out, f.key)
	}
	sort.Strings(out)
	return out
}
