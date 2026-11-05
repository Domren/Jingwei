package scanner

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"strconv"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

// SCRAM 客户端（RFC 5802 / RFC 7677）。PostgreSQL 与 MongoDB 都靠它做 SASL 认证，
// 哈希组做成参数而不是复制两份实现——复制出来的第二份永远只有一份被测到。
//
// 两个服务器在同一机制名下的差别（都在真机上量过，不是照文档抄的）：
//   - MongoDB 的 SCRAM-SHA-1 仍是 HMAC-SHA-1/PBKDF2-SHA1（服务端存的 storedKey 是 20 字节），
//     不一样的只有喂给派生的「口令」：它先算 hex(md5(user + ":mongo:" + password))；
//   - MongoDB 的 SCRAM-SHA-256 用原口令，且服务端给的 salt 是完整使用，不截断。
type scramHashes struct {
	mech string
	h    func() hash.Hash
	mac  func(key, msg []byte) []byte
	kdf  func(str, salt []byte, iter, keyLen int) []byte
}

func hmacWith(h func() hash.Hash) func(key, msg []byte) []byte {
	return func(key, msg []byte) []byte {
		m := hmac.New(h, key)
		m.Write(msg)
		return m.Sum(nil)
	}
}

func kdfWith(h func() hash.Hash) func(pass, salt []byte, iter, keyLen int) []byte {
	return func(pass, salt []byte, iter, keyLen int) []byte {
		return pbkdf2.Key(pass, salt, iter, keyLen, h)
	}
}

func newScramHashes(mech string, h func() hash.Hash) scramHashes {
	return scramHashes{mech: mech, h: h, mac: hmacWith(h), kdf: kdfWith(h)}
}

var (
	ScramSHA256 = newScramHashes("SCRAM-SHA-256", sha256.New)
	ScramSHA1   = newScramHashes("SCRAM-SHA-1", sha1.New)
)

// scramClient 是一次 SCRAM 会话的数学部分；报文封装交给各协议适配器。
type scramClient struct {
	hs           scramHashes
	password     string
	clientNonce  string
	clientFirst  string // "n=,r=<nonce>"：PG 与 Mongo 都把身份放在 SASL 之外，这里留空用户名
	serverFirst  string
	serverNonce  string
	salted       []byte
	authMessage  string
	serverWanted []byte
}

// newScramClient 生成随机 client nonce。nonce 必须不可预测：它参与 auth-message
// 的计算，固定的话两次会话的 proof 也一样，等于把重放素材留在实现里。
func newScramClient(hs scramHashes, password string) (*scramClient, error) {
	buf := make([]byte, 18)
	if _, err := rand.Read(buf); err != nil {
		return nil, err
	}
	c := &scramClient{hs: hs, password: password}
	c.clientNonce = base64.StdEncoding.EncodeToString(buf)
	c.clientFirst = "n=,r=" + c.clientNonce
	return c, nil
}

func (c *scramClient) FirstBare() string { return c.clientFirst }

// HandleServerFirst 解析服务端第一条消息并算出 client-final。
//
// nonce 校验不是装饰：RFC 5802 要求服务端 nonce 是本端 nonce 的扩展。不校验就允许对面
// 用任意 nonce，那样算出来的 proof 就和一个中间人共用了。
func (c *scramClient) HandleServerFirst(msg string) (string, error) {
	attrs := scramAttrs(msg)
	saltB64, iterStr, r := attrs["s"], attrs["i"], attrs["r"]
	if saltB64 == "" || iterStr == "" || r == "" {
		return "", errors.New("服务端第一条消息缺 r/s/i")
	}
	if !strings.HasPrefix(r, c.clientNonce) {
		return "", errors.New("服务端 nonce 不是本端 nonce 的扩展")
	}
	iter, err := strconv.Atoi(iterStr)
	if err != nil || iter <= 0 || iter > 1<<20 {
		return "", fmt.Errorf("迭代次数 %q 不可信", iterStr)
	}
	salt, err := base64.StdEncoding.DecodeString(saltB64)
	if err != nil {
		return "", errors.New("salt 不是合法 base64")
	}
	c.serverFirst, c.serverNonce = msg, r
	c.salted = c.hs.kdf([]byte(c.password), salt, iter, c.hs.h().Size())

	bare := "c=biws,r=" + c.serverNonce
	c.authMessage = c.clientFirst + "," + c.serverFirst + "," + bare
	clientKey := c.hs.mac(c.salted, []byte("Client Key"))
	stored := digestOf(c.hs.h, clientKey)
	sig := c.hs.mac(stored, []byte(c.authMessage))
	proof := append([]byte(nil), clientKey...)
	for i := range proof {
		proof[i] ^= sig[i]
	}
	serverKey := c.hs.mac(c.salted, []byte("Server Key"))
	c.serverWanted = c.hs.mac(serverKey, []byte(c.authMessage))
	return bare + ",p=" + base64.StdEncoding.EncodeToString(proof), nil
}

// VerifyServerFinal 校验服务端签名。口令已经发出去了，不认回这个签名就等于把
// 「对面是不是那台服务」交给一个没验证过的对象。
func (c *scramClient) VerifyServerFinal(msg string) bool {
	if len(c.serverWanted) == 0 {
		return false
	}
	got, err := base64.StdEncoding.DecodeString(scramAttrs(msg)["v"])
	if err != nil {
		return false
	}
	return hmac.Equal(got, c.serverWanted)
}

func scramAttrs(msg string) map[string]string {
	out := map[string]string{}
	for _, part := range strings.Split(msg, ",") {
		if k, v, ok := strings.Cut(part, "="); ok {
			out[k] = v
		}
	}
	return out
}

func digestOf(h func() hash.Hash, b []byte) []byte {
	x := h()
	x.Write(b)
	return x.Sum(nil)
}
