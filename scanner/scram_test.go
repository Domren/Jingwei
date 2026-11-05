package scanner

import (
	"encoding/base64"
	"testing"
)

// SCRAM 的数学对着另一套独立实现（Python hashlib/hmac 算出的向量）校，而不是对着
// 本仓库的另一段 Go 代码校——后者只会证明「两处写错的方式一致」。
// 端到端还另有 PostgreSQL 16（默认 scram-sha-256）与 MongoDB 8 的真机验证。
func TestScramVectors(t *testing.T) {
	cases := []struct {
		name          string
		hs            scramHashes
		password      string
		clientNonce   string
		serverFirst   string
		wantProof     string
		wantServerSig string
	}{
		{
			name:        "SCRAM-SHA-256",
			hs:          ScramSHA256,
			password:    "pen",
			clientNonce: "fyko+d2lbbFgONRv9qkxdawL",
			serverFirst: "r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096",
			wantProof:   "c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=OQnXTE8gd4+LBTfd2d2yC1RDUIMMJH0PnmdVGeCdR+M=",
		},
		{
			name:        "SCRAM-SHA-1",
			hs:          ScramSHA1,
			password:    "pen",
			clientNonce: "cpB1934r2p3F97zjrrJ1QxCsX3pLpVXk",
			serverFirst: "r=cpB1934r2p3F97zjrrJ1QxCsX3pLpVXk,s=QSXCR+Q6sek8bf92,i=4096",
			wantProof:   "c=biws,r=cpB1934r2p3F97zjrrJ1QxCsX3pLpVXk,p=wNWl8Hv+y0jcld0CA3mTHfi/BnM=",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &scramClient{hs: tc.hs, password: tc.password, clientNonce: tc.clientNonce}
			c.clientFirst = "n=,r=" + tc.clientNonce
			final, err := c.HandleServerFirst(tc.serverFirst)
			if err != nil {
				t.Fatal(err)
			}
			if final != tc.wantProof {
				t.Fatalf("client-final = %q\n want      %q", final, tc.wantProof)
			}
			if len(c.serverWanted) == 0 {
				t.Fatal("没算出期望的服务端签名")
			}
			// 服务端签名要能验通；验不通的会话不能报命中。
			good := "v=" + base64.StdEncoding.EncodeToString(c.serverWanted)
			if !c.VerifyServerFinal(good) {
				t.Fatal("正确的服务端签名没验通")
			}
			if c.VerifyServerFinal("v=AAAAAAAAAAAAAAAAAAAAAAAAAAA=") {
				t.Fatal("错误的服务端签名居然验通了")
			}
		})
	}
}

// 服务端 nonce 必须扩展本端 nonce。不校验这一条，proof 就可能和中间人共享。
func TestScramRejectsForeignNonce(t *testing.T) {
	c := &scramClient{hs: ScramSHA256, password: "pen", clientNonce: "CLIENT"}
	c.clientFirst = "n=,r=CLIENT"
	if _, err := c.HandleServerFirst("r=SOMETHING_ELSE,s=QSXCR+Q6sek8bf92,i=4096"); err == nil {
		t.Fatal("nonce 不是本端扩展时必须报错")
	}
	if _, err := c.HandleServerFirst("r=CLIENTbutValid,s=QSXCR+Q6sek8bf92"); err == nil {
		t.Fatal("缺 i 字段时必须报错")
	}
	// 迭代次数被写成一个天文数字时，PBKDF2 会把这台机器钉住——预算不是这么烧的。
	if _, err := c.HandleServerFirst("r=CLIENTx,s=QSXCR+Q6sek8bf92,i=999999999"); err == nil {
		t.Fatal("迭代次数不可信时必须报错")
	}
}

func TestScramAttrsParsesBase64WithEquals(t *testing.T) {
	// salt 的 base64 里带 '='，按逗号切分后值里也可能有 '='；键值只在第一个 '=' 处切。
	attrs := scramAttrs("r=abc=def,s=QSXCR+Q6sek8bf92==,i=4096")
	if attrs["r"] != "abc=def" || attrs["s"] != "QSXCR+Q6sek8bf92==" || attrs["i"] != "4096" {
		t.Fatalf("attrs = %+v", attrs)
	}
}

// MongoDB 的 SCRAM-SHA-1 与 PG 用同一组哈希；不一样的只有喂给派生的「口令」。
// 这条规则不是从文档抄的：文档里「uses MD5」的说法让人以为哈希组换成 MD5，
// 而拿 mongod 存的 credential（salt/iterationCount/storedKey）反推，只有
// hex(md5(user + ":mongo:" + password)) 能对上 storedKey——所以单独钉一个测试。
func TestMongoScramKey(t *testing.T) {
	cred := Credential{Username: "jwadmin", Password: "pen"}
	if got := mongoScramKey(ScramSHA256, cred); got != "pen" {
		t.Fatalf("SCRAM-SHA-256 必须用原口令，得到 %q", got)
	}
	if got := mongoScramKey(ScramSHA1, cred); got != "8cd81062f43353d9cfb41a3a6cf9acda" {
		t.Fatalf("SCRAM-SHA-1 的口令输入 = %q，应为 hex(md5(user:mongo:pass)) = %q", got, "8cd81062f43353d9cfb41a3a6cf9acda")
	}
}
