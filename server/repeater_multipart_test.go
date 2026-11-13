package server

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// 欠账 R17 的复现与验收夹具：带 JWT 的 multipart 文件上传，重发出站字节必须与
// 直接发送（yakit 同口径）逐字节一致。
//
// 根因（本文件两条用例分别钉住）：
//   - 文本通道（UI 现状）：body 走 JSON string——JSON 字符串是 UTF-8 语义，二进制
//     文件部件（0x80-0xFF 裸字节）在编码侧被替换成 U+FFFD，出站字节必然与原报文
//     不一致。这是通道固有的，修不掉，只能绕开；
//   - base64 通道（修复）：body_base64 把原始字节无损带过 JSON，出站逐字节一致。
//
// 反向验证：退掉 body_base64 的解码分支，base64 用例的 body 变空、字节比对立即失败。

const r17JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.R17sig"

// buildR17MultipartBody 构造与真实文件上传同形的 multipart 正文：文本字段 + 二进制
// 文件部件（0x00-0xFF 全字节样本，覆盖 NUL 与非法 UTF-8 序列）。
func buildR17MultipartBody(boundary string) []byte {
	var buf bytes.Buffer
	buf.WriteString("--" + boundary + "\r\n")
	buf.WriteString("Content-Disposition: form-data; name=\"username\"\r\n\r\n")
	buf.WriteString("admin\r\n")
	buf.WriteString("--" + boundary + "\r\n")
	buf.WriteString("Content-Disposition: form-data; name=\"file\"; filename=\"payload.bin\"\r\n")
	buf.WriteString("Content-Type: application/octet-stream\r\n\r\n")
	file := make([]byte, 256)
	for i := range file {
		file[i] = byte(i)
	}
	buf.Write(file)
	buf.WriteString("\r\n--" + boundary + "--\r\n")
	return buf.Bytes()
}

// r17CaptureServer 落地侧：原样收下请求字节与 JWT 头。
func r17CaptureServer(t *testing.T, body *[]byte, auth *string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		*body = b
		*auth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
}

// r17SendDirect 直接发送原始字节（yakit 同口径）。
func r17SendDirect(t *testing.T, url string, contentType string, body []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Authorization", "Bearer "+r17JWT)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
}

// r17SendViaRepeater 走重发处理器（与 UI 相同的 JSON 载荷形态）。
func r17SendViaRepeater(t *testing.T, s *Server, url string, payload map[string]any) {
	t.Helper()
	t.Setenv(repeaterAllowLocalEnv, "1")
	req := httptest.NewRequest(http.MethodPost, "/api/repeater/send", mustJSONReader(t, payload))
	rec := httptest.NewRecorder()
	s.sendRepeater(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("重发接口 HTTP %d: %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if out.Error != "" {
		t.Fatalf("重发返回错误: %s", out.Error)
	}
}

func r17Case(t *testing.T, payloadBody func(body []byte) map[string]any) (direct, via []byte) {
	t.Helper()
	s := &Server{}
	const boundary = "----jingwei-r17"
	const contentType = "multipart/form-data; boundary=" + boundary
	original := buildR17MultipartBody(boundary)

	var directBody, viaBody []byte
	directSrv := r17CaptureServer(t, &directBody, new(string))
	defer directSrv.Close()
	viaSrv := r17CaptureServer(t, &viaBody, new(string))
	defer viaSrv.Close()

	r17SendDirect(t, directSrv.URL+"/upload", contentType, original)
	if len(directBody) == 0 {
		t.Fatalf("直接发送未到达捕获服务（directBody 空），后续比对无意义")
	}

	payload := payloadBody(original)
	payload["method"] = "POST"
	payload["url"] = viaSrv.URL + "/upload"
	payload["headers"] = map[string]string{
		"Content-Type":  contentType,
		"Authorization": "Bearer " + r17JWT,
	}
	r17SendViaRepeater(t, s, viaSrv.URL+"/upload", payload)
	t.Logf("R17 捕获：direct=%d bytes, via=%d bytes", len(directBody), len(viaBody))
	return directBody, viaBody
}

// 文本通道的现状定性（R17 根因）：body 以 JSON string 携带二进制时，0x80-0xFF 裸
// 字节被替换成 U+FFFD，出站字节与原报文必然不一致。这条通道对纯文本 multipart
// 没有影响（CRLF/JWT 都是 ASCII）——缺陷 precisely 局限在二进制部件。
func TestRepeaterMultipartTextChannelCorruptsBinary(t *testing.T) {
	direct, via := r17Case(t, func(body []byte) map[string]any {
		return map[string]any{"body": string(body)}
	})
	if bytes.Equal(direct, via) {
		t.Fatal("文本通道携带二进制应当产生字节差异（否则本用例没有钉住 R17 根因）")
	}
	t.Logf("R17 复现：direct=%d bytes, via=%d bytes（二进制部件被 UTF-8 强制转换破坏）", len(direct), len(via))
}

// 验收（R17）：base64 通道的出站字节与直接发送逐字节一致——差异归零。
func TestRepeaterMultipartBase64MatchesDirectSend(t *testing.T) {
	direct, via := r17Case(t, func(body []byte) map[string]any {
		return map[string]any{"body_base64": base64Std(body)}
	})
	if !bytes.Equal(direct, via) {
		t.Fatalf("R17 验收失败：出站字节不一致（direct=%d bytes, via=%d bytes）", len(direct), len(via))
	}
}

// base64Std 是标准编码的小包装，避免测试文件直接拉 encoding/base64 的多种写法。
func base64Std(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}
