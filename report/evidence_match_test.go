package report

import "testing"

// 上传类证据的措辞各靶场不一：有的写 "successfully uploaded"，有的写
// "uploaded successfully"，还有的只回一句 "upload success"。三种都要能命中。
func TestEvidenceMatchRangeUploadWording(t *testing.T) {
	body := "HTTP/1.1 200 OK\r\n\r\n<p>uploaded successfully: /uploads/shell.php</p>"
	_, _, ok := EvidenceMatchRange("upload", "文件上传导致远程代码执行", "/upload.php", "", body)
	if !ok {
		t.Fatal("uploaded successfully should match")
	}
	body2 := "HTTP/1.1 200 OK\r\n\r\n{\"msg\":\"upload success\"}"
	if _, _, ok := EvidenceMatchRange("upload", "任意文件上传", "/upload.php", "", body2); !ok {
		t.Fatal("upload success should match")
	}
}

// 类别专属标记没命中时，通用凭证/命令输出特征要能兜底。
func TestEvidenceMatchRangeGenericFallback(t *testing.T) {
	body := "HTTP/1.1 200 OK\r\n\r\nuid=33(www-data) gid=33(www-data) groups=33(www-data)"
	start, end, ok := EvidenceMatchRange("information", "敏感信息泄露", "/x", "", body)
	if !ok {
		t.Fatal("generic uid marker should match")
	}
	if start < 0 || end <= start {
		t.Fatalf("bad range %d-%d", start, end)
	}
}
