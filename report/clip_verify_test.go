package report

import (
	"fmt"
	"strings"
	"testing"
)

func TestClipResponseVerify(t *testing.T) {
	noise := strings.Repeat("<div class=\"noise\">unrelated html noise</div>\n", 3000)
	cases := []struct {
		name   string
		vuln   string
		marker string
	}{
		{"LFI", "File Inclusion 文件包含", "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin"},
		{"SQL", "SQL Injection 注入", "You have an error in your SQL syntax; check the manual near '1''' at line 1"},
		{"XSS", "XSS 跨站脚本", "<script>alert('xss')</script>"},
		{"CMD", "Command Injection 命令执行", "uid=33(www-data) gid=33(www-data) groups=33(www-data)"},
	}
	for _, c := range cases {
		resp := "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nServer: Apache\r\n\r\n" + noise + c.marker + noise
		clipped, truncated := clipHTTPResponseForReport(c.vuln, c.vuln, "/vuln?id=1", "", resp)
		kept := strings.Contains(clipped, strings.SplitN(c.marker, "\n", 2)[0])
		fmt.Printf("[%s] 原始=%d 裁剪=%d truncated=%v 命中保留=%v\n", c.name, len(resp), len(clipped), truncated, kept)
		if !kept {
			t.Errorf("%s: 裁剪后丢失命中特征", c.name)
		}
		if len(clipped) >= len(resp) {
			t.Errorf("%s: 未裁剪", c.name)
		}
	}
}
