package db

import (
	"regexp"
	"testing"
)

// 内置「删除类接口路径」规则匹配的是整个 tool_input JSON 串，因此用例直接以
// JSON 形态给出，与 Interceptor 实际拿到的 subject 一致。
// 内置「删除系统关键目录」（v4）规则直接匹配 agent 的 tool_input。
func TestRMCriticalPathPattern(t *testing.T) {
	re := regexp.MustCompile(rmCriticalPathPattern)

	hit := []string{
		`{"command":"rm -f /etc/passwd"}`,
		`{"command":"rm -f /etc"}`,
		`{"command":"rm -f /bin/sh"}`,
		`{"command":"rm -f /usr/bin/x"}`,
		`{"command":"rm -f /var/lib/mysql/ibdata1"}`,
		`{"command":"rm -f /var/run/x.pid"}`,
		`{"command":"rm -f /var"}`,
		`{"command":"rm -f /root/.bash_history"}`,
		`{"command":"rm -f /"}`,
		`{"command":"cd / && rm -f /lib/libc.so.6"}`,
	}
	for _, s := range hit {
		if !re.MatchString(s) {
			t.Errorf("应命中却放行: %s", s)
		}
	}

	// 应用数据（web 根目录等）必须允许清理，否则 P4 撤离删不掉落地 webshell。
	miss := []string{
		`{"command":"rm -f /var/www/html/upload/shell.php"}`,
		`{"command":"cd /var/www/html/upload && rm -f shell.php token123.php"}`,
		`{"command":"rm -f /etcetera"}`,
		`{"command":"rm -f /varnish/cache"}`,
		`{"command":"rm -f /home/user/notes.txt"}`,
		`{"command":"nmap -p80 10.0.0.1"}`,
	}
	for _, s := range miss {
		if re.MatchString(s) {
			t.Errorf("误拦: %s", s)
		}
	}
}

func TestDeleteEndpointPathPattern(t *testing.T) {
	re := regexp.MustCompile(deleteEndpointPathPattern)

	hit := []string{
		`{"command":"curl -s 'http://t.com/api/user/delete?id=1'"}`,    // GET 打删除接口
		`{"command":"curl -X POST http://t.com/admin/delete -d id=1"}`, // POST 打删除接口
		`{"command":"curl 'http://t.com/api/deleteAll'"}`,
		`{"command":"curl 'http://t.com/api/delete_user?id=1'"}`,
		`{"command":"curl 'http://t.com/api/delete-user?id=1'"}`,
		`{"url":"http://t.com/api/remove?id=1"}`,
		`{"command":"curl http://t.com/files/unlink/3"}`,
		`{"command":"curl http://t.com/api/del?id=2"}`,
		`{"command":"curl -X POST http://t/v1/erase"}`,
		`{"command":"curl http://t/admin/destroyAll"}`, // v1 的路径规则不允许后缀，这里补上
	}
	for _, s := range hit {
		if !re.MatchString(s) {
			t.Errorf("应命中却放行: %s", s)
		}
	}

	// 动词后必须跟分隔符，避免 /delivery、/details 这类只读路径被误拦。
	miss := []string{
		`{"command":"curl 'http://t.com/api/delivery?id=1'"}`,
		`{"command":"curl 'http://t.com/order/details'"}`,
		`{"command":"curl 'http://t.com/api/delta/sync'"}`,
		`{"command":"curl 'http://t.com/user/delegate'"}`,
		`{"command":"curl 'http://delete.example.com/'"}`, // 删除动词出现在域名而非路径
		`{"command":"curl 'http://t.com/remote/status'"}`,
		`{"command":"nmap -p80 10.0.0.1"}`,
	}
	for _, s := range miss {
		if re.MatchString(s) {
			t.Errorf("误拦: %s", s)
		}
	}
}
