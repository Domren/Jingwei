package server

import (
	"strings"
	"testing"

	"github.com/Domren/jingwei/db"
)

// TestClassifyIntranetFailureFourCategories 四类失效原因各有指名 key：
// 密钥轮换 / 目标重启 / 被清理 / 网络不通，未知错误落到 unknown 占位。
func TestClassifyIntranetFailureFourCategories(t *testing.T) {
	cases := []struct {
		text string
		key  string
	}{
		{"HTTP 401 Unauthorized: 载荷密钥已轮换，认证失败", intranetFailKeyRotation},
		{"403 forbidden token 无效，重放被拒", intranetFailKeyRotation},
		{"dial tcp: read: connection reset by peer", intranetFailTargetReboot},
		{"目标重启中 connection refused", intranetFailTargetReboot},
		{"404 Not Found: 文件不存在，webshell 已被清理", intranetFailCleaned},
		{"no such file or directory: /var/www/.shell.php removed", intranetFailCleaned},
		{"context deadline exceeded: i/o timeout，网络不通", intranetFailNetworkDead},
		{"dial tcp 10.0.0.1:80: no route to host 不可达", intranetFailNetworkDead},
		{"something unexpected happened", intranetFailUnknown},
		{"", intranetFailUnknown},
	}
	for _, c := range cases {
		if got := classifyIntranetFailureReason(c.text); got != c.key {
			t.Errorf("classify(%q)=%q，期望 %q", c.text, got, c.key)
		}
	}
}

// TestIntranetFailureAdviceNamesReasonAndRemedy 每类都要给出具体原因和补救，
// 不能只给一个 key 让操作员自己猜下一步。
func TestIntranetFailureAdviceNamesReasonAndRemedy(t *testing.T) {
	for _, key := range []string{
		intranetFailKeyRotation, intranetFailTargetReboot,
		intranetFailCleaned, intranetFailNetworkDead, intranetFailUnknown,
	} {
		c := getIntranetFailureCategory(key)
		if c.Key != key {
			t.Fatalf("分类 %s 查回的 Key=%s", key, c.Key)
		}
		if strings.TrimSpace(c.Reason) == "" || strings.TrimSpace(c.Remedy) == "" {
			t.Fatalf("分类 %s 缺少原因或补救: %+v", key, c)
		}
		advice := intranetFailureAdvice(key)
		if !strings.Contains(advice, c.Reason) || !strings.Contains(advice, c.Remedy) {
			t.Fatalf("分类 %s 的建议未点名原因/补救: %q", key, advice)
		}
	}
}

// TestIntranetSessionFailureReasonFromMetadata 健康快照里的分类 key 可被读回，
// 前端据此渲染标签；未分类时返回空串。
func TestIntranetSessionFailureReasonFromMetadata(t *testing.T) {
	sess := &db.IntranetSession{Metadata: map[string]any{"health_failure_reason": intranetFailCleaned}}
	if got := intranetSessionFailureReason(sess); got != intranetFailCleaned {
		t.Fatalf("读回的失效原因=%q", got)
	}
	if got := intranetSessionFailureReason(&db.IntranetSession{Metadata: map[string]any{}}); got != "" {
		t.Fatalf("未分类时应为空，得到 %q", got)
	}
	if got := intranetSessionFailureReason(nil); got != "" {
		t.Fatalf("nil 会话应为空，得到 %q", got)
	}
}
