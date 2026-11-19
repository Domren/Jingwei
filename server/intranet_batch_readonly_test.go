package server

import (
	"strings"
	"testing"
	"time"
)

// TestBatchReadOnlyWhoamiAggregatesTenSessions 模拟一个 10 台会话的分组，
// 批量 whoami 汇总：10 条结果都在、输出正确、无错误；不依赖数据库或网络。
func TestBatchReadOnlyWhoamiAggregatesTenSessions(t *testing.T) {
	targets := make([]batchTarget, 0, 10)
	for i := 1; i <= 10; i++ {
		targets = append(targets, batchTarget{ID: int64(i), Name: "web-" + string(rune('a'+i-1))})
	}
	calls := 0
	results, reject := batchReadOnlyRun(targets, "whoami", time.Second, func(tg batchTarget, cmd string, _ time.Duration) intranetExecOutcome {
		calls++
		if cmd != "whoami" {
			t.Fatalf("目标 #%d 收到的命令不是 whoami: %q", tg.ID, cmd)
		}
		return intranetExecOutcome{Output: "uid=33(www-data) host=" + tg.Name, ExitCode: 0}
	})
	if reject != "" {
		t.Fatalf("只读命令被误拒: %s", reject)
	}
	if calls != 10 || len(results) != 10 {
		t.Fatalf("期望 10 台全部执行，实际 calls=%d results=%d", calls, len(results))
	}
	for i, item := range results {
		wantID := int64(i + 1)
		if item.SessionID != wantID {
			t.Fatalf("第 %d 条会话 ID=%d，期望 %d", i, item.SessionID, wantID)
		}
		if item.Result.IsError || item.Error != "" || item.Result.ExitCode != 0 {
			t.Fatalf("第 %d 条误报错误: %+v", i, item)
		}
		if !strings.Contains(item.Result.Output, "host=web-") {
			t.Fatalf("第 %d 条输出未汇总: %q", i, item.Result.Output)
		}
	}
}

// TestBatchWriteCommandRejectedByGuard 写命令（含夹在只读命令后面的写）必须在
// 投递前被守卫拒绝，且执行器一次都不被调用——拒绝不是「放行后记一笔」。
func TestBatchWriteCommandRejectedByGuard(t *testing.T) {
	writes := []string{
		"rm -rf /",
		"echo pwned > /tmp/a",
		"useradd backdoor",
		"curl -X POST -d 'a=b' http://x/",
		"sed -i 's/a/b/' /etc/passwd",
		"find / -name x -delete",
		"whoami && rm -rf /var/www",
		"cat /etc/passwd; chmod 777 /tmp",
		"cat `rm -rf /`",
		"cat $(whoami > /tmp/x)",
		"python3 -c 'import os; os.system(\"id\")'",
		"tee /etc/cron.d/x",
	}
	for _, cmd := range writes {
		t.Run(cmd, func(t *testing.T) {
			if reason := batchReadOnlyRejectReason(cmd); reason == "" {
				t.Fatalf("写命令 %q 未被守卫拒绝", cmd)
			}
			calls := 0
			results, reject := batchReadOnlyRun([]batchTarget{{ID: 1, Name: "web"}}, cmd, time.Second,
				func(batchTarget, string, time.Duration) intranetExecOutcome {
					calls++
					return intranetExecOutcome{ExitCode: 0}
				})
			if reject == "" || results != nil {
				t.Fatalf("写命令 %q 的批量结果应为拒绝且无结果，reject=%q results=%v", cmd, reject, results)
			}
			if calls != 0 {
				t.Fatalf("写命令 %q 被拒绝但执行器仍被调用 %d 次", cmd, calls)
			}
		})
	}
}

// TestBatchReadOnlyAllowsCommonReconCommands 常见只读侦察命令必须放行，
// 否则守卫会变得不可用；包装器与管道逐段都要只读。
func TestBatchReadOnlyAllowsCommonReconCommands(t *testing.T) {
	reads := []string{
		"whoami",
		"id && hostname && pwd",
		"ps aux | grep nginx",
		"cat /etc/os-release",
		"sudo -n whoami",
		"FOO=bar whoami",
		"ip addr show",
		"tasklist /nh",
		"printf '%s\\n' ok",
	}
	for _, cmd := range reads {
		if reason := batchReadOnlyRejectReason(cmd); reason != "" {
			t.Fatalf("只读命令 %q 被误拒: %s", cmd, reason)
		}
	}
}
