package report

import (
	"strings"
	"testing"
	"time"
)

func TestTraceMatrixMarkdownListsTracesAndVerdicts(t *testing.T) {
	in := TraceMatrixInput{
		GeneratedAt: time.Date(2026, 11, 6, 10, 0, 0, 0, time.UTC),
		Hostname:    "10.99.0.10",
		Rows: []TraceMatrixRow{
			{
				Kind: "cron", Name: "cron 计划任务", Host: "10.99.0.10",
				Landed:  []string{"crontab:+a1b2c3"},
				Traces:  []string{"一条带 `# jw:<token>` 注释的 crontab 行"},
				Residue: []string{"cron 执行日志里已经发生的那些次执行"},
				Verify:  "`crontab -l` 里不再出现该 token",
				Verdict: TraceVerdictCleared, Detail: "JW_ARTIFACT_GONE",
			},
			{
				Kind: "ssh_key", Name: "SSH 授权公钥", Host: "10.99.0.10",
				Landed:  []string{"/root/.ssh/authorized_keys"},
				Traces:  []string{"一行带注释的公钥"},
				Residue: []string{"认证日志里的登录记录"},
				Verify:  "该行不再存在",
				Verdict: TraceVerdictUnverified, Detail: "台账里没有独立的验证命令，只执行了撤销命令",
			},
		},
		LedgerExternal: []string{"systemctl list-unit-files: jingwei-leftover.service"},
		Unknown:        []string{"落地物 #7（at）没有可用会话，无法复核"},
	}
	out := TraceMatrixMarkdown(in)

	for _, want := range []string{
		"## 维持痕迹矩阵",
		"| 手段 | 本次落地点 | 部署后留下的痕迹 | 清除验证方式 | 结论 |",
		"cron 计划任务", "crontab:+a1b2c3",
		"已验证清除：JW_ARTIFACT_GONE",
		"未配置验证命令，无法复核：台账里没有独立的验证命令",
		"撤销之后仍然存在的痕迹", "认证日志里的登录记录",
		"账外残留（不在台账里的发现）", "jingwei-leftover.service",
		"未能复核：落地物 #7",
		"不能当成「没有残留」",
		"平台没有部署它们，也就无法声称已经清除",
		"撤销命令的退出码不作为证据",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("矩阵缺少 %q：\n%s", want, out)
		}
	}
	// 表格必须每行五列，否则 Markdown 渲染会散架。
	for i, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "| ") && strings.Count(line, "|") != 6 {
			t.Errorf("第 %d 行不是五列表格：%s", i+1, line)
		}
	}
}

func TestTraceMatrixMarkdownWithoutArtifacts(t *testing.T) {
	out := TraceMatrixMarkdown(TraceMatrixInput{})
	if !strings.Contains(out, "本轮没有登记任何维持落地物") {
		t.Fatalf("空台账应当明说没有维持手段：\n%s", out)
	}
	// 一条都没扫的时候不能写「已扫描的类别里没有发现」——那是把没做说成做了。
	if strings.Contains(out, "已扫描的类别里没有发现台账之外的持久化条目") {
		t.Fatalf("没有扫描记录时不该声称扫过：\n%s", out)
	}
}

func TestTraceMatrixMarkdownKeepsUnknownSeparateFromClean(t *testing.T) {
	out := TraceMatrixMarkdown(TraceMatrixInput{
		Rows:    []TraceMatrixRow{{Kind: "file", Name: "上传的文件", Verdict: TraceVerdictFailed, Detail: "权限不足"}},
		Unknown: []string{"落地物 #3（file）复核结果无法判定：输出里没有标记"},
	})
	if !strings.Contains(out, "撤销失败，仍在目标上：权限不足") {
		t.Fatalf("失败结论没有写出来：\n%s", out)
	}
	if !strings.Contains(out, "上面这些是**没有检查过**的部分") {
		t.Fatalf("未能复核的部分必须单独说明：\n%s", out)
	}
}

func TestTraceMatrixMarkdownEscapesPipes(t *testing.T) {
	out := TraceMatrixMarkdown(TraceMatrixInput{Rows: []TraceMatrixRow{{
		Kind: "registry", Name: "注册表自启动项",
		Landed:  []string{`HKCU\...\Run | jw-token`},
		Traces:  []string{"值名与数据都是可关联标记"},
		Verify:  "reg query 不再返回该值名",
		Verdict: TraceVerdictCleared,
	}}})
	if strings.Contains(out, "Run | jw-token") {
		t.Fatalf("单元里的竖线没有转义，表格会被撑断：\n%s", out)
	}
}
