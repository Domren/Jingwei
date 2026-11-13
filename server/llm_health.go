package server

import (
	"net/http"
	"strings"
	"time"

	"github.com/Autumn-27/jingwei/llmrec"
)

// GET /api/tasks/{id}/llm-health（R21 §5.4 ⑥）
// 回答「这个任务废了几轮、每轮是怎么废的、当前是否该换链」。
// 形态抄 guard_denials：按 (status, error_class) 汇总，另带最近的轮记录
// 与首帧超时的当前配置（前端提示用）。
//
// 2026-11-12 改（R21 缺口②）：告警判据不再要求 `total>=10`。原判据让任务开局
// 每轮即废时「该响的不响」（任务 #5 实测 failure_rate=1 / alarm=false），
// 而靠心跳攒到 10 轮要两小时——告警的意义全在头两分钟。新判据只看「连续失败」：
// 首轮就不可达、或连续 2 轮全废，立刻响。
func (s *Server) taskLLMHealth(w http.ResponseWriter, r *http.Request) {
	taskID := strings.TrimSpace(r.PathValue("id"))
	if taskID == "" {
		writeErr(w, http.StatusBadRequest, "缺少任务 ID")
		return
	}
	ctx := r.Context()
	stats, err := s.m.pg.LLMRoundStatsByTask(ctx, taskID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	recent, err := s.m.pg.ListLLMRoundsByTask(ctx, taskID, 20)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	consecutive, err := s.m.pg.ConsecutiveFailedRounds(ctx, taskID)
	if err != nil {
		// 连续失败数拿不到时不影响其余字段；按 0 处理会让告警偏保守，
		// 但下面的「在飞/首轮」判据仍然有效。
		consecutive = 0
	}

	total, failed, running := 0, 0, 0
	classCount := map[string]int{}
	for _, st := range stats {
		switch st.Status {
		case "running":
			// 在飞的轮既不是成功也不是失败：单独计数，不进废轮率分母。
			running += st.Count
			continue
		case "ok":
			total++
		default:
			total++
			failed++
		}
		if st.ErrorClass != "" {
			classCount[st.ErrorClass] += st.Count
		}
	}
	failureRate := 0.0
	if total > 0 {
		failureRate = float64(failed) / float64(total)
	}

	// 告警判据（与总轮数无关，所以端点一坏就生效）：
	//   - 连续失败 ≥2 轮：确定是持续性问题，不是偶发抖动；
	//   - 首轮即失败且失败类是「不可自愈」的（账户/模型名/不可达）：立刻响。
	// 后者覆盖「任务刚开跑、库里只有 1 行」这个原判据完全看不见的窗口。
	alarm, alarmReason := llmAlarm(total, consecutive, classCount)

	writeJSON(w, http.StatusOK, map[string]any{
		"task_id":                taskID,
		"total_rounds":           total,
		"failed_rounds":          failed,
		"running_rounds":         running,
		"failure_rate":           failureRate,
		"consecutive_failures":   consecutive,
		"by_class":               classCount,
		"recent":                 recent,
		"first_event_timeout_s":  int(llmFirstEventTimeout() / time.Second),
		"alarm_unusable_gateway": alarm,
		"alarm_reason":           alarmReason,
	})
}

// llmAlarm 是告警判据。返回是否告警与一句人话原因（前端直接显示）。
//
// 抽成纯函数是为了让夹具能穷举窗口：任务开局、偶发失败、端点全废、恢复中。
func llmAlarm(total, consecutive int, byClass map[string]int) (bool, string) {
	if total == 0 {
		return false, ""
	}
	if consecutive >= 2 {
		return true, "连续 " + itoa(consecutive) + " 轮失败，该端点当前不可用"
	}
	// 首轮即废，且失败类不会自愈：不必等第二轮。
	if total == 1 && consecutive == 1 {
		for _, c := range []string{
			string(llmrec.ErrClassUnreachable),
			string(llmrec.ErrClassAccountInvalid),
			string(llmrec.ErrClassModelNotFound),
		} {
			if byClass[c] > 0 {
				return true, "首轮即失败（" + c + "），这类错误不会自愈，先修配置再跑"
			}
		}
	}
	return false, ""
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

// llmFirstEventTimeout 从 llmrec 读配置（唯一解析口径，缺口⑩）。
// 先前 server 侧另有一份「纯数字按秒」的解析，与 llmrec 的 ParseDuration
// 不一致，同一个环境变量会得到两个答案。现在两边共用 llmrec.ParseTimeoutValue。
func llmFirstEventTimeout() time.Duration {
	return llmrec.FirstEventTimeout()
}
