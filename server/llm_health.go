package server

import (
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// GET /api/tasks/{id}/llm-health（R21 §5.4 ⑥）
// 回答「这个任务废了几轮、每轮是怎么废的、当前是否该换链」。
// 形态抄 guard_denials：按 (status, error_class) 汇总，另带最近的轮记录
// 与首帧超时的当前配置（前端提示用）。
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

	total, failed := 0, 0
	classCount := map[string]int{}
	for _, st := range stats {
		total += st.Count
		if st.Status != "ok" {
			failed += st.Count
		}
		if st.ErrorClass != "" {
			classCount[st.ErrorClass] += st.Count
		}
	}
	failureRate := 0.0
	if total > 0 {
		failureRate = float64(failed) / float64(total)
	}

	// 废轮率阈值：超 30% 时给出「该中转端不可用」的提示（§5.4 ⑥）。
	const alarmThreshold = 0.30
	alarm := failureRate > alarmThreshold && total >= 10

	writeJSON(w, http.StatusOK, map[string]any{
		"task_id":                taskID,
		"total_rounds":           total,
		"failed_rounds":          failed,
		"failure_rate":           failureRate,
		"by_class":               classCount,
		"recent":                 recent,
		"first_event_timeout_s":  int(llmFirstEventTimeout() / time.Second),
		"alarm_unusable_gateway": alarm,
	})
}

// llmFirstEventTimeout 从 llmrec 读配置；拆开只为 server 层不直接吃包内实现细节。
func llmFirstEventTimeout() time.Duration {
	// 与 llmrec.FirstEventTimeout 同口径；为避免循环依赖（server→llmrec→db→server），
	// 这里读同一个环境变量。env 值在两边必须一致，由 envaudit 盯。
	return llmrecFirstEventTimeout()
}

// 独立成一个函数，便于夹具固定。
var llmrecFirstEventTimeout = func() time.Duration {
	// 与 llmrec.FirstEventTimeout 相同实现：JINGWEI_LLM_FIRST_EVENT_TIMEOUT。
	// 用 inline 读是刻意的：llmrec 侧不导出这个值给 server（避免 server 直接
	// 操纵 llmrec 的内部配置面）。
	if v := parseEnvDuration("JINGWEI_LLM_FIRST_EVENT_TIMEOUT"); v > 0 {
		return v
	}
	return 45 * time.Second
}

func parseEnvDuration(key string) time.Duration {
	raw := strings.TrimSpace(getenvInline(key))
	if raw == "" {
		return 0
	}
	if d, err := time.ParseDuration(raw); err == nil {
		return d
	}
	if n, err := strconv.Atoi(raw); err == nil && n > 0 {
		return time.Duration(n) * time.Second
	}
	return 0
}

// getenvInline 与 llmrec 的同名函数口径一致；拆开是为可测。
var getenvInline = func(key string) string {
	return strings.TrimSpace(os.Getenv(key))
}
