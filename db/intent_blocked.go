package db

import "strings"

// 意图 blocked 原因的枚举（1.6.2 排期第 3 步）。
//
// 背景（2026-11-11 实测，任务 #4）：91 条意图里 **blocked 40 条，`blocked_reason` 全空**。
// 根因不是「忘了写」，而是写入口径：`SetIntentBlockedReason` 只在「LLM 配额」
// 这一种情况下被调用，而三处泛型状态写入（SetNodeState / SetIntentState /
// CompareAndSetIntentState）一律 `blocked_reason=NULL`——**经由泛型路径转成
// blocked 的意图，原因被硬置空**。
//
// 后果不是显示问题：
//   - R19 要回答的「为什么还没完」在库里答不出；
//   - `ReopenIntentsByBlockedReason` 按原因重开的那条路对这 40 条完全无效
//     （它们没有可匹配的原因）。
//
// 修法（本文件 + 三处写入口）：转 blocked 必须带原因，且原因必须是下面枚举之一；
// 转其它状态时才清空。存量数据由迁移统一标 `unknown` 并可筛。
const (
	// IntentBlockedLLMQuota LLM 配额/余额耗尽：等账户充值或换 profile。
	IntentBlockedLLMQuota = "llm_quota_exhausted"
	// IntentBlockedLLMUnavailable 端点不可用（不可达/模型名不支持/账户失效）：
	// 与配额不同，这类要改配置而不是充值。
	IntentBlockedLLMUnavailable = "llm_unavailable"
	// IntentBlockedOutOfScope 目标不在授权范围内（确定性拒绝，重试无收益）。
	IntentBlockedOutOfScope = "out_of_scope"
	// IntentBlockedGuardDenied 被出站守卫拦下（同站门/资产禁令/失败关闭）。
	IntentBlockedGuardDenied = "guard_denied"
	// IntentBlockedAssetMissing 依赖的资产已被删除或不再属于本任务。
	IntentBlockedAssetMissing = "asset_missing"
	// IntentBlockedPrereqMissing 前置条件不满足（需要凭据/需要先完成另一条意图）。
	IntentBlockedPrereqMissing = "prereq_missing"
	// IntentBlockedSuperseded 已被后续意图取代（例如同洞已由另一条覆盖）。
	IntentBlockedSuperseded = "superseded"
	// IntentBlockedBudget 预算/轮数到限（R19 的闸门触发）。
	IntentBlockedBudget = "budget_exhausted"
	// IntentBlockedTaskStopped 任务被暂停/删除/超时收尾，非意图自身失败。
	IntentBlockedTaskStopped = "task_stopped"
	// IntentBlockedUnknown 存量回填用：原因当时没记，现在也推不出来。
	// 明确标出来比留空好——空值会被误读成「没原因」，unknown 会被读成
	// 「这条历史数据的原因丢失了」，后者才是事实。
	IntentBlockedUnknown = "unknown"
)

// IntentBlockedReasons 是全部合法原因，供校验、前端筛选与测试共用。
//
// 顺序即前端下拉的展示顺序：先「要人动手」的，再「系统自动」的，最后 unknown。
var IntentBlockedReasons = []string{
	IntentBlockedLLMQuota,
	IntentBlockedLLMUnavailable,
	IntentBlockedOutOfScope,
	IntentBlockedGuardDenied,
	IntentBlockedAssetMissing,
	IntentBlockedPrereqMissing,
	IntentBlockedBudget,
	IntentBlockedTaskStopped,
	IntentBlockedSuperseded,
	IntentBlockedUnknown,
}

// IntentBlockedReasonLabel 给前端与报告用的中文名。
var IntentBlockedReasonLabel = map[string]string{
	IntentBlockedLLMQuota:       "LLM 配额/余额耗尽",
	IntentBlockedLLMUnavailable: "LLM 端点不可用",
	IntentBlockedOutOfScope:     "目标不在授权范围",
	IntentBlockedGuardDenied:    "被出站守卫拦下",
	IntentBlockedAssetMissing:   "依赖资产已不存在",
	IntentBlockedPrereqMissing:  "前置条件不满足",
	IntentBlockedBudget:         "预算/轮数到限",
	IntentBlockedTaskStopped:    "任务已停止",
	IntentBlockedSuperseded:     "已被后续意图取代",
	IntentBlockedUnknown:        "原因未记录（历史数据）",
}

// NormalizeIntentBlockedReason 把调用方给的原因收敛到枚举。
//
// 空值不是「合法空」而是缺陷：返回 false，由调用方决定是报错还是回落 unknown。
// 这样「忘记传」在编码期就会被夹具抓住，而不是等到一个月后查台账才发现。
func NormalizeIntentBlockedReason(raw string) (string, bool) {
	r := strings.ToLower(strings.TrimSpace(raw))
	if r == "" {
		return "", false
	}
	for _, known := range IntentBlockedReasons {
		if r == known {
			return r, true
		}
	}
	// 允许调用方传语义近似的别名，落到最近的枚举上——比直接失败更实用，
	// 但**不**接受空值或无法归类的值（那会重新制造「原因不明」）。
	switch r {
	case "quota", "quota_exhausted", "insufficient_quota", "billing":
		return IntentBlockedLLMQuota, true
	case "llm_down", "unreachable", "model_not_found", "account_invalid", "endpoint_unavailable":
		return IntentBlockedLLMUnavailable, true
	case "scope", "not_in_scope", "unauthorized_target":
		return IntentBlockedOutOfScope, true
	case "guard", "denied", "blocked_by_guard":
		return IntentBlockedGuardDenied, true
	case "asset_gone", "no_asset":
		return IntentBlockedAssetMissing, true
	case "prereq", "missing_prereq", "needs_credential":
		return IntentBlockedPrereqMissing, true
	case "budget", "max_rounds", "max_tokens", "cost_limit":
		return IntentBlockedBudget, true
	case "stopped", "paused", "task_ended":
		return IntentBlockedTaskStopped, true
	case "dup", "duplicate", "replaced":
		return IntentBlockedSuperseded, true
	}
	return "", false
}

// IsKnownIntentBlockedReason 判断是否枚举内（前端筛选与迁移校验用）。
func IsKnownIntentBlockedReason(raw string) bool {
	_, ok := NormalizeIntentBlockedReason(raw)
	return ok
}

// errInvalidBlockedReason 是严格校验失败时的错误（供 MustNormalizeIntentBlockedReason）。
type errInvalidBlockedReason string

func (e errInvalidBlockedReason) Error() string {
	return "blocked_reason 必须是已登记的原因枚举之一，实得 " + string(e) +
		"（可选值：" + strings.Join(IntentBlockedReasons, "/") + "）"
}

// BackfillIntentBlockedReasons 把「已 blocked 但原因为空」的存量意图标成 unknown。
//
// 为什么不猜原因：40 条里可能有各种成因（守卫拒绝、资产丢失、预算到限），
// 靠现在的库推不出来。标 unknown 是**如实登记的缺口**——它可被筛选出来，
// 「这一条原因丢了」是事实；留空则会被读成「这条没有原因」，那是假的。
//
// 幂等：只改 blocked_reason IS NULL 的行，重复执行不会再动任何数据。
// 返回本次实际回填的行数（首次执行 40 左右，之后恒为 0）。
func (d *DB) BackfillIntentBlockedReasons() (int64, error) {
	res, err := d.Exec(`UPDATE exploration_nodes
SET blocked_reason=$1
WHERE kind='intent' AND state='blocked' AND COALESCE(blocked_reason,'')=''`, IntentBlockedUnknown)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// IntentBlockedReasonStat 是「按原因分布」的一行，供台账与 /api 用。
type IntentBlockedReasonStat struct {
	Reason string `json:"reason"`
	Label  string `json:"label"`
	Count  int    `json:"count"`
	// Empty 标记这一行是「原因为空」的异常项：回填后应该恒为 0，
	// 不为 0 就说明还有别的写入口在绕过枚举（这正是本条的验收判据）。
	Empty bool `json:"empty,omitempty"`
}

// IntentBlockedReasonStats 返回某任务（taskID<=0 时全表）的 blocked 原因分布。
//
// 判据④「blocked 且原因为空 = 0」直接读这个函数的 Empty 行。
func (s *ExplorationStore) IntentBlockedReasonStats() ([]IntentBlockedReasonStat, error) {
	rows, err := s.db.Query(`SELECT COALESCE(blocked_reason,''), COUNT(*)
FROM exploration_nodes
WHERE exploration_id=$1 AND kind='intent' AND state='blocked'
GROUP BY COALESCE(blocked_reason,'') ORDER BY 2 DESC`, s.expID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []IntentBlockedReasonStat{}
	for rows.Next() {
		var st IntentBlockedReasonStat
		if err := rows.Scan(&st.Reason, &st.Count); err != nil {
			return nil, err
		}
		if st.Reason == "" {
			st.Empty = true
			st.Label = "原因为空（缺陷）"
		} else {
			st.Label = IntentBlockedReasonLabel[st.Reason]
			if st.Label == "" {
				st.Label = st.Reason
			}
		}
		out = append(out, st)
	}
	return out, rows.Err()
}
