package server

// RCE 阶梯验证任务的执行侧（P9）。
//
// 阶梯授权的唯一裁决者是 guard.RCEGate 代码闸门（入队前）。这里在执行侧再做一次
// 纯函数复核，防止任务在队列里被改过 params 后绕过授权。本任务只负责记录「本次获
// 授权的级别」；它不伪造命令回显、不生成 payload，也不会把未观测到的执行结果写成
// confirmed。真正的命令下发由操作员在已授权范围内另行完成。

import (
	"strconv"

	"github.com/Domren/jingwei/guard"
)

// runVerifyRCE 复核入队前已裁决的阶梯参数，并把授权结论写进 summary。
// 任何跳级如果在入队后变得不合法（例如操作员中途关闭了某级），这里都会把任务判失败，
// 保证「代码闸门」在排队场景下也不会被时间差绕过。
func (r *deepRun) runVerifyRCE(summary map[string]any) (string, string, string, map[string]any) {
	cfg, achieved, requested := guard.RCELevelFromParams(r.task.Params)
	action, reason := guard.EvaluateRCELevel(cfg, achieved, requested)
	summary["rce_level"] = requested
	summary["rce_level_name"] = guard.RCELevelName(requested)
	summary["rce_achieved"] = achieved
	summary["rce_switches"] = map[string]bool{
		"callback": cfg.Callback,
		"harmless": cfg.Harmless,
		"read":     cfg.Read,
		"write":    cfg.Write,
	}
	summary["rce_ladder"] = "回连证明 → 无害命令 → 读文件 → 写文件（逐级授权，跳级须人工审批）"
	if action != guard.RCEAllow {
		// 入队前应由闸门拦下；走到这里说明任务被直接创建或参数被改，拒绝执行。
		summary["rce_note"] = "阶梯复核未通过：" + reason
		r.logf("run", "RCE 阶梯复核未通过：%s", reason)
		return "failed", "failed", reason, summary
	}
	summary["rce_note"] = "代码闸门已授权第 " + strconv.Itoa(requested) + " 级（" + guard.RCELevelName(requested) +
		"）；本任务仅记录授权结论，未执行任何命令、未生成 payload。"
	r.logf("run", "RCE 阶梯已授权第 %d 级（%s）", requested, guard.RCELevelName(requested))
	return "done", "done", "", summary
}
