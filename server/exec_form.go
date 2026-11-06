package server

import (
	"net/http"
	"strings"

	"github.com/Autumn-27/jingwei/scanner"
)

// execForm 把一条命令行编成 shell / argv / 单串三种语境各自的形式（E4）。
//
// 为什么放在工作台旁边：贴进 `Runtime.exec(String)` 的命令口（Java 内存马、反序列化 gadget、
// 某些只收一整串的执行口）时，`cat a | grep b` 会被切成 5 个参数，管道成了 cat 的文件名，
// 进程照样起来、退出码照样是 0，于是「这台机器上没有这个文件」这种结论被当成事实记进报告。
// 这里把「这条命令在该语境下该长成什么样」算清楚，并明确说哪条路走不通。
//
// 纯静态分析：不建任务、不发包、不碰任何目标，因此不受目标策略/授权清单约束，也不写台账。
func (s *Server) execForm(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16)
	var req struct {
		Command string `json:"command"`
		OSKind  string `json:"os_kind"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "请求格式错误")
		return
	}
	form, err := scanner.PrepareExecForm(req.Command, req.OSKind)
	if err != nil {
		// 解析不了就是「这条命令连 shell 都不会接受」，直接给人看原文，不换成套话。
		writeErr(w, 400, strings.TrimSpace(err.Error()))
		return
	}
	writeJSON(w, http.StatusOK, form)
}
