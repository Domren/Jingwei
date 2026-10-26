package agent

// cleanupRules is a code-owned system-prompt tail for the executor. Proving a
// write-side finding (upload, RCE, account takeover) mutates the target, and a
// round that never reverts it leaves webshells and forged accounts behind —
// several Pikachu rounds did exactly that. Scoped to what this run created, so
// the agent never "cleans up" the application's own files.
//
// Rule 2 exists because one round "reverted" an upload with an HTTP DELETE, which
// the PHP server answered with 200 without removing anything, then reported the
// finding as if the target were restored.
func cleanupRules() string {
	return "\n\n【验证痕迹收尾（平台强制）】" +
		"\n1. 凡改动目标状态的验证（上传文件、RCE 落地文件、写库/改数据、建或改账号、加计划任务/启动项），在【同一意图内】验证成功后立即撤销：删除本次在目标上创建的文件、恢复被改的数据；恢复所用的命令与其输出一起记进 record_fact 的 evidence（或补进该 finding），让报告能证明目标已复原。" +
		"\n2. 撤销要走目标真正会执行的通道：用已拿到的命令执行通道删文件（rm/unlink）、应用自己的删除功能，或数据库回写。服务器不实现的动词（对静态文件发 HTTP DELETE 等）返回 200 也没有删除，不算撤销。" +
		"\n3. 撤销后必须证明：再请求该路径应 404、列目录应不再包含它、被改的数据应读回原值，把这条【撤销验证报文】一起进 evidence。证不了就在 finding 里写明残留路径与原因并标注「未清理，需人工确认」，不许静默收尾。" +
		"\n4. 只清理本次自己创建的东西：目标原有的文件、账号、数据一律不动；分不清是不是自己建的就不删，如实标注「未清理，需人工确认」。" +
		"\n5. PoC 用无害探针（id / whoami / 唯一标记文件再读回），不要留真实后门、不要写持久化、不要把真实用户数据搬到工作目录之外。"
}
