package server

import "strings"

// 本文件把「平台在目标机上投递的脚本」按 shell 族拆成纯构造函数。
//
// 背景（R3）：上传/下载/权限维持/撤销的脚本原先散落在执行路径里直接拼字符串，
// 只能在真机或进程内 SSH 靶机上才能观察到「到底生成了什么语法」。R3 的缺口是
// PowerShell 会话上生成的脚本究竟是不是 PS 语法——没有夹具就没有证据。
//
// 约束：这里的函数只拼字符串，不执行、不读库、不依赖 Server。执行路径必须调用
// 它们，测试直接断言它们的输出。这样「构造」与「投递」共用同一份实现，测试
// 断言的也就是线上真正发出去的东西。
//
// 两个族的分界线由 powershellCmdScriptReason 定义：cmd 族脚本必然命中该守卫，
// PS 族脚本必然不命中。intranet_script_family_test.go 正反两例钉住这条线。

// ── cmd.exe 族 ───────────────────────────────────────────────────────────────

// intranetCmdExistsProbeCmd 上传前探测目标是否已存在。
func intranetCmdExistsProbeCmd(target string) string {
	return "if exist " + target + " (echo JW_FILE_EXISTS) else (echo JW_FILE_NEW)"
}

// intranetCmdUploadChunkCmd 分块写入 base64 文本；first 为真时覆盖，否则追加。
//
// 用 `<nul set /p="chunk">>` 而不是 `echo chunk>>`：cmd 对紧邻 `>>` 的尾随
// 数字有句柄重定向语义，真机（Win11 22631，2026-11-14 R3 批 B）实测
// `echo QUJDR4>>f` 落盘 9 字节「QUJDR4 +空格+CRLF」——echo 与重定向之间被
// cmd 插入空格。set /p 的提示符无尾随换行也无空格，且 chunk 被引号括住，
// 尾数字与 `>>` 之间隔着引号，句柄语义不触发。
// 代价：`<nul` 喂空输入时 set /p 置 ERRORLEVEL=1，会把整个 `(cmd) & call
// echo __JW_EC__%^ERRORLEVEL%` trailer 误标为失败——所以末尾显式
// `cmd /c exit 0` 归零（与 wmi 撤销命令同一处理）。
//
// 注意：1MB 多块上传全 400 的主根因不在本函数，而是块大小非 3 的倍数导致
// 各块编码的 '=' padding 落在拼接流中间（certutil 拒收 0x8007000d），见
// intranetWindowsUploadChunk 的注释与本文件的 r3_batchb 夹具；echo 空格
// 是当时一并观测到的伴生 bug。
func intranetCmdUploadChunkCmd(chunk, b64Temp string, first bool) string {
	op := ">>"
	if first {
		op = ">"
	}
	return `(<nul set /p="` + chunk + `"` + op + b64Temp + `) & cmd /c exit 0`
}

// intranetCmdDecodeCmd certutil 解码 base64 文本为二进制。
func intranetCmdDecodeCmd(b64Temp, binTemp string) string {
	return "certutil -decode -f " + b64Temp + " " + binTemp
}

// intranetCmdMoveCmd 用解码结果覆盖目标文件。
func intranetCmdMoveCmd(binTemp, target string) string {
	return "move /y " + binTemp + " " + target
}

// intranetCmdCleanupCmd 清理上传临时文件。
func intranetCmdCleanupCmd(paths ...string) string {
	return "del /f /q " + strings.Join(paths, " ")
}

// intranetWindowsRevokeVerifyCmd cmd 会话下上传落地物的撤销与验证命令。
// del 幂等：目标已被外部删除时也要能走完撤销；cmd 内建 echo 不重置 ERRORLEVEL，
// 末尾显式归零。
func intranetWindowsRevokeVerifyCmd(quoted string) (revoke, verify string) {
	revoke = "del /f /q " + quoted + " >nul 2>&1 & echo " + intranetArtifactOK + " & cmd /c exit 0"
	verify = "(if exist " + quoted + " (echo " + intranetArtifactPresent +
		") else (echo " + intranetArtifactGone + ")) & cmd /c exit 0"
	return revoke, verify
}

// ── PowerShell 族 ────────────────────────────────────────────────────────────

// intranetPSAppendChunkCmd 追加一段 base64 文本，不经过 cmd.exe。
func intranetPSAppendChunkCmd(b64Temp, chunk string) string {
	return `[IO.File]::AppendAllText(` + intranetPSQuote(b64Temp) + `, ` + intranetPSQuote(chunk) +
		`, [Text.Encoding]::ASCII); Write-Output 'JW_PS_APPEND_OK'`
}

// intranetPSRemoveCmd 清理临时文件；文件不存在时不报错。
func intranetPSRemoveCmd(path string) string {
	return "Remove-Item -Force " + intranetPSQuote(path) +
		" -ErrorAction SilentlyContinue; Write-Output 'JW_CLEANUP_OK'"
}

// intranetPSWriteDecodedCmd 明文传输：base64 解码后直接覆盖目标。
func intranetPSWriteDecodedCmd(target, b64Temp string) string {
	return `[IO.File]::WriteAllBytes(` + intranetPSQuote(target) +
		`, [Convert]::FromBase64String([Text.Encoding]::ASCII.GetString([IO.File]::ReadAllBytes(` +
		intranetPSQuote(b64Temp) + `)))); Write-Output 'JW_PS_WRITE_OK'`
}

// intranetPSWriteGzipCmd gzip 传输：PS 原生解压后覆盖目标。
func intranetPSWriteGzipCmd(target, b64Temp string) string {
	var b strings.Builder
	b.WriteString(`$gz=[Convert]::FromBase64String([Text.Encoding]::ASCII.GetString([IO.File]::ReadAllBytes(` +
		intranetPSQuote(b64Temp) + `)));`)
	b.WriteString(`$ms=New-Object IO.MemoryStream(,$gz);`)
	b.WriteString(`$gzst=New-Object IO.Compression.GZipStream($ms,[IO.Compression.CompressionMode]::Decompress);`)
	b.WriteString(`$out=New-Object IO.MemoryStream;$gzst.CopyTo($out);`)
	b.WriteString(`[IO.File]::WriteAllBytes(` + intranetPSQuote(target) + `,$out.ToArray());`)
	b.WriteString(`Write-Output 'JW_PS_GZIP_OK'`)
	return b.String()
}

// intranetWindowsPSRevokeVerifyCmd PowerShell 会话下上传落地物的撤销与验证命令。
func intranetWindowsPSRevokeVerifyCmd(path string) (revoke, verify string) {
	revoke = `Remove-Item -Force -LiteralPath ` + intranetPSQuote(path) +
		` -ErrorAction SilentlyContinue; Write-Output '` + intranetArtifactOK + `'`
	verify = `if (Test-Path -LiteralPath ` + intranetPSQuote(path) +
		`) { '` + intranetArtifactPresent + `' } else { '` + intranetArtifactGone + `' }`
	return revoke, verify
}
