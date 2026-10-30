package agent

import (
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"
)

// 证据质量校验。
//
// 之前出现过这样的上报：evidence 写一句「真实抓包见取证截图」就完事。截图是
// 事后可补的产物，evidence 才是判定依据本身——它必须能让读报告的人在不打开
// 任何附件的情况下，看见「发了什么、回来什么、因此说明什么」。
//
// 这里做两件事：拦掉"看别处"式占位文案；要求证据有实质内容（长度 + 具体片段）。

// placeholderEvidenceRE matches stubs that only point elsewhere instead of
// carrying evidence: "见截图"、"详见报告"、"同上"、"略"、"N/A"…整段就是这一句。
var placeholderEvidenceRE = regexp.MustCompile(`(?i)^\s*(真实|本次)?(证据|完整证据|具体证据)?\s*(见|详见|请见|参见|参阅|参考)\s*(取证截图|截图|报告|复现过程|复现步骤|reproduction|proof|proofread|附件|上面|上述|前文|下文)\s*[。.!！]?\s*$|^\s*(同上|略|无|N/A|NA|none|null|nil|-{1,})\s*$`)

// minEvidenceRunes is the shortest text that can still carry a conclusion plus
// one concrete fragment. Anything shorter is a caption, not evidence.
const minEvidenceRunes = 20

// validateFindingEvidence rejects placeholder or empty evidence with a message
// the agent can act on (it is told to keep the other fields and retry).
func validateFindingEvidence(evidence string) error {
	e := strings.TrimSpace(evidence)
	if e == "" {
		return fmt.Errorf("report_finding 的 evidence 不能为空：它是报告里的判定依据，必须写清「发了什么、回来什么、因此说明什么」（关键请求行/头 + 响应状态行/片段 + 结论）。请保持其他字段不变，重新调用并补上 evidence。本次调用未登记漏洞，不会产生重复记录。")
	}
	if placeholderEvidenceRE.MatchString(e) {
		return fmt.Errorf("report_finding 的 evidence 不能是占位指向（%q）：「见截图/见报告/同上/略」这类写法不携带任何判定依据。请直接把关键请求行/头、响应状态行与命中片段贴进 evidence（真实收发的完整字节仍放 raw_request/raw_response 或 traffic_refs），并写清结论。请保持其他字段不变，重新调用并补上 evidence。本次调用未登记漏洞，不会产生重复记录。", e)
	}
	if n := utf8.RuneCountInString(e); n < minEvidenceRunes {
		return fmt.Errorf("report_finding 的 evidence 太短（%d 字）：至少要能放下关键请求/响应片段与结论。请保持其他字段不变，重新调用并补上 evidence（%d 字以上）。本次调用未登记漏洞，不会产生重复记录。", n, minEvidenceRunes)
	}
	return nil
}
