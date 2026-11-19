package guard

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Autumn-27/norma/hook"
)

// P5 验收：静态漏检样本由行为判据在 guard 调用处命中并打强制二次验证标记；
// 强制复核不改变 normal finding 判定（只产出 Message，不产出 block Decision）。

const behaviorHoneypotOutput = `HTTP 200 /api/probe
payload=/api/a success=1 elapsed_ms=0.35
payload=/api/b success=1 elapsed_ms=0.31
payload=/api/c success=1 elapsed_ms=0.33
payload=/api/d success=1 elapsed_ms=0.34`

func TestHoneypotDetectForcesRecheckOnBehavior(t *testing.T) {
	msg := honeypotDetect(behaviorHoneypotOutput)
	if msg == "" {
		t.Fatal("行为蜜罐应触发提示")
	}
	if !strings.Contains(msg, "强制二次验证") {
		t.Fatalf("缺强制复核标记: %s", msg)
	}
}

func TestHoneypotDetectNormalOutputUnaffected(t *testing.T) {
	normal := `HTTP 200 /api/probe
payload=/api/a success=1 elapsed_ms=12
payload=/api/b success=0 elapsed_ms=43 noise="500 error"
payload=/api/c success=1 elapsed_ms=31`
	if msg := honeypotDetect(normal); msg != "" {
		t.Fatalf("正常输出不应触发蜜罐提示: %s", msg)
	}
}

func TestPostToolUseBehaviorDoesNotBlockFindings(t *testing.T) {
	g := New()
	res := g.postToolUse(context.Background(), hook.Event{
		ToolName: "Bash",
		Result:   json.RawMessage(behaviorHoneypotOutput),
	})
	if res.Decision == "block" {
		t.Fatalf("强制复核不得阻断工具/finding: %+v", res)
	}
	if !strings.Contains(res.Message, "强制二次验证") {
		t.Fatalf("缺复核标记: %+v", res)
	}
	// 失败归因不受影响：行为提示不写 attrib，也不会把分类改成 blocked。
	if attrs := g.Attributions(); attrs["blocked"] != 0 {
		t.Fatalf("行为提示误改失败归因: %+v", attrs)
	}
}
