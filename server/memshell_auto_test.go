package server

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// E3：不传 type 时应进入自动选型流程（而不是在校验阶段被当成非法 type 拒掉），
// 显式传非法 type 仍必须早拒。这里不依赖数据库，靠「数据源未连接」的 503
// 证明请求已经走过参数校验进入自动选型分支。
func TestDeployJavaMemshellAutoTypeAccepted(t *testing.T) {
	s := &Server{ctx: context.Background(), m: &Manager{}}

	post := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/deep/webshells/1/memshells",
			bytes.NewBufferString(body))
		req.SetPathValue("id", "1")
		rec := httptest.NewRecorder()
		s.deployJavaMemshell(rec, req)
		return rec
	}

	auto := post(`{"name":"auto-ms"}`)
	if auto.Code == http.StatusBadRequest && strings.Contains(auto.Body.String(), "type 必须是") {
		t.Fatalf("缺省 type 应走自动选型，被参数校验拒绝: %s", auto.Body.String())
	}
	if auto.Code != http.StatusServiceUnavailable {
		t.Fatalf("缺省 type 应到数据源检查才停，实际 %d %s", auto.Code, auto.Body.String())
	}

	bad := post(`{"type":"memshell"}`)
	if bad.Code != http.StatusBadRequest || !strings.Contains(bad.Body.String(), "type 必须是") {
		t.Fatalf("非法 type 应早拒，实际 %d %s", bad.Code, bad.Body.String())
	}

	explicit := post(`{"type":"filter"}`)
	if explicit.Code == http.StatusBadRequest && strings.Contains(explicit.Body.String(), "type 必须是") {
		t.Fatalf("合法显式 type 被拒: %s", explicit.Body.String())
	}
}
