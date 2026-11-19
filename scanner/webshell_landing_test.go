package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestClassifyLandingProbe 钉住 P18 的保守口径：只有明确 404/410 判为可安全
// 投放；2xx/3xx（路径上已有内容）判为 JW_FILE_EXISTS；传输失败、鉴权墙、
// 5xx 判为 JW_FILE_UNKNOWN，且后两者都当作占用——不覆盖已授权资产。
func TestClassifyLandingProbe(t *testing.T) {
	cases := []struct {
		name     string
		ok       bool
		status   int
		marker   string
		occupied bool
	}{
		{"明确 404 可投放", true, 404, JWFileNew, false},
		{"410 可投放", true, 410, JWFileNew, false},
		{"已有文件 200", true, 200, JWFileExists, true},
		{"重定向 302 也算占用", true, 302, JWFileExists, true},
		{"鉴权墙 403 不可判定", true, 403, JWFileUnknown, true},
		{"服务端 500 不可判定", true, 500, JWFileUnknown, true},
		{"传输失败不可判定", false, 0, JWFileUnknown, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			marker, occupied := ClassifyLandingProbe(tc.ok, tc.status)
			if marker != tc.marker || occupied != tc.occupied {
				t.Fatalf("got marker=%q occupied=%v, want %q/%v", marker, occupied, tc.marker, tc.occupied)
			}
		})
	}
}

// TestProbeWebshellLanding 用桩 HTTP 服务验证探测真的会 GET 落地路径并按状态
// 返回标记，命中时不覆盖的决策由 ClassifyLandingProbe 给出——夹具把两半都钉住。
func TestProbeWebshellLanding(t *testing.T) {
	occupiedSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte("已有文件的内容"))
	}))
	defer occupiedSrv.Close()
	freeSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer freeSrv.Close()

	client := NewDeepClient(5 * time.Second)
	marker, occupied, detail := ProbeWebshellLanding(context.Background(), client, occupiedSrv.URL, nil)
	if marker != JWFileExists || !occupied {
		t.Fatalf("已有文件应命中不覆盖: marker=%q occupied=%v detail=%q", marker, occupied, detail)
	}
	marker, occupied, detail = ProbeWebshellLanding(context.Background(), client, freeSrv.URL, nil)
	if marker != JWFileNew || occupied {
		t.Fatalf("404 应判为可安全投放: marker=%q occupied=%v detail=%q", marker, occupied, detail)
	}
}
