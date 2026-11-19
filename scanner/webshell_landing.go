package scanner

import (
	"context"
	"net/http"
	"strconv"
)

// 部署前冲突检测的落地探测标记，沿用内网上传里 test -e 的 JW_FILE_EXISTS /
// JW_FILE_NEW 口径，外加 JW_FILE_UNKNOWN 表达「探测不可判定」。
const (
	JWFileExists  = "JW_FILE_EXISTS"
	JWFileNew     = "JW_FILE_NEW"
	JWFileUnknown = "JW_FILE_UNKNOWN"
)

// ClassifyLandingProbe 把一次落地路径探测的 HTTP 结果归类成标记与是否占用。
// 纯函数，便于夹具覆盖所有分支而不依赖真实目标。
//
// 口径偏保守：只有明确的 404/410 才判为「新路径、可安全投放」；任何其它
// 2xx/3xx（路径上已有内容在响应）判为 JW_FILE_EXISTS，传输失败、鉴权墙、
// 服务端错误等判为 JW_FILE_UNKNOWN——两者都当作「占用」，先不覆盖、转人工。
// 理由：写得起这个路径的已授权资产，一旦被我们覆盖就无法自动恢复。
func ClassifyLandingProbe(transportOK bool, statusCode int) (marker string, occupied bool) {
	if !transportOK || statusCode <= 0 {
		return JWFileUnknown, true
	}
	switch {
	case statusCode == http.StatusNotFound || statusCode == http.StatusGone:
		return JWFileNew, false
	case statusCode >= 200 && statusCode < 400:
		return JWFileExists, true
	default:
		// 401/403/5xx 等：既不能证明有文件，也不能证明没有，保守当作占用。
		return JWFileUnknown, true
	}
}

// ProbeWebshellLanding 在注入前对落地地址发一次 GET，判断路径是否已被占用。
// 返回的 marker 与 ClassifyLandingProbe 一致，detail 用于落冲突记录/报人工。
func ProbeWebshellLanding(ctx context.Context, c *DeepClient, landURL string, headers map[string]string) (marker string, occupied bool, detail string) {
	resp := c.Do(ctx, DeepRequest{Method: http.MethodGet, URL: landURL, Headers: headers})
	marker, occupied = ClassifyLandingProbe(resp.OK(), resp.StatusCode)
	detail = "落地探测 " + landURL + "：标记=" + marker + "，HTTP=" + strconv.Itoa(resp.StatusCode)
	if resp.Error != "" {
		detail += "，传输错误=" + resp.Error
	}
	return marker, occupied, detail
}
