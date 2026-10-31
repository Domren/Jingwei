package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/Autumn-27/jingwei/captcha"
	actool "github.com/Autumn-27/norma/tool"
)

const (
	maxSliderCaptchaBody  = 24 << 20
	maxSliderCaptchaImage = 20 << 20
)

type sliderCaptchaInput struct {
	Background      string `json:"background"`
	Piece           string `json:"piece"`
	InitialX        int    `json:"initial_x"`
	MinOffset       int    `json:"min_offset"`
	MaxOffset       int    `json:"max_offset"`
	Track           bool   `json:"track"`
	TrackPoints     int    `json:"track_points"`
	TrackDurationMS int    `json:"track_duration_ms"`
	TrackSeed       int64  `json:"track_seed"`
}

func (in sliderCaptchaInput) validate() error {
	if strings.TrimSpace(in.Background) == "" {
		return errors.New("background 不能为空")
	}
	if strings.TrimSpace(in.Piece) == "" {
		return errors.New("piece 不能为空")
	}
	if in.InitialX < 0 {
		return errors.New("initial_x 不能为负")
	}
	if in.MinOffset < 0 || in.MaxOffset < 0 {
		return errors.New("min_offset / max_offset 不能为负")
	}
	if in.MaxOffset > 0 && in.MaxOffset < in.MinOffset {
		return errors.New("max_offset 不能小于 min_offset")
	}
	return nil
}

func (in sliderCaptchaInput) solveOptions() captcha.SolveOptions {
	return captcha.SolveOptions{InitialX: in.InitialX, MinOffset: in.MinOffset, MaxOffset: in.MaxOffset}
}

type sliderCaptchaResponse struct {
	captcha.SolveResult
	Track []captcha.TrackPoint `json:"track,omitempty"`
}

func buildSliderCaptchaResponse(res captcha.SolveResult, in sliderCaptchaInput) sliderCaptchaResponse {
	out := sliderCaptchaResponse{SolveResult: res}
	if in.Track {
		out.Track = captcha.HumanTrack(res.Distance, captcha.TrackOptions{
			DurationMS: in.TrackDurationMS,
			Points:     in.TrackPoints,
			Seed:       in.TrackSeed,
		})
	}
	return out
}

// solveSliderCaptcha is the shared image-only endpoint: any JWT-authenticated
// caller (UI, agent bridge, external script) posts two base64 images and gets
// the gap coordinate plus an optional drag track.
func (s *Server) solveSliderCaptcha(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxSliderCaptchaBody)
	var in sliderCaptchaInput
	if err := decode(r, &in); err != nil {
		writeErr(w, 400, "请求格式错误或内容超过 24MB")
		return
	}
	if err := in.validate(); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	background, err := captcha.DecodeDataURL(in.Background)
	if err != nil {
		writeErr(w, 400, "背景图无效: "+err.Error())
		return
	}
	piece, err := captcha.DecodeDataURL(in.Piece)
	if err != nil {
		writeErr(w, 400, "滑块图无效: "+err.Error())
		return
	}
	res, err := captcha.SolveSlider(background, piece, in.solveOptions())
	if err != nil {
		writeErr(w, 422, err.Error())
		return
	}
	writeJSON(w, 200, buildSliderCaptchaResponse(res, in))
}

// loadSliderCaptchaImage accepts a data URL / base64 string, or a local file
// path for agent workflows that already saved a fetched image to disk. The HTTP
// endpoint deliberately does not accept paths.
func loadSliderCaptchaImage(raw string) ([]byte, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return nil, errors.New("图片数据为空")
	}
	if !strings.HasPrefix(strings.ToLower(s), "data:") {
		if fi, err := os.Stat(s); err == nil && fi.Mode().IsRegular() {
			if fi.Size() > maxSliderCaptchaImage {
				return nil, fmt.Errorf("图片文件过大: %d 字节", fi.Size())
			}
			return os.ReadFile(s)
		}
	}
	return captcha.DecodeDataURL(s)
}

// toolSolveSliderCaptcha exposes the solver to LLM agents so captcha handling is
// a reusable platform capability, not a one-off inside webcrack.
func (s *Server) toolSolveSliderCaptcha() actool.CoreTool {
	return roTool("solve_slider_captcha",
		"求解图片型滑块验证码：传入背景图（带缺口）与滑块图，返回缺口坐标 offset、需要拖动的距离 distance（已减去 initial_x）、缺口 y 与置信度；可选生成拟人拖动轨迹（x/y/时间戳）。纯本地图像计算，不联网。图片支持 data URL / base64，agent 也可传本机已落盘的文件路径。仅用于已授权目标，不得用于绕过平台自身门禁。",
		objSchema(map[string]any{
			"background":        strParam("背景图：data URL、base64，或本机文件路径"),
			"piece":             strParam("滑块图：data URL、base64，或本机文件路径"),
			"initial_x":         map[string]any{"type": "integer", "description": "滑块在认证控件中可见的左边缘 x 像素（可选，默认 0）"},
			"min_offset":        map[string]any{"type": "integer", "description": "缺口搜索的最小 x（可选）"},
			"max_offset":        map[string]any{"type": "integer", "description": "缺口搜索的最大 x（可选，0 表示不限制）"},
			"track":             map[string]any{"type": "boolean", "description": "是否生成拟人拖动轨迹，默认 false"},
			"track_points":      map[string]any{"type": "integer", "description": "轨迹点数，8-80，默认随机"},
			"track_duration_ms": map[string]any{"type": "integer", "description": "拖动总时长毫秒，250-5000，默认随机"},
			"track_seed":        map[string]any{"type": "integer", "description": "轨迹随机种子（可选，便于复现）"},
		}, "background", "piece"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a sliderCaptchaInput
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf("参数格式错误: " + err.Error()), nil
			}
			if err := a.validate(); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			background, err := loadSliderCaptchaImage(a.Background)
			if err != nil {
				return actool.Errorf("背景图无效: " + err.Error()), nil
			}
			piece, err := loadSliderCaptchaImage(a.Piece)
			if err != nil {
				return actool.Errorf("滑块图无效: " + err.Error()), nil
			}
			res, err := captcha.SolveSlider(background, piece, a.solveOptions())
			if err != nil {
				return actool.Errorf("求解失败: " + err.Error()), nil
			}
			return jsonResult(buildSliderCaptchaResponse(res, a))
		})
}
