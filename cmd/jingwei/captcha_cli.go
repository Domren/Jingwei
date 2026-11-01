package main

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/Autumn-27/jingwei/captcha"
)

// captchaSolveRequest is the JSON envelope the WebCrack bridge (and any local
// helper) uses to call the solver without embedding an image pipeline in
// Python. Images are passed as base64/data URLs, never as file paths, so a
// target-controlled page cannot make this command read local files.
type captchaSolveRequest struct {
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

type captchaSolveResponse struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
	captcha.SolveResult
	Track []captcha.TrackPoint `json:"track,omitempty"`
}

const captchaSolveMaxInput = 24 << 20

// runCaptchaSolveCommand maps one JSON request on stdin to one JSON response on
// stdout. It always exits 0 after emitting a response: an unsolvable image is a
// normal tool outcome, not a process failure.
func runCaptchaSolveCommand(args []string, stdin io.Reader, stdout io.Writer) int {
	var resp captchaSolveResponse
	enc := json.NewEncoder(stdout)
	if len(args) != 0 {
		resp.Error = "captcha-solve 不接受额外参数"
		_ = enc.Encode(resp)
		return 0
	}
	var req captchaSolveRequest
	dec := json.NewDecoder(io.LimitReader(stdin, captchaSolveMaxInput+1))
	if err := dec.Decode(&req); err != nil {
		resp.Error = fmt.Sprintf("解析请求失败: %v", err)
		_ = enc.Encode(resp)
		return 0
	}
	background, err := captcha.DecodeDataURL(req.Background)
	if err != nil {
		resp.Error = "背景图: " + err.Error()
		_ = enc.Encode(resp)
		return 0
	}
	piece, err := captcha.DecodeDataURL(req.Piece)
	if err != nil {
		resp.Error = "滑块图: " + err.Error()
		_ = enc.Encode(resp)
		return 0
	}
	answer, err := captcha.SolveSlider(background, piece, captcha.SolveOptions{
		InitialX:  req.InitialX,
		MinOffset: req.MinOffset,
		MaxOffset: req.MaxOffset,
	})
	if err != nil {
		resp.Error = err.Error()
		_ = enc.Encode(resp)
		return 0
	}
	resp.OK = true
	resp.SolveResult = answer
	if req.Track {
		resp.Track = captcha.HumanTrack(answer.Distance, captcha.TrackOptions{
			DurationMS: req.TrackDurationMS,
			Points:     req.TrackPoints,
			Seed:       req.TrackSeed,
		})
	}
	_ = enc.Encode(resp)
	return 0
}
