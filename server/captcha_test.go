package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"image"
	"image/color"
	"image/png"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Autumn-27/jingwei/captcha"
)

func testSliderBackground(t *testing.T) (bg, piece []byte, gapX, gapY int) {
	t.Helper()
	const w, h = 200, 100
	const px, py, ps = 60, 30, 30

	background := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			background.SetRGBA(x, y, color.RGBA{R: 120, G: 120, B: 120, A: 255})
		}
	}
	for y := py; y < py+ps; y++ {
		for x := px; x < px+ps; x++ {
			background.SetRGBA(x, y, color.RGBA{R: 20, G: 20, B: 20, A: 255})
		}
	}
	slider := image.NewRGBA(image.Rect(0, 0, ps, ps))
	for y := 0; y < ps; y++ {
		for x := 0; x < ps; x++ {
			slider.SetRGBA(x, y, color.RGBA{R: 180, G: 180, B: 180, A: 255})
		}
	}

	var bgBuf, pieceBuf bytes.Buffer
	if err := png.Encode(&bgBuf, background); err != nil {
		t.Fatal(err)
	}
	if err := png.Encode(&pieceBuf, slider); err != nil {
		t.Fatal(err)
	}
	return bgBuf.Bytes(), pieceBuf.Bytes(), px, py
}

func sliderDataURL(raw []byte) string {
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(raw)
}

func TestSolveSliderCaptchaHandler(t *testing.T) {
	bg, piece, gapX, gapY := testSliderBackground(t)
	body, err := json.Marshal(map[string]any{
		"background":        sliderDataURL(bg),
		"piece":             base64.StdEncoding.EncodeToString(piece),
		"initial_x":         10,
		"track":             true,
		"track_points":      16,
		"track_duration_ms": 500,
		"track_seed":        1,
	})
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	(&Server{}).solveSliderCaptcha(w, httptest.NewRequest("POST", "/api/captcha/slider", bytes.NewReader(body)))
	if w.Code != 200 {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	var out struct {
		captcha.SolveResult
		Track []captcha.TrackPoint `json:"track"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if abs(out.Offset-gapX) > 2 || abs(out.Y-gapY) > 2 {
		t.Errorf("offset = (%d,%d), want (%d,%d) within 2px", out.Offset, out.Y, gapX, gapY)
	}
	if out.Distance != out.Offset-10 {
		t.Errorf("distance = %d, want offset-10 = %d", out.Distance, out.Offset-10)
	}
	if out.BackgroundWidth != 200 || out.BackgroundHeight != 100 || out.PieceWidth != 30 {
		t.Errorf("sizes = %dx%d piece %d", out.BackgroundWidth, out.BackgroundHeight, out.PieceWidth)
	}
	if len(out.Track) != 16 {
		t.Fatalf("track points = %d, want 16", len(out.Track))
	}
	if last := out.Track[len(out.Track)-1]; last.X != out.Distance || last.T != 500 {
		t.Errorf("last track point = %+v, want x=%d t=500", last, out.Distance)
	}
}

func TestSolveSliderCaptchaHandlerRejectsBadInput(t *testing.T) {
	bg, piece, _, _ := testSliderBackground(t)
	cases := []struct {
		name string
		body map[string]any
		want int
	}{
		{"missing images", map[string]any{}, 400},
		{"negative initial_x", map[string]any{"background": sliderDataURL(bg), "piece": sliderDataURL(piece), "initial_x": -1}, 400},
		{"inverted range", map[string]any{"background": sliderDataURL(bg), "piece": sliderDataURL(piece), "min_offset": 100, "max_offset": 50}, 400},
		{"bad piece", map[string]any{"background": sliderDataURL(bg), "piece": "data:image/png;base64,!!!"}, 400},
		{"piece larger than background", map[string]any{"background": sliderDataURL(encodeTestImage(t, 40, 40)), "piece": sliderDataURL(encodeTestImage(t, 60, 60))}, 422},
	}
	for _, c := range cases {
		body, _ := json.Marshal(c.body)
		w := httptest.NewRecorder()
		(&Server{}).solveSliderCaptcha(w, httptest.NewRequest("POST", "/api/captcha/slider", bytes.NewReader(body)))
		if w.Code != c.want {
			t.Errorf("%s: status = %d, want %d (body %s)", c.name, w.Code, c.want, w.Body.String())
		}
	}
}

func encodeTestImage(t *testing.T, w, h int) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			img.SetRGBA(x, y, color.RGBA{R: 90, G: 90, B: 90, A: 255})
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestSolveSliderCaptchaToolReadsFileAndBase64(t *testing.T) {
	bg, piece, gapX, _ := testSliderBackground(t)
	bgPath := filepath.Join(t.TempDir(), "bg.png")
	if err := os.WriteFile(bgPath, bg, 0o600); err != nil {
		t.Fatal(err)
	}
	in, err := json.Marshal(map[string]any{
		"background":        bgPath,
		"piece":             sliderDataURL(piece),
		"track":             true,
		"track_points":      12,
		"track_duration_ms": 400,
		"track_seed":        3,
	})
	if err != nil {
		t.Fatal(err)
	}
	res, err := (&Server{}).toolSolveSliderCaptcha().Call(context.Background(), in, nil)
	if err != nil {
		t.Fatalf("tool call: %v", err)
	}
	if res.IsError {
		t.Fatalf("tool error: %s", res.Flatten())
	}
	var out struct {
		Offset   int                  `json:"offset"`
		Distance int                  `json:"distance"`
		Track    []captcha.TrackPoint `json:"track"`
	}
	if err := json.Unmarshal([]byte(res.Flatten()), &out); err != nil {
		t.Fatalf("decode tool result: %v (%s)", err, res.Flatten())
	}
	if abs(out.Offset-gapX) > 2 {
		t.Errorf("offset = %d, want %d within 2px", out.Offset, gapX)
	}
	if out.Distance != out.Offset {
		t.Errorf("distance = %d, want %d with initial_x 0", out.Distance, out.Offset)
	}
	if len(out.Track) != 12 || out.Track[len(out.Track)-1].X != out.Distance {
		t.Errorf("track = %+v", out.Track)
	}

	if _, err := loadSliderCaptchaImage(bgPath); err != nil {
		t.Errorf("load file: %v", err)
	}
	if _, err := loadSliderCaptchaImage(sliderDataURL(piece)); err != nil {
		t.Errorf("load data URL: %v", err)
	}
	if _, err := loadSliderCaptchaImage(""); err == nil {
		t.Error("expected error for empty image input")
	}
}

func TestSliderCaptchaToolIsSeeded(t *testing.T) {
	found := false
	for _, name := range []string{"solve_slider_captcha"} {
		for _, tool := range (&Server{}).deepTools() {
			if tool.Name() == name {
				found = true
				if !strings.Contains(tool.Description(), "滑块") {
					t.Errorf("%s description = %q", name, tool.Description())
				}
			}
		}
	}
	if !found {
		t.Error("solve_slider_captcha is not registered in deepTools()")
	}
}

func abs(v int) int {
	if v < 0 {
		return -v
	}
	return v
}
