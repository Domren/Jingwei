package captcha

import (
	"bytes"
	"encoding/base64"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"math"
	"math/rand"
	"reflect"
	"testing"
)

// smoothImage builds a deterministic low-frequency background: a coarse random
// grid bilinearly interpolated to pixels. Gradients are smooth everywhere, so a
// test can isolate the content signal from edge texture.
func smoothImage(w, h int, seed int64) *image.RGBA {
	const cell = 8
	rng := rand.New(rand.NewSource(seed))
	gw, gh := w/cell+2, h/cell+2
	grid := make([]float64, gw*gh)
	for i := range grid {
		grid[i] = 28 + rng.Float64()*200
	}
	at := func(x, y int) float64 { return grid[y*gw+x] }
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		fy := float64(y) / cell
		y0 := int(fy)
		ty := fy - float64(y0)
		for x := 0; x < w; x++ {
			fx := float64(x) / cell
			x0 := int(fx)
			tx := fx - float64(x0)
			top := at(x0, y0)*(1-tx) + at(x0+1, y0)*tx
			bottom := at(x0, y0+1)*(1-tx) + at(x0+1, y0+1)*tx
			v := uint8(math.Round(top*(1-ty) + bottom*ty))
			img.SetRGBA(x, y, color.RGBA{R: v, G: v, B: v, A: 255})
		}
	}
	return img
}

func encodePNG(t *testing.T, img image.Image) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatalf("png encode: %v", err)
	}
	return buf.Bytes()
}

func cropRGBA(src *image.RGBA, x0, y0, w, h int) *image.RGBA {
	out := image.NewRGBA(image.Rect(0, 0, w, h))
	draw.Draw(out, out.Bounds(), src, image.Pt(x0, y0), draw.Src)
	return out
}

// The dominant signal of a real slider captcha: the background has a gap whose
// outline matches the piece outline. The piece here is a shape with a bite, and
// the gap is carved with the same shape at a known offset.
func TestSolveSliderFindsGap(t *testing.T) {
	bg := smoothImage(240, 120, 7)
	const pw, ph = 40, 40
	const tx, ty = 97, 35

	piece := image.NewRGBA(image.Rect(0, 0, pw, ph))
	for y := 0; y < ph; y++ {
		for x := 0; x < pw; x++ {
			if x >= 27 && y < 9 {
				continue // transparent bite
			}
			piece.SetRGBA(x, y, color.RGBA{R: 210, G: 90, B: 40, A: 255})
		}
	}
	for y := ty; y < ty+ph; y++ {
		for x := tx; x < tx+pw; x++ {
			if x-tx >= 27 && y-ty < 9 {
				continue
			}
			bg.SetRGBA(x, y, color.RGBA{R: 10, G: 10, B: 10, A: 255})
		}
	}

	res, err := SolveSlider(encodePNG(t, bg), encodePNG(t, piece),
		SolveOptions{MinOffset: 50, MaxOffset: 180, InitialX: 20})
	if err != nil {
		t.Fatalf("solve: %v", err)
	}
	if absInt(res.Offset-tx) > 2 || absInt(res.Y-ty) > 2 {
		t.Fatalf("offset = (%d,%d), want (%d,%d) within 2px", res.Offset, res.Y, tx, ty)
	}
	if res.Distance != res.Offset-20 {
		t.Errorf("distance = %d, want offset-initial_x = %d", res.Distance, res.Offset-20)
	}
	if res.BackgroundWidth != 240 || res.BackgroundHeight != 120 || res.PieceWidth != pw || res.PieceHeight != ph {
		t.Errorf("sizes = %dx%d piece %dx%d", res.BackgroundWidth, res.BackgroundHeight, res.PieceWidth, res.PieceHeight)
	}
	if res.Confidence < 0 || res.Confidence > 1 {
		t.Errorf("confidence out of range: %v", res.Confidence)
	}
}

// The other signal: the piece is a pixel crop of the background (many captchas
// slice the puzzle out and show it separately). No artificial gap exists, so
// only the content match can locate it.
func TestSolveSliderMatchesContent(t *testing.T) {
	bg := smoothImage(200, 100, 11)
	const pw = 30
	const tx, ty = 77, 21
	piece := cropRGBA(bg, tx, ty, pw, pw)

	res, err := SolveSlider(encodePNG(t, bg), encodePNG(t, piece), SolveOptions{})
	if err != nil {
		t.Fatalf("solve: %v", err)
	}
	if absInt(res.Offset-tx) > 2 || absInt(res.Y-ty) > 2 {
		t.Fatalf("offset = (%d,%d), want (%d,%d) within 2px (score %.3f)", res.Offset, res.Y, tx, ty, res.Score)
	}
	if res.PieceWidth != pw || res.PieceHeight != pw {
		t.Errorf("piece = %dx%d, want %dx%d", res.PieceWidth, res.PieceHeight, pw, pw)
	}
}

func TestSolveSliderRespectsSearchRange(t *testing.T) {
	bg := smoothImage(200, 100, 23)
	const pw = 30
	const tx, ty = 60, 30
	piece := cropRGBA(bg, tx, ty, pw, pw)

	res, err := SolveSlider(encodePNG(t, bg), encodePNG(t, piece),
		SolveOptions{MinOffset: 58, MaxOffset: 80})
	if err != nil {
		t.Fatalf("solve: %v", err)
	}
	if res.Offset < 58 || res.Offset > 80 {
		t.Errorf("offset = %d, outside [58, 80]", res.Offset)
	}

	if _, err := SolveSlider(encodePNG(t, bg), encodePNG(t, piece),
		SolveOptions{MinOffset: 180}); err == nil {
		t.Error("expected error when MinOffset exceeds the available width")
	}
}

func TestSolveSliderErrors(t *testing.T) {
	bg := smoothImage(60, 60, 3)
	piece := cropRGBA(bg, 10, 10, 20, 20)

	if _, err := SolveSlider([]byte("not an image"), encodePNG(t, piece), SolveOptions{}); err == nil {
		t.Error("expected error for invalid background")
	} else if !bytes.Contains([]byte(err.Error()), []byte("背景图")) {
		t.Errorf("error = %v, want background prefix", err)
	}
	if _, err := SolveSlider(encodePNG(t, bg), []byte("not an image"), SolveOptions{}); err == nil {
		t.Error("expected error for invalid piece")
	} else if !bytes.Contains([]byte(err.Error()), []byte("滑块图")) {
		t.Errorf("error = %v, want piece prefix", err)
	}

	big := smoothImage(80, 80, 4)
	if _, err := SolveSlider(encodePNG(t, bg), encodePNG(t, big), SolveOptions{}); err == nil {
		t.Error("expected error when piece is larger than background")
	}

	tiny := image.NewRGBA(image.Rect(0, 0, 4, 4))
	if _, err := SolveSlider(encodePNG(t, tiny), encodePNG(t, tiny), SolveOptions{}); err == nil {
		t.Error("expected error for too-small image")
	}
}

func TestDecodeDataURL(t *testing.T) {
	raw := []byte("\x89PNG\r\n\x1a\nfake-image-body")
	std := base64.StdEncoding.EncodeToString(raw)
	cases := []string{
		"data:image/png;base64," + std,
		"data:image/png;base64," + std[:4] + "\n" + std[4:],
		"  " + std + " ",
		base64.RawStdEncoding.EncodeToString(raw),
		base64.URLEncoding.EncodeToString(raw),
		base64.RawURLEncoding.EncodeToString(raw),
	}
	for i, c := range cases {
		got, err := DecodeDataURL(c)
		if err != nil {
			t.Errorf("case %d: %v", i, err)
			continue
		}
		if !bytes.Equal(got, raw) {
			t.Errorf("case %d: decoded bytes differ", i)
		}
	}
	for _, bad := range []string{"", "data:image/png,abc", "!!!", "data:image/png;base64"} {
		if _, err := DecodeDataURL(bad); err == nil {
			t.Errorf("expected error for %q", bad)
		}
	}
}

func TestHumanTrack(t *testing.T) {
	if got := HumanTrack(0, TrackOptions{}); len(got) != 1 || got[0] != (TrackPoint{}) {
		t.Fatalf("distance 0 = %+v, want a single zero point", got)
	}
	if got := HumanTrack(-5, TrackOptions{}); len(got) != 1 || got[0].X != 0 {
		t.Fatalf("negative distance = %+v", got)
	}

	const distance = 150
	tr := HumanTrack(distance, TrackOptions{DurationMS: 800, Points: 24, Seed: 42})
	if len(tr) != 24 {
		t.Fatalf("points = %d, want 24", len(tr))
	}
	if tr[0] != (TrackPoint{X: 0, Y: tr[0].Y, T: 0}) || tr[0].T != 0 {
		t.Errorf("first point = %+v", tr[0])
	}
	last := tr[len(tr)-1]
	if last.X != distance || last.T != 800 {
		t.Errorf("last point = %+v, want x=%d t=800", last, distance)
	}
	maxX := 0
	for i, p := range tr {
		if i > 0 && p.T <= tr[i-1].T {
			t.Errorf("timestamps not increasing at %d: %+v", i, p)
		}
		if p.X < 0 || p.X > distance+5 {
			t.Errorf("x out of range at %d: %d", i, p.X)
		}
		if absInt(p.Y) > 2 {
			t.Errorf("y jitter too large at %d: %d", i, p.Y)
		}
		if p.X > maxX {
			maxX = p.X
		}
	}
	if maxX <= distance {
		t.Errorf("expected an overshoot beyond %d, max x = %d", distance, maxX)
	}

	if again := HumanTrack(distance, TrackOptions{DurationMS: 800, Points: 24, Seed: 42}); !reflect.DeepEqual(tr, again) {
		t.Error("same seed must produce the same track")
	}
	if other := HumanTrack(distance, TrackOptions{DurationMS: 800, Points: 24, Seed: 43}); reflect.DeepEqual(tr, other) {
		t.Error("different seeds should produce different tracks")
	}
}

func TestHumanTrackShortDistanceHasNoOvershoot(t *testing.T) {
	tr := HumanTrack(20, TrackOptions{DurationMS: 400, Points: 12, Seed: 7})
	for i := 1; i < len(tr); i++ {
		if tr[i].X < tr[i-1].X {
			t.Fatalf("short track should be monotonic: %+v", tr)
		}
	}
	if tr[len(tr)-1].X != 20 {
		t.Errorf("last x = %d, want 20", tr[len(tr)-1].X)
	}
}
