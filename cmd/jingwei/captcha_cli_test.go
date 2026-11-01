package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"image"
	"image/color"
	"image/png"
	"strings"
	"testing"
)

func captchaCLITestImages(t *testing.T) (string, string) {
	t.Helper()
	bg := image.NewRGBA(image.Rect(0, 0, 200, 100))
	for y := 0; y < 100; y++ {
		for x := 0; x < 200; x++ {
			v := uint8(40 + x)
			bg.SetRGBA(x, y, color.RGBA{v, v, v, 255})
		}
	}
	for y := 35; y < 65; y++ {
		for x := 120; x < 150; x++ {
			bg.SetRGBA(x, y, color.RGBA{10, 10, 10, 255})
		}
	}
	piece := image.NewRGBA(image.Rect(0, 0, 30, 30))
	for y := 0; y < 30; y++ {
		for x := 0; x < 30; x++ {
			v := uint8(40 + 120 + x)
			piece.SetRGBA(x, y, color.RGBA{v, v, v, 255})
		}
	}
	encode := func(img image.Image) string {
		var buf bytes.Buffer
		if err := png.Encode(&buf, img); err != nil {
			t.Fatal(err)
		}
		return base64.StdEncoding.EncodeToString(buf.Bytes())
	}
	return encode(bg), encode(piece)
}

func TestCaptchaSolveCommand(t *testing.T) {
	bg, piece := captchaCLITestImages(t)
	req, _ := json.Marshal(captchaSolveRequest{
		Background: bg,
		Piece:      piece,
		Track:      true,
		TrackSeed:  7,
	})
	var out bytes.Buffer
	if code := runCaptchaSolveCommand(nil, bytes.NewReader(req), &out); code != 0 {
		t.Fatalf("exit code = %d", code)
	}
	var resp captchaSolveResponse
	if err := json.Unmarshal(out.Bytes(), &resp); err != nil {
		t.Fatalf("invalid JSON %q: %v", out.String(), err)
	}
	if !resp.OK {
		t.Fatalf("solve failed: %s", resp.Error)
	}
	if resp.Offset < 118 || resp.Offset > 122 {
		t.Fatalf("offset = %d, want ~120", resp.Offset)
	}
	if len(resp.Track) == 0 {
		t.Fatal("track not returned")
	}
	last := resp.Track[len(resp.Track)-1]
	if last.X != resp.Distance {
		t.Fatalf("track ends at %d, distance %d", last.X, resp.Distance)
	}
}

func TestCaptchaSolveCommandRejectsBadInput(t *testing.T) {
	var out bytes.Buffer
	if code := runCaptchaSolveCommand(nil, strings.NewReader("{"), &out); code != 0 {
		t.Fatalf("exit code = %d", code)
	}
	if !strings.Contains(out.String(), `"ok":false`) {
		t.Fatalf("unexpected response: %s", out.String())
	}
	out.Reset()
	if code := runCaptchaSolveCommand([]string{"extra"}, strings.NewReader("{}"), &out); code != 0 {
		t.Fatalf("exit code = %d", code)
	}
	if !strings.Contains(out.String(), "不接受额外参数") {
		t.Fatalf("unexpected response: %s", out.String())
	}
}
