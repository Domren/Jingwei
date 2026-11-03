package server

import (
	"bytes"
	crand "crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"math/big"
	mrand "math/rand/v2"
	"net/http"
	"sync"
	"time"

	"github.com/Autumn-27/jingwei/captcha"
)

const (
	sliderWidth        = 320
	sliderHeight       = 160
	sliderPieceSize    = 48
	sliderTolerance    = 6
	sliderChallengeTTL = 3 * time.Minute
	sliderMaxPending   = 4096
	sliderCaptchaRate  = 30 // issues per client IP per minute
)

// sliderChallenge never leaves the server: only the id and images are sent to
// the browser. The answer is consumed exactly once, and a challenge is bound to
// the address that requested it so a solved image cannot be passed around.
type sliderChallenge struct {
	id        string
	answerX   int
	pieceY    int
	expires   time.Time
	clientIP  string
	width     int
	height    int
	pieceSize int
}

type sliderChallengeStore struct {
	mu    sync.Mutex
	items map[string]*sliderChallenge
	now   func() time.Time
}

func (s *sliderChallengeStore) clock() time.Time {
	if s.now != nil {
		return s.now()
	}
	return time.Now()
}

func (s *sliderChallengeStore) put(c *sliderChallenge) bool {
	now := s.clock()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.items == nil {
		s.items = map[string]*sliderChallenge{}
	}
	for id, item := range s.items {
		if !now.Before(item.expires) {
			delete(s.items, id)
		}
	}
	if len(s.items) >= sliderMaxPending {
		return false
	}
	s.items[c.id] = c
	return true
}

// consume deletes the challenge before checking the answer, so a failed or
// repeated submission can never be replayed against the same puzzle.
func (s *sliderChallengeStore) consume(id, ip string, x int) bool {
	if id == "" {
		return false
	}
	now := s.clock()
	s.mu.Lock()
	c := s.items[id]
	delete(s.items, id)
	s.mu.Unlock()
	if c == nil || !now.Before(c.expires) || c.clientIP != ip {
		return false
	}
	diff := x - c.answerX
	if diff < 0 {
		diff = -diff
	}
	return diff <= sliderTolerance
}

func randomHex(bytesLen int) (string, error) {
	buf := make([]byte, bytesLen)
	if _, err := crand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func randomRange(lo, hi int) (int, error) {
	if hi <= lo {
		return lo, nil
	}
	n, err := crand.Int(crand.Reader, big.NewInt(int64(hi-lo)))
	if err != nil {
		return 0, err
	}
	return lo + int(n.Int64()), nil
}

func clampByte(v int) uint8 {
	if v < 0 {
		return 0
	}
	if v > 255 {
		return 255
	}
	return uint8(v)
}

func mix(a, b uint8, t float64) uint8 {
	return clampByte(int(float64(a) + (float64(b)-float64(a))*t))
}

// blendPixel applies src over dst. Colours are kept opaque; only alpha controls
// how strongly an overlay shape covers the texture underneath.
func blendPixel(img *image.RGBA, x, y int, src color.RGBA) {
	if !image.Pt(x, y).In(img.Bounds()) {
		return
	}
	i := img.PixOffset(x, y)
	a := float64(src.A) / 255
	img.Pix[i+0] = clampByte(int(float64(src.R)*a + float64(img.Pix[i+0])*(1-a)))
	img.Pix[i+1] = clampByte(int(float64(src.G)*a + float64(img.Pix[i+1])*(1-a)))
	img.Pix[i+2] = clampByte(int(float64(src.B)*a + float64(img.Pix[i+2])*(1-a)))
	img.Pix[i+3] = 255
}

func fillCircle(img *image.RGBA, cx, cy, radius int, c color.RGBA) {
	for y := cy - radius; y <= cy+radius; y++ {
		for x := cx - radius; x <= cx+radius; x++ {
			dx, dy := x-cx, y-cy
			if dx*dx+dy*dy <= radius*radius {
				blendPixel(img, x, y, c)
			}
		}
	}
}

func drawLine(img *image.RGBA, x0, y0, x1, y1 int, c color.RGBA) {
	dx := x1 - x0
	if dx < 0 {
		dx = -dx
	}
	dy := y1 - y0
	if dy < 0 {
		dy = -dy
	}
	sx, sy := 1, 1
	if x0 > x1 {
		sx = -1
	}
	if y0 > y1 {
		sy = -1
	}
	err := dx - dy
	for {
		blendPixel(img, x0, y0, c)
		if x0 == x1 && y0 == y1 {
			return
		}
		e2 := 2 * err
		if e2 > -dy {
			err -= dy
			x0 += sx
		}
		if e2 < dx {
			err += dx
			y0 += sy
		}
	}
}

func strokeRect(img *image.RGBA, x, y, w, h, width int, c color.RGBA) {
	for i := 0; i < width; i++ {
		for xx := x + i; xx < x+w-i; xx++ {
			blendPixel(img, xx, y+i, c)
			blendPixel(img, xx, y+h-1-i, c)
		}
		for yy := y + i; yy < y+h-i; yy++ {
			blendPixel(img, x+i, yy, c)
			blendPixel(img, x+w-1-i, yy, c)
		}
	}
}

func randomUint64() uint64 {
	var b [8]byte
	if _, err := crand.Read(b[:]); err != nil {
		return uint64(time.Now().UnixNano())
	}
	return binary.LittleEndian.Uint64(b[:])
}

func drawSliderBackground(img *image.RGBA) {
	rng := mrand.New(mrand.NewPCG(randomUint64(), randomUint64()))
	base := [3]int{20 + rng.IntN(70), 30 + rng.IntN(80), 60 + rng.IntN(90)}
	base2 := [3]int{60 + rng.IntN(110), 40 + rng.IntN(100), 90 + rng.IntN(110)}
	for y := 0; y < sliderHeight; y++ {
		for x := 0; x < sliderWidth; x++ {
			t := float64(x+y) / float64(sliderWidth+sliderHeight)
			n := rng.IntN(18) - 9
			img.SetRGBA(x, y, color.RGBA{
				R: clampByte(int(float64(base[0])+(float64(base2[0])-float64(base[0]))*t) + n),
				G: clampByte(int(float64(base[1])+(float64(base2[1])-float64(base[1]))*t) + n),
				B: clampByte(int(float64(base[2])+(float64(base2[2])-float64(base[2]))*t) + n),
				A: 255,
			})
		}
	}
	for i := 0; i < 24; i++ {
		fillCircle(img, rng.IntN(sliderWidth), rng.IntN(sliderHeight), 8+rng.IntN(34), color.RGBA{
			R: uint8(rng.IntN(256)), G: uint8(rng.IntN(256)), B: uint8(rng.IntN(256)), A: uint8(28 + rng.IntN(54)),
		})
	}
	for i := 0; i < 7; i++ {
		drawLine(img, rng.IntN(sliderWidth), rng.IntN(sliderHeight), rng.IntN(sliderWidth), rng.IntN(sliderHeight),
			color.RGBA{R: uint8(rng.IntN(256)), G: uint8(rng.IntN(256)), B: uint8(rng.IntN(256)), A: uint8(45 + rng.IntN(45))})
	}
}

type sliderPuzzle struct {
	challenge  *sliderChallenge
	background string
	piece      string
}

// sliderRender is one drawing pass: the notch position plus the two images the
// browser will see.
type sliderRender struct {
	answerX, pieceY   int
	background, piece string
}

// sliderPuzzleAttempts bounds how often newSliderPuzzle redraws before it ships
// an unverified puzzle.
const sliderPuzzleAttempts = 4

// newSliderPuzzle cuts an opaque square straight out of a textured background,
// then draws a visible gap in the place it came from. The piece therefore both
// fits the gap outline and carries the original texture, which keeps the
// puzzle solvable by a human and by the platform's own slider solver.
//
// "Solvable" is now checked instead of assumed. On a cluttered draw the outline
// and content signals can both prefer a different spot — measured roughly one
// puzzle in sixty — and a notch the reference solver cannot locate is a notch a
// legitimate user may not see either, which locks that client IP out until the
// challenge expires. Redrawing is bounded because refusing to issue a captcha
// would lock everyone out over one unlucky draw.
func newSliderPuzzle(ip string) (*sliderPuzzle, error) {
	id, err := randomHex(24)
	if err != nil {
		return nil, err
	}
	var out sliderRender
	for attempt := 0; attempt < sliderPuzzleAttempts; attempt++ {
		out, err = renderSliderPuzzle()
		if err != nil {
			return nil, err
		}
		if sliderPuzzleSolvable(out) {
			break
		}
	}
	return &sliderPuzzle{
		challenge: &sliderChallenge{
			id:        id,
			answerX:   out.answerX,
			pieceY:    out.pieceY,
			expires:   time.Now().Add(sliderChallengeTTL),
			clientIP:  ip,
			width:     sliderWidth,
			height:    sliderHeight,
			pieceSize: sliderPieceSize,
		},
		background: out.background,
		piece:      out.piece,
	}, nil
}

// renderSliderPuzzle draws one candidate. It carries no memory of earlier
// attempts, so newSliderPuzzle can redraw until the notch is unambiguous.
func renderSliderPuzzle() (sliderRender, error) {
	var out sliderRender
	answerX, err := randomRange(sliderPieceSize+24, sliderWidth-sliderPieceSize-16)
	if err != nil {
		return out, err
	}
	pieceY, err := randomRange(24, sliderHeight-sliderPieceSize-16)
	if err != nil {
		return out, err
	}
	bg := image.NewRGBA(image.Rect(0, 0, sliderWidth, sliderHeight))
	// Fill the full canvas first: SetRGBA on a zero-value RGBA image leaves
	// transparent pixels, which would make the piece cutout look like a hole.
	draw.Draw(bg, bg.Bounds(), &image.Uniform{C: color.RGBA{A: 255}}, image.Point{}, draw.Src)
	drawSliderBackground(bg)

	pieceImg := image.NewRGBA(image.Rect(0, 0, sliderPieceSize, sliderPieceSize))
	draw.Draw(pieceImg, pieceImg.Bounds(), bg, image.Pt(answerX, pieceY), draw.Src)

	gap := image.Rect(answerX, pieceY, answerX+sliderPieceSize, pieceY+sliderPieceSize)
	// Keep most of the original texture inside the gap: the piece then matches
	// the background strongly when correctly placed. The frame, not a heavy
	// dark fill, is what makes the target visible to the user.
	draw.Draw(bg, gap, &image.Uniform{C: color.RGBA{R: 8, G: 12, B: 24, A: 40}}, image.Point{}, draw.Over)
	strokeRect(bg, answerX-3, pieceY-3, sliderPieceSize+6, sliderPieceSize+6, 2, color.RGBA{R: 10, G: 16, B: 30, A: 170})
	strokeRect(bg, answerX-1, pieceY-1, sliderPieceSize+2, sliderPieceSize+2, 2, color.RGBA{R: 235, G: 245, B: 255, A: 230})

	backgroundURL, err := encodePNGDataURL(bg)
	if err != nil {
		return out, err
	}
	pieceURL, err := encodePNGDataURL(pieceImg)
	if err != nil {
		return out, err
	}
	out.answerX, out.pieceY = answerX, pieceY
	out.background, out.piece = backgroundURL, pieceURL
	return out, nil
}

// sliderPuzzleSolvable asks the platform's own slider solver where the notch is
// and accepts the drawing only when the answer lands inside the tolerance the
// login form itself will grant.
func sliderPuzzleSolvable(draw sliderRender) bool {
	bgBytes, err := captcha.DecodeDataURL(draw.background)
	if err != nil {
		return false
	}
	pieceBytes, err := captcha.DecodeDataURL(draw.piece)
	if err != nil {
		return false
	}
	res, err := captcha.SolveSlider(bgBytes, pieceBytes, captcha.SolveOptions{})
	if err != nil {
		return false
	}
	delta := res.Offset - draw.answerX
	if delta < 0 {
		delta = -delta
	}
	return delta <= sliderTolerance
}

func encodePNGDataURL(img image.Image) (string, error) {
	var buf bytes.Buffer
	enc := png.Encoder{CompressionLevel: png.BestSpeed}
	if err := enc.Encode(&buf, img); err != nil {
		return "", err
	}
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}

type sliderChallengeResponse struct {
	ID         string `json:"id"`
	Background string `json:"background"`
	Piece      string `json:"piece"`
	Width      int    `json:"width"`
	Height     int    `json:"height"`
	PieceX     int    `json:"piece_x"`
	PieceY     int    `json:"piece_y"`
	PieceSize  int    `json:"piece_size"`
	MaxX       int    `json:"max_x"`
	ExpiresIn  int    `json:"expires_in"`
}

// GET /api/auth/captcha — issues a one-shot slider puzzle for the login and
// first-run setup forms. No token is needed, but issuance is per-IP capped.
func (s *Server) authCaptcha(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	ip := clientIP(r)
	if ok, retry := s.captchaRate.allow("captcha:"+ip, sliderCaptchaRate, time.Minute); !ok {
		writeRateLimited(w, retry, "验证码请求过于频繁，请稍后重试")
		return
	}
	puzzle, err := newSliderPuzzle(ip)
	if err != nil {
		writeErr(w, 500, "验证码生成失败")
		return
	}
	if !s.captchaStore.put(puzzle.challenge) {
		writeErr(w, 429, "验证码请求过多，请稍后重试")
		return
	}
	c := puzzle.challenge
	writeJSON(w, 200, sliderChallengeResponse{
		ID:         c.id,
		Background: puzzle.background,
		Piece:      puzzle.piece,
		Width:      c.width,
		Height:     c.height,
		PieceX:     0,
		PieceY:     c.pieceY,
		PieceSize:  c.pieceSize,
		MaxX:       c.width - c.pieceSize,
		ExpiresIn:  int(time.Until(c.expires).Seconds()),
	})
}

func validateCaptcha(s *Server, r *http.Request, id string, x int) bool {
	return s.captchaStore.consume(id, clientIP(r), x)
}
