// Package captcha solves image-based slider captchas. It locates the gap in a
// background image for a given puzzle piece and renders a human-like drag
// track, using only the images themselves. Any caller can reuse it: the scan
// baseline, a deep-use flow, or an agent tool.
package captcha

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"math"
	"math/rand"
	"sort"
	"strings"
	"time"
)

const (
	// MaxImageSide / MaxImagePixels bound the work and memory one request can
	// trigger. Slider captchas are small; a page screenshot is the largest input
	// worth accepting.
	MaxImageSide   = 4096
	MaxImagePixels = 4 << 20
)

// SolveOptions tunes the search. InitialX is the visible left edge of the
// piece in the captcha UI; when set, Distance = Offset - InitialX.
type SolveOptions struct {
	InitialX  int
	MinOffset int
	MaxOffset int
}

// SolveResult is the gap location in background-image coordinates.
type SolveResult struct {
	Offset           int     `json:"offset"`
	Distance         int     `json:"distance"`
	Y                int     `json:"y"`
	Confidence       float64 `json:"confidence"`
	Score            float64 `json:"score"`
	BackgroundWidth  int     `json:"background_width"`
	BackgroundHeight int     `json:"background_height"`
	PieceWidth       int     `json:"piece_width"`
	PieceHeight      int     `json:"piece_height"`
	ElapsedMS        int64   `json:"elapsed_ms"`
}

// TrackOptions controls the generated drag path. Zero values pick a natural
// duration and point count.
type TrackOptions struct {
	DurationMS int
	Points     int
	Seed       int64
}

// TrackPoint is one mouse sample: position and time offset in milliseconds.
type TrackPoint struct {
	X int `json:"x"`
	Y int `json:"y"`
	T int `json:"t"`
}

// DecodeDataURL accepts a data URL or bare base64 (standard or URL-safe).
func DecodeDataURL(raw string) ([]byte, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return nil, errors.New("空图片数据")
	}
	if strings.HasPrefix(strings.ToLower(s), "data:") {
		comma := strings.IndexByte(s, ',')
		if comma < 0 {
			return nil, errors.New("data URL 缺少逗号")
		}
		if !strings.Contains(strings.ToLower(s[:comma]), ";base64") {
			return nil, errors.New("仅支持 base64 编码的 data URL")
		}
		s = s[comma+1:]
	}
	s = strings.Map(func(r rune) rune {
		switch r {
		case ' ', '\n', '\r', '\t':
			return -1
		}
		return r
	}, s)
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding,
	} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, nil
		}
	}
	return nil, errors.New("base64 解码失败")
}

func decodeImage(raw []byte) (image.Image, error) {
	if len(raw) == 0 {
		return nil, errors.New("空图片数据")
	}
	img, _, err := image.Decode(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("解码图片失败（支持 PNG/JPEG/GIF）: %w", err)
	}
	b := img.Bounds()
	w, h := b.Dx(), b.Dy()
	if w < 8 || h < 8 {
		return nil, fmt.Errorf("图片尺寸过小: %dx%d", w, h)
	}
	if w > MaxImageSide || h > MaxImageSide || w*h > MaxImagePixels {
		return nil, fmt.Errorf("图片尺寸过大: %dx%d", w, h)
	}
	return img, nil
}

type grayImage struct {
	w, h int
	pix  []float64
}

func toGray(img image.Image) *grayImage {
	b := img.Bounds()
	g := &grayImage{w: b.Dx(), h: b.Dy(), pix: make([]float64, b.Dx()*b.Dy())}
	for y := 0; y < b.Dy(); y++ {
		for x := 0; x < b.Dx(); x++ {
			r, gg, bb, _ := img.At(b.Min.X+x, b.Min.Y+y).RGBA()
			g.pix[y*g.w+x] = 0.299*float64(r>>8) + 0.587*float64(gg>>8) + 0.114*float64(bb>>8)
		}
	}
	return g
}

func boxBlur(g *grayImage) *grayImage {
	out := &grayImage{w: g.w, h: g.h, pix: make([]float64, len(g.pix))}
	for y := 0; y < g.h; y++ {
		for x := 0; x < g.w; x++ {
			var sum float64
			var n int
			for dy := -1; dy <= 1; dy++ {
				yy := y + dy
				if yy < 0 || yy >= g.h {
					continue
				}
				for dx := -1; dx <= 1; dx++ {
					xx := x + dx
					if xx < 0 || xx >= g.w {
						continue
					}
					sum += g.pix[yy*g.w+xx]
					n++
				}
			}
			out.pix[y*g.w+x] = sum / float64(n)
		}
	}
	return out
}

func gradient(g *grayImage) *grayImage {
	out := &grayImage{w: g.w, h: g.h, pix: make([]float64, len(g.pix))}
	for y := 0; y < g.h; y++ {
		y0, y1 := y-1, y+1
		if y0 < 0 {
			y0 = 0
		}
		if y1 >= g.h {
			y1 = g.h - 1
		}
		for x := 0; x < g.w; x++ {
			x0, x1 := x-1, x+1
			if x0 < 0 {
				x0 = 0
			}
			if x1 >= g.w {
				x1 = g.w - 1
			}
			gx := g.pix[y*g.w+x1] - g.pix[y*g.w+x0]
			gy := g.pix[y1*g.w+x] - g.pix[y0*g.w+x]
			out.pix[y*g.w+x] = math.Hypot(gx, gy)
		}
	}
	return out
}

// dilateMax lifts each pixel to the max of its 3x3 neighbourhood, so a contour
// lookup tolerates the one-pixel offset between the piece outline and the gap
// outline drawn by the captcha server.
func dilateMax(g *grayImage) *grayImage {
	out := &grayImage{w: g.w, h: g.h, pix: make([]float64, len(g.pix))}
	for y := 0; y < g.h; y++ {
		for x := 0; x < g.w; x++ {
			best := 0.0
			for dy := -1; dy <= 1; dy++ {
				yy := y + dy
				if yy < 0 || yy >= g.h {
					continue
				}
				for dx := -1; dx <= 1; dx++ {
					xx := x + dx
					if xx < 0 || xx >= g.w {
						continue
					}
					if v := g.pix[yy*g.w+xx]; v > best {
						best = v
					}
				}
			}
			out.pix[y*g.w+x] = best
		}
	}
	return out
}

type pieceImage struct {
	gray     *grayImage
	mask     []bool
	w, h     int
	hasShape bool // the source carried transparency, so the mask is the piece outline
}

func extractPiece(img image.Image) (*pieceImage, error) {
	b := img.Bounds()
	w, h := b.Dx(), b.Dy()
	hasAlpha := false
	for y := 0; y < h && !hasAlpha; y++ {
		for x := 0; x < w; x++ {
			if _, _, _, a := img.At(b.Min.X+x, b.Min.Y+y).RGBA(); a < 0xf000 {
				hasAlpha = true
				break
			}
		}
	}
	minX, minY, maxX, maxY := 0, 0, w-1, h-1
	if hasAlpha {
		minX, minY, maxX, maxY = w, h, -1, -1
		count := 0
		for y := 0; y < h; y++ {
			for x := 0; x < w; x++ {
				if _, _, _, a := img.At(b.Min.X+x, b.Min.Y+y).RGBA(); a >= 0x2000 {
					if x < minX {
						minX = x
					}
					if y < minY {
						minY = y
					}
					if x > maxX {
						maxX = x
					}
					if y > maxY {
						maxY = y
					}
					count++
				}
			}
		}
		if count < 16 {
			return nil, errors.New("滑块图像透明区域过大，未找到有效像素")
		}
	}
	pw, ph := maxX-minX+1, maxY-minY+1
	p := &pieceImage{
		gray:     &grayImage{w: pw, h: ph, pix: make([]float64, pw*ph)},
		mask:     make([]bool, pw*ph),
		w:        pw,
		h:        ph,
		hasShape: hasAlpha,
	}
	opaque := 0
	for y := 0; y < ph; y++ {
		for x := 0; x < pw; x++ {
			r, g, bl, a := img.At(b.Min.X+minX+x, b.Min.Y+minY+y).RGBA()
			p.gray.pix[y*pw+x] = 0.299*float64(r>>8) + 0.587*float64(g>>8) + 0.114*float64(bl>>8)
			ok := true
			if hasAlpha {
				ok = a >= 0x2000
			}
			p.mask[y*pw+x] = ok
			if ok {
				opaque++
			}
		}
	}
	if opaque < 16 {
		return nil, errors.New("滑块图像有效像素过少")
	}
	return p, nil
}

func erode(mask []bool, w, h, radius int) []bool {
	out := make([]bool, len(mask))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			if !mask[y*w+x] {
				continue
			}
			ok := true
			for dy := -radius; dy <= radius && ok; dy++ {
				for dx := -radius; dx <= radius; dx++ {
					xx, yy := x+dx, y+dy
					if xx < 0 || yy < 0 || xx >= w || yy >= h || !mask[yy*w+xx] {
						ok = false
						break
					}
				}
			}
			out[y*w+x] = ok
		}
	}
	return out
}

func boundaryPoints(mask []bool, w, h int) []image.Point {
	out := make([]image.Point, 0, 4*w+4*h)
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			i := y*w + x
			if !mask[i] {
				continue
			}
			if x == 0 || x == w-1 || y == 0 || y == h-1 ||
				!mask[i-1] || !mask[i+1] || !mask[i-w] || !mask[i+w] {
				out = append(out, image.Point{X: x, Y: y})
			}
		}
	}
	return out
}

// Sample limits bound the work one solve can trigger regardless of image size.
// A 4096x4096 background with a huge piece must not turn into billions of
// comparisons; the candidate grid is thinned and each candidate cost is capped.
const (
	maxContourSamples = 480
	maxContentSamples = 900
	maxSearchCells    = 120000
)

func subsamplePoints(pts []image.Point, limit int) []image.Point {
	if limit <= 0 || len(pts) <= limit {
		return pts
	}
	out := make([]image.Point, 0, limit)
	for i := 0; i < limit; i++ {
		out = append(out, pts[i*len(pts)/limit])
	}
	return out
}

func sampleMask(mask []bool, w, h, limit int) []image.Point {
	total := countTrue(mask)
	if total == 0 {
		return nil
	}
	stride := 1
	if total > limit {
		stride = (total + limit - 1) / limit
	}
	out := make([]image.Point, 0, limit)
	seen := 0
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			if !mask[y*w+x] {
				continue
			}
			if seen%stride == 0 {
				out = append(out, image.Point{X: x, Y: y})
			}
			seen++
		}
	}
	return out
}

func sampleEvery(pts []image.Point, n int) []image.Point {
	if n <= 1 || len(pts) <= n {
		return pts
	}
	out := make([]image.Point, 0, len(pts)/n+1)
	for i := 0; i < len(pts); i += n {
		out = append(out, pts[i])
	}
	return out
}

func meanGray(g *grayImage) float64 {
	var sum float64
	for _, v := range g.pix {
		sum += v
	}
	return sum / float64(len(g.pix))
}

func contourScore(gradMax *grayImage, pts []image.Point, x, y int) float64 {
	if len(pts) == 0 {
		return 0
	}
	var sum float64
	for _, p := range pts {
		sum += gradMax.pix[(y+p.Y)*gradMax.w+(x+p.X)]
	}
	return sum / float64(len(pts))
}

// contentDiff is the mean absolute gray difference over sampled piece interior
// pixels. Small values mean the piece's own pixels appear at (x, y) in the
// background.
func contentDiff(bg *grayImage, piece *grayImage, samples []image.Point, x, y int) float64 {
	if len(samples) == 0 {
		return 128
	}
	var sum float64
	for _, s := range samples {
		d := bg.pix[(y+s.Y)*bg.w+(x+s.X)] - piece.pix[s.Y*piece.w+s.X]
		if d < 0 {
			d = -d
		}
		sum += d
	}
	return sum / float64(len(samples))
}

// SolveSlider finds the gap. Two independent signals are combined: the piece
// outline must line up with an edge-rich contour in the background (every
// slider captcha draws the gap), and the piece pixels should match the
// background content (true for templates cut from the background). Either
// signal can carry the result when the other is weak.
func SolveSlider(background, piece []byte, opts SolveOptions) (SolveResult, error) {
	started := time.Now()
	bgImg, err := decodeImage(background)
	if err != nil {
		return SolveResult{}, fmt.Errorf("背景图: %w", err)
	}
	pieceImg, err := decodeImage(piece)
	if err != nil {
		return SolveResult{}, fmt.Errorf("滑块图: %w", err)
	}
	bg := boxBlur(toGray(bgImg))
	grad := gradient(bg)
	gradMax := dilateMax(grad)
	gmean := meanGray(grad) + 1e-6

	p, err := extractPiece(pieceImg)
	if err != nil {
		return SolveResult{}, err
	}
	pg := boxBlur(p.gray)

	maxX := bg.w - p.w
	maxY := bg.h - p.h
	if maxX < 0 || maxY < 0 {
		return SolveResult{}, fmt.Errorf("滑块尺寸 %dx%d 超过背景 %dx%d", p.w, p.h, bg.w, bg.h)
	}
	minX := 0
	if opts.MinOffset > minX {
		minX = opts.MinOffset
	}
	limitX := maxX
	if opts.MaxOffset > 0 && opts.MaxOffset < limitX {
		limitX = opts.MaxOffset
	}
	if minX > limitX {
		return SolveResult{}, errors.New("搜索范围为空：MinOffset 大于可用宽度")
	}

	contours := subsamplePoints(boundaryPoints(p.mask, p.w, p.h), maxContourSamples)
	interior := erode(p.mask, p.w, p.h, 2)
	samples := sampleMask(interior, p.w, p.h, maxContentSamples)
	if len(samples) < 16 {
		samples = sampleMask(p.mask, p.w, p.h, maxContentSamples)
	}
	coarseSamples := sampleEvery(samples, 4)

	// The candidate grid is thinned on large backgrounds so the outline scan
	// stays bounded; the top candidates are refined at full resolution below.
	step := 1
	if span := (limitX - minX + 1) * (maxY + 1); span > maxSearchCells {
		step = int(math.Ceil(math.Sqrt(float64(span) / maxSearchCells)))
	}
	type candidate struct {
		x, y             int
		contour, content float64
		score            float64
	}
	type seed struct {
		x, y  int
		score float64
	}
	var outlineSeeds []seed
	for y := 0; y <= maxY; y += step {
		for x := minX; x <= limitX; x += step {
			outlineSeeds = append(outlineSeeds, seed{x: x, y: y, score: contourScore(gradMax, contours, x, y)})
		}
	}
	sort.Slice(outlineSeeds, func(i, j int) bool { return outlineSeeds[i].score > outlineSeeds[j].score })
	if len(outlineSeeds) > 24 {
		outlineSeeds = outlineSeeds[:24]
	}

	// A coarse content scan catches pieces that match the background pixels but
	// whose outline is buried in texture.
	var contentSeeds []seed
	cstep := step * 2
	for y := 0; y <= maxY; y += cstep {
		for x := minX; x <= limitX; x += cstep {
			d := contentDiff(bg, pg, coarseSamples, x, y)
			contentSeeds = append(contentSeeds, seed{x: x, y: y, score: 1 - d/128})
		}
	}
	sort.Slice(contentSeeds, func(i, j int) bool { return contentSeeds[i].score > contentSeeds[j].score })
	if len(contentSeeds) > 8 {
		contentSeeds = contentSeeds[:8]
	}

	seen := map[[2]int]bool{}
	var all []candidate
	consider := func(x, y int) {
		if x < minX || x > limitX || y < 0 || y > maxY {
			return
		}
		key := [2]int{x, y}
		if seen[key] {
			return
		}
		seen[key] = true
		cs := contourScore(gradMax, contours, x, y)
		cNorm := math.Min(cs/gmean, 5) / 5
		cScore := math.Max(0, math.Min(1, 1-contentDiff(bg, pg, samples, x, y)/64))
		all = append(all, candidate{x: x, y: y, contour: cNorm, content: cScore,
			score: 0.65*cNorm + 0.35*cScore})
	}
	refine := func(seeds []seed) {
		for _, s := range seeds {
			for dy := -step; dy <= step; dy++ {
				for dx := -step; dx <= step; dx++ {
					consider(s.x+dx, s.y+dy)
				}
			}
		}
	}
	refine(outlineSeeds)
	refine(contentSeeds)
	if len(all) == 0 {
		return SolveResult{}, errors.New("未找到可用的滑块位置")
	}
	sort.Slice(all, func(i, j int) bool { return all[i].score > all[j].score })
	best := all[0]

	// Confidence is how far the winner stands above the best distinct runner-up.
	sep := p.w / 3
	if sep < 6 {
		sep = 6
	}
	confidence := 0.5
	for _, c := range all[1:] {
		if absInt(c.x-best.x) >= sep || absInt(c.y-best.y) >= sep {
			confidence = (best.score - c.score) / math.Max(best.score, 1e-6)
			break
		}
	}
	confidence = math.Max(0, math.Min(1, confidence))

	distance := best.x - opts.InitialX
	return SolveResult{
		Offset:           best.x,
		Distance:         distance,
		Y:                best.y,
		Confidence:       math.Round(confidence*1000) / 1000,
		Score:            math.Round(best.score*1000) / 1000,
		BackgroundWidth:  bg.w,
		BackgroundHeight: bg.h,
		PieceWidth:       p.w,
		PieceHeight:      p.h,
		ElapsedMS:        time.Since(started).Milliseconds(),
	}, nil
}

func countTrue(b []bool) int {
	n := 0
	for _, v := range b {
		if v {
			n++
		}
	}
	return n
}

func absInt(v int) int {
	if v < 0 {
		return -v
	}
	return v
}

// HumanTrack renders a drag path from 0 to distance: ease-in-out acceleration,
// a small overshoot with a settle-back, and vertical jitter. It is meant for
// mouse-event replay, so points are ordered by increasing timestamp.
func HumanTrack(distance int, opts TrackOptions) []TrackPoint {
	if distance <= 0 {
		return []TrackPoint{{X: 0, Y: 0, T: 0}}
	}
	rng := rand.New(rand.NewSource(opts.Seed))
	if opts.Seed == 0 {
		rng = rand.New(rand.NewSource(time.Now().UnixNano()))
	}
	duration := opts.DurationMS
	if duration <= 0 {
		duration = 550 + rng.Intn(450)
	}
	duration = clampInt(duration, 250, 5000)
	points := opts.Points
	if points <= 0 {
		points = 18 + rng.Intn(12)
	}
	points = clampInt(points, 8, 80)

	overshoot := 0
	if distance > 40 {
		overshoot = 2 + rng.Intn(4)
	}
	out := make([]TrackPoint, 0, points)
	for i := 0; i < points; i++ {
		t := float64(i) / float64(points-1)
		eased := easeInOutCubic(t)
		x := int(math.Round(eased * float64(distance+overshoot)))
		if x > distance+overshoot {
			x = distance + overshoot
		}
		// Settle back inside the last 12% of the path.
		if t > 0.88 {
			back := (t - 0.88) / 0.12
			x = int(math.Round(float64(distance+overshoot) - back*float64(overshoot)))
		}
		if i == points-1 {
			x = distance
		}
		y := rng.Intn(5) - 2
		out = append(out, TrackPoint{X: x, Y: y, T: int(math.Round(t * float64(duration)))})
	}
	return out
}

func easeInOutCubic(t float64) float64 {
	if t < 0.5 {
		return 4 * t * t * t
	}
	f := -2*t + 2
	return 1 - f*f*f/2
}

func clampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
