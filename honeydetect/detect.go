// Package honeydetect identifies honeypots from service banners, HTTP headers,
// response bodies and protocol quirks. 为什么要单独做这件事：AI agent 是蜜罐的
// 理想猎物——它不知疲倦地枚举、会认真对待每一个"漏洞"、还会把发现写进报告。
// 一个假的 SSH 服务就能骗它花掉半小时，一个假的 MySQL 报错就能骗出一条假漏洞。
//
// 设计原则：
//   - 纯静态签名，不主动探测（探测本身就是行为异常）；
//   - 输出置信度而非二值判断（0=正常, 1=极可能是蜜罐）；
//   - 签名可独立更新，不依赖外部数据库。
package honeydetect

import (
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Score ranges from 0.0 (no honeypot indicators) to 1.0 (strong honeypot signal).
type Score struct {
	Value   float64  `json:"value"`
	Signals []Signal `json:"signals"`
	Verdict string   `json:"verdict"` // clean | suspicious | likely_honeypot
	// ForceRecheck 表示命中了行为判据，必须强制二次验证后再写 finding。
	// 只影响「是否复核」的提示，不改变工具闸门允许/阻断的判定。
	ForceRecheck bool `json:"force_recheck,omitempty"`
}

// Signal is one detection hit.
type Signal struct {
	Source   string  `json:"source"`   // banner | header | body | protocol | fingerprint
	Rule     string  `json:"rule"`     // rule id
	Detail   string  `json:"detail"`   // human-readable explanation
	Severity string  `json:"severity"` // low | medium | high
	Weight   float64 `json:"weight"`   // contribution to Score.Value
}

// Input carries the raw bytes/text a detector inspects.
type Input struct {
	Banner   string // TCP banner / service identification
	Headers  string // raw HTTP response headers
	Body     string // response body
	Protocol string // ssh | ftp | telnet | mysql | redis | http | ...
}

// signature is one static honeypot indicator.
type signature struct {
	id       string
	source   string
	severity string
	weight   float64
	pattern  *regexp.Regexp
	detail   string
}

// sigs is the built-in signature set.  Each entry is a well-known honeypot
// fingerprint that a real service would not produce.
var sigs = []signature{
	// ── Cowrie (SSH/Telnet honeypot) ──────────────────────────────────────────
	{id: "cowrie-ssh-banner", source: "banner", severity: "high", weight: 0.7,
		pattern: regexp.MustCompile(`(?i)SSH-2\.0-OpenSSH_[\d.]+[^\r\n]*cowrie|cowrie[^\r\n]*SSH`),
		detail:  "SSH banner contains Cowrie honeypot marker"},
	{id: "cowrie-telnet-banner", source: "banner", severity: "high", weight: 0.7,
		pattern: regexp.MustCompile(`(?i)cowrie`),
		detail:  "Telnet banner contains Cowrie honeypot marker"},
	{id: "cowrie-fake-auth", source: "body", severity: "medium", weight: 0.5,
		pattern: regexp.MustCompile(`(?i)(login|password)\s*:\s*$`),
		detail:  "Telnet login prompt with no preceding banner — common in Cowrie"},
	{id: "cowrie-honeyfs", source: "body", severity: "medium", weight: 0.5,
		pattern: regexp.MustCompile(`(?i)busybox\s+v?1\.\d+\.\d+\s+\(.*\)\s+built-in\s+shell\s+\(ash\)`),
		detail:  "BusyBox banner with specific version — Cowrie's honeyfs default"},

	// ── Kippo (SSH honeypot, older) ───────────────────────────────────────────
	{id: "kippo-ssh-banner", source: "banner", severity: "high", weight: 0.7,
		pattern: regexp.MustCompile(`(?i)SSH-2\.0-OpenSSH_5\.1p1\s+Debian-5`),
		detail:  "SSH banner matches Kippo's default fingerprint"},

	// ── OpenCanary (multi-protocol) ──────────────────────────────────────────
	{id: "opencanary-ftp", source: "banner", severity: "high", weight: 0.7,
		pattern: regexp.MustCompile(`(?i)220[^\r\n]*opencanary|220[^\r\n]*pyftpdlib`),
		detail:  "FTP banner matches OpenCanary/pyftpdlib"},
	{id: "opencanary-smb", source: "banner", severity: "medium", weight: 0.5,
		pattern: regexp.MustCompile(`(?i)Windows\s+Server\s+2003\s+3790\s+Service\s+Pack`),
		detail:  "SMB banner matches OpenCanary's default Windows fingerprint"},

	// ── Glastopf (Web honeypot) ──────────────────────────────────────────────
	{id: "glastopf-server", source: "header", severity: "high", weight: 0.8,
		pattern: regexp.MustCompile(`(?i)Server:\s*glastopf`),
		detail:  "HTTP Server header reveals Glastopf web honeypot"},
	{id: "glastopf-body", source: "body", severity: "medium", weight: 0.5,
		pattern: regexp.MustCompile(`(?i)glastopf`),
		detail:  "Response body references Glastopf honeypot"},

	// ── HFish ─────────────────────────────────────────────────────────────────
	{id: "hfish-banner", source: "body", severity: "high", weight: 0.7,
		pattern: regexp.MustCompile(`(?i)hfish|HFish`),
		detail:  "Response contains HFish honeypot marker"},

	// ── Dionaea (Malware honeypot) ───────────────────────────────────────────
	{id: "dionaea-banner", source: "banner", severity: "high", weight: 0.7,
		pattern: regexp.MustCompile(`(?i)dionaea`),
		detail:  "Banner reveals Dionaea malware honeypot"},

	// ── Generic honeypot indicators ──────────────────────────────────────────
	{id: "fake-uname", source: "body", severity: "medium", weight: 0.4,
		pattern: regexp.MustCompile(`(?i)Linux\s+\w+\s+2\.6\.32-.*-generic`),
		detail:  "Kernel version 2.6.32 — common default in many honeypot images"},
	{id: "telnet-honey", source: "banner", severity: "medium", weight: 0.5,
		pattern: regexp.MustCompile(`(?i)Ubuntu\s+12\.04(\.\d+)?\s+LTS`),
		detail:  "Ubuntu 12.04 banner — default in Kippo/Cowrie docker images"},
	{id: "http-fake-phpmyadmin", source: "body", severity: "medium", weight: 0.5,
		pattern: regexp.MustCompile(`(?i)phpmyadmin[^\r\n]*pma_password[^\r\n]*honey`),
		detail:  "phpMyAdmin login page with honeypot-specific form field"},

	// ── Tarpit / anti-AI patterns ────────────────────────────────────────────
	{id: "tarpit-slow-response", source: "protocol", severity: "medium", weight: 0.4,
		pattern: regexp.MustCompile(`(?i)very\s+slow|tarpit|delay`),
		detail:  "Response indicates tarpit-style deliberate delay — designed to waste agent time"},
	{id: "fake-vuln-banner", source: "body", severity: "medium", weight: 0.5,
		pattern: regexp.MustCompile(`(?i)(?:SQL\s+syntax\s+error.*near.*honey|Welcome\s+to\s+the\s+honeypot|This\s+is\s+a\s+honeypot)`),
		detail:  "Response contains explicit honeypot self-identification"},
}

// Detect inspects the input and returns a honeypot score.
func Detect(in Input) Score {
	var signals []Signal

	check := func(text, source string) {
		if text == "" {
			return
		}
		for _, s := range sigs {
			if s.source != source {
				continue
			}
			if s.pattern.MatchString(text) {
				signals = append(signals, Signal{
					Source:   s.source,
					Rule:     s.id,
					Detail:   s.detail,
					Severity: s.severity,
					Weight:   s.weight,
				})
			}
		}
	}

	check(in.Banner, "banner")
	check(in.Headers, "header")
	check(in.Body, "body")
	check(in.Protocol, "protocol")

	// Score is the sum of signal weights, capped at 1.0. Using a fixed additive
	// model avoids normalizing across categories that have no data — a single
	// strong header hit (Glastopf) should not be diluted by unrelated body rules.
	score := 0.0
	for _, sig := range signals {
		score += sig.Weight
	}
	if score > 1.0 {
		score = 1.0
	}
	// Boost: multiple independent signals raise confidence.
	if len(signals) >= 3 && score < 1.0 {
		score = score * 1.2
		if score > 1.0 {
			score = 1.0
		}
	}

	verdict := "clean"
	switch {
	case score >= 0.6:
		verdict = "likely_honeypot"
	case score >= 0.3:
		verdict = "suspicious"
	}

	return Score{Value: score, Signals: signals, Verdict: verdict}
}

// DetectBanner is a convenience for TCP banners alone.
func DetectBanner(banner string) Score {
	return Detect(Input{Banner: banner})
}

// DetectHTTP is a convenience for HTTP responses.
func DetectHTTP(headers, body string) Score {
	return Detect(Input{Headers: headers, Body: body, Protocol: "http"})
}

// IsLikelyHoneypot reports whether the score crosses the high-confidence threshold.
func IsLikelyHoneypot(s Score) bool {
	return s.Verdict == "likely_honeypot"
}

// Summary returns a one-line human-readable summary of the score.
func Summary(s Score) string {
	if len(s.Signals) == 0 {
		return "未发现蜜罐特征"
	}
	parts := make([]string, 0, len(s.Signals))
	for _, sig := range s.Signals {
		parts = append(parts, sig.Detail)
	}
	return strings.Join(parts, "; ")
}

// =====================================================================
// P5 · 行为判据（静态签名之外）
//
// 静态签名抓的是「蜜罐长什么样」；行为判据抓的是「蜜罐怎么回应」。
// 两类蜜罐静态签名漏检：① 过度完美——每个 payload 都 success、零噪声，
// 真实服务在枚举中必然有 404/报错/随机噪声；② 时间反常——响应恒定极快且
// 抖动趋近于零，真实服务有网络与业务抖动。命中后打 ForceRecheck 标记，
// 要求 agent 二次验证，但不改变工具闸门与 finding 判定。
// =====================================================================

// TimingSample 是一次 payload 探针的观测值。
type TimingSample struct {
	Payload string        `json:"payload,omitempty"`
	Success bool          `json:"success"`
	Elapsed time.Duration `json:"elapsed"`
	Noise   string        `json:"noise,omitempty"` // 非空表示该次有报错/噪声
}

const (
	behaviorMinSamples      = 3
	behaviorFastThreshold   = 2 * time.Millisecond // 恒定低于此值视为脚本桩
	behaviorJitterTolerance = 500 * time.Microsecond
)

// DetectBehavior 用行为样本补充静态检测。timing 为空时返回 clean。
func DetectBehavior(in Input, timing ...TimingSample) Score {
	// 静态信号也带进来：行为命中 + 静态命中时 Confidence 更高。
	_ = in // 预留给未来与静态信号交叉验证；当前行为判据只看样本本身。
	var signals []Signal
	if tooPerfect(timing) {
		signals = append(signals, Signal{
			Source: "behavior", Rule: "behavior-too-perfect", Severity: "high", Weight: 0.6,
			Detail: "过度完美：所有 payload 均 success 且无噪声，疑似脚本桩蜜罐",
		})
	}
	if constantFast(timing) {
		signals = append(signals, Signal{
			Source: "behavior", Rule: "behavior-constant-fast", Severity: "high", Weight: 0.5,
			Detail: "时间反常：响应恒定极快且抖动趋近于零，疑似预置应答蜜罐",
		})
	}
	if len(signals) == 0 {
		return Score{Verdict: "clean"}
	}
	value := 0.0
	for _, sig := range signals {
		value += sig.Weight
	}
	if len(signals) >= 2 {
		value *= 1.2 // 两个独立行为信号叠加，提高置信度
	}
	if value > 1.0 {
		value = 1.0
	}
	verdict := "suspicious"
	if value >= 0.6 {
		verdict = "likely_honeypot"
	}
	return Score{Value: value, Signals: signals, Verdict: verdict, ForceRecheck: true}
}

// tooPerfect：至少 3 个样本，全部 success、全部无噪声。
func tooPerfect(samples []TimingSample) bool {
	if len(samples) < behaviorMinSamples {
		return false
	}
	for _, s := range samples {
		if !s.Success || strings.TrimSpace(s.Noise) != "" {
			return false
		}
	}
	return true
}

// constantFast：至少 3 个样本，全部 >0 且 <=阈值，且最大-最小抖动在容差内。
func constantFast(samples []TimingSample) bool {
	if len(samples) < behaviorMinSamples {
		return false
	}
	min, max := time.Duration(0), time.Duration(0)
	for i, s := range samples {
		if s.Elapsed <= 0 || s.Elapsed > behaviorFastThreshold {
			return false
		}
		if i == 0 || s.Elapsed < min {
			min = s.Elapsed
		}
		if i == 0 || s.Elapsed > max {
			max = s.Elapsed
		}
	}
	return max-min <= behaviorJitterTolerance
}

// MergeScores 合并静态与行为评分。Verdict 重新按合并值计算；任一命中行为判据
// 都必须保留 ForceRecheck 标记。
func MergeScores(a, b Score) Score {
	out := Score{}
	out.Signals = append(append([]Signal{}, a.Signals...), b.Signals...)
	out.Value = a.Value + b.Value
	if out.Value > 1.0 {
		out.Value = 1.0
	}
	out.ForceRecheck = a.ForceRecheck || b.ForceRecheck
	switch {
	case out.Value >= 0.6:
		out.Verdict = "likely_honeypot"
	case out.Value >= 0.3:
		out.Verdict = "suspicious"
	default:
		out.Verdict = "clean"
	}
	return out
}

// NeedsRecheck 报告是否应强制二次验证。
func NeedsRecheck(s Score) bool { return s.ForceRecheck }

// ParseTimingSamples 从工具输出里解析行为样本行，格式（每行一个样本）：
//
//	payload=/api/a success=1 elapsed_ms=0.35
//	payload=/api/b success=true elapsed_ms=0.31 noise="404"
//
// 这是给 agent / 深挖模块回灌观测值的轻量约定；解析不到就返回 nil，
// 行为判据静默跳过，不影响静态检测。
var (
	reSampleElapsed = regexp.MustCompile(`(?i)elapsed_ms\s*[:=]\s*([0-9]+(?:\.[0-9]+)?)`)
	reSampleSuccess = regexp.MustCompile(`(?i)\bsuccess\s*[:=]\s*(true|yes|ok|1)\b`)
	reSampleNoise   = regexp.MustCompile(`(?i)\bnoise\s*[:=]\s*"([^"]*)"`)
)

func ParseTimingSamples(output string) []TimingSample {
	var out []TimingSample
	for _, line := range strings.Split(output, "\n") {
		m := reSampleElapsed.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		ms, err := strconv.ParseFloat(m[1], 64)
		if err != nil || ms < 0 {
			continue
		}
		s := TimingSample{Elapsed: time.Duration(ms * float64(time.Millisecond))}
		s.Success = reSampleSuccess.MatchString(line)
		if n := reSampleNoise.FindStringSubmatch(line); n != nil {
			s.Noise = n[1]
		}
		out = append(out, s)
	}
	return out
}
