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
	"strings"
)

// Score ranges from 0.0 (no honeypot indicators) to 1.0 (strong honeypot signal).
type Score struct {
	Value   float64  `json:"value"`
	Signals []Signal `json:"signals"`
	Verdict string   `json:"verdict"` // clean | suspicious | likely_honeypot
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
