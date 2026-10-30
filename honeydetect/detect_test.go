package honeydetect

import "testing"

func TestDetectCowrieSSH(t *testing.T) {
	s := DetectBanner("SSH-2.0-OpenSSH_7.4p1 Ubuntu-4ubuntu2.3 cowrie")
	if s.Verdict != "likely_honeypot" {
		t.Fatalf("Cowrie banner should be likely_honeypot, got %s (score=%.2f)", s.Verdict, s.Value)
	}
	if len(s.Signals) == 0 {
		t.Fatal("expected at least one signal")
	}
}

func TestDetectKippoSSH(t *testing.T) {
	s := DetectBanner("SSH-2.0-OpenSSH_5.1p1 Debian-5")
	if s.Verdict == "clean" {
		t.Fatalf("Kippo banner should not be clean, got %s (score=%.2f)", s.Verdict, s.Value)
	}
}

func TestDetectGlastopf(t *testing.T) {
	s := DetectHTTP("Server: glastopf\nContent-Type: text/html", "<html><body>hello</body></html>")
	if s.Verdict != "likely_honeypot" {
		t.Fatalf("Glastopf header should be likely_honeypot, got %s (score=%.2f)", s.Verdict, s.Value)
	}
}

func TestDetectNormalSSH(t *testing.T) {
	s := DetectBanner("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13")
	if s.Verdict != "clean" {
		t.Fatalf("Normal SSH should be clean, got %s (score=%.2f)", s.Verdict, s.Value)
	}
}

func TestDetectNormalHTTP(t *testing.T) {
	s := DetectHTTP("Server: nginx/1.24.0\nContent-Type: text/html", "<html><body>Welcome</body></html>")
	if s.Verdict != "clean" {
		t.Fatalf("Normal HTTP should be clean, got %s (score=%.2f)", s.Verdict, s.Value)
	}
}

func TestDetectMultipleSignals(t *testing.T) {
	// Cowrie + fake uname + Ubuntu 12.04 — multiple independent signals
	s := Detect(Input{
		Banner: "SSH-2.0-OpenSSH_5.1p1 Debian-5 cowrie",
		Body:   "Linux honeypot 2.6.32-5-amd64\nUbuntu 12.04.5 LTS",
	})
	if s.Verdict != "likely_honeypot" {
		t.Fatalf("Multi-signal should be likely_honeypot, got %s (score=%.2f)", s.Verdict, s.Value)
	}
	if len(s.Signals) < 2 {
		t.Fatalf("expected >= 2 signals, got %d", len(s.Signals))
	}
}

func TestDetectEmpty(t *testing.T) {
	s := Detect(Input{})
	if s.Verdict != "clean" || s.Value != 0 {
		t.Fatalf("Empty input should be clean/0, got %s/%.2f", s.Verdict, s.Value)
	}
}

func TestSummary(t *testing.T) {
	s := DetectBanner("SSH-2.0-OpenSSH_7.4p1 cowrie")
	if Summary(s) == "未发现蜜罐特征" {
		t.Fatal("summary should mention signals")
	}
	empty := Detect(Input{})
	if Summary(empty) != "未发现蜜罐特征" {
		t.Fatal("empty summary should be default text")
	}
}
