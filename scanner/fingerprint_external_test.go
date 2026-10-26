package scanner

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestExternalFingerprintLibraryLoaded(t *testing.T) {
	fp := loadExternalFingerprints()
	if fp == nil || len(fp.technologies) < 24000 {
		t.Fatalf("external fingerprint library not loaded: %d rules", len(fp.technologies))
	}
	if len(fp.faviconMMH3) < 500 {
		t.Fatalf("favicon rules missing: %d", len(fp.faviconMMH3))
	}
}

func TestExternalBodyFingerprint(t *testing.T) {
	body := `<html><body><img src="/seeyon/USER-DATA/IMAGES/LOGIN/login.gif"></body></html>`
	techs := DetectTechnologies(http.Header{}, body)
	if !containsFold(techs, "致远OA") {
		t.Fatalf("seeyon fingerprint missing: %v", techs)
	}
	if len(techs) > maxDetectedTechnologies {
		t.Fatalf("technology cap exceeded: %d", len(techs))
	}
}

func TestExternalHeaderFingerprint(t *testing.T) {
	h := http.Header{}
	h.Add("Set-Cookie", "PbootSystem=abc123; Path=/")
	techs := DetectTechnologies(h, "<html></html>")
	if !containsFold(techs, "PbootCMS") {
		t.Fatalf("pbootcms header fingerprint missing: %v", techs)
	}
}

func TestExternalURLFingerprint(t *testing.T) {
	techs := DetectTechnologiesForURL(http.Header{}, "", "http://target/CDGServer3/SysConfig")
	if !containsFold(techs, "亿赛通数据泄露防护（DLP）系统") {
		t.Fatalf("url fingerprint missing: %v", techs)
	}
}

func TestExternalFaviconFingerprint(t *testing.T) {
	techs := finalizeTechHits(detectFaviconHits(1747282642, ""))
	if !containsFold(techs, "Joomla内容管理系统") {
		t.Fatalf("joomla favicon fingerprint missing: %v", techs)
	}
	techs = finalizeTechHits(detectFaviconHits(-748565678, ""))
	if !containsFold(techs, "Dreamer CMS") {
		t.Fatalf("dreamer favicon fingerprint missing: %v", techs)
	}
}

func TestACMatcherOverlappingPatterns(t *testing.T) {
	m := newACMatcher()
	m.addRule(0, []string{"he"})
	m.addRule(1, []string{"she"})
	m.addRule(2, []string{"his"})
	m.addRule(3, []string{"hers"})
	m.build()
	if got := fmt.Sprint(m.match("ushers")); got != "[0 1 3]" {
		t.Fatalf("ushers matches: %s", got)
	}
	if got := fmt.Sprint(m.match("his")); got != "[2]" {
		t.Fatalf("his matches: %s", got)
	}
	if got := m.match("xyz"); len(got) != 0 {
		t.Fatalf("unexpected matches: %v", got)
	}
}

func TestACMatcherRequiresAllRuleKeywords(t *testing.T) {
	m := newACMatcher()
	m.addRule(0, []string{"fastadmin", "bootstrap.min.css"})
	m.addRule(1, []string{"bootstrap.min.css"})
	m.build()
	if got := fmt.Sprint(m.match("only bootstrap.min.css here")); got != "[1]" {
		t.Fatalf("partial rule fired: %s", got)
	}
	if got := fmt.Sprint(m.match("fastadmin with bootstrap.min.css")); got != "[0 1]" {
		t.Fatalf("full rule missing: %s", got)
	}
}

func TestFaviconHashes(t *testing.T) {
	if got := murmur3Sum32([]byte("foo"), 0); got != -156908512 {
		t.Fatalf("mmh3(foo) = %d", got)
	}
	if got := murmur3Sum32([]byte("hello"), 0); got != 613153351 {
		t.Fatalf("mmh3(hello) = %d", got)
	}
	mmh3, digest := faviconHashes([]byte("hello world"))
	encoded := "aGVsbG8gd29ybGQ=\n"
	if got := base64BytesWithNewlines([]byte("hello world")); string(got) != encoded {
		t.Fatalf("encodebytes: %q", got)
	}
	if want := murmur3Sum32([]byte(encoded), 0); mmh3 != want {
		t.Fatalf("favicon mmh3: got %d want %d", mmh3, want)
	}
	sum := md5.Sum([]byte("hello world"))
	if want := hex.EncodeToString(sum[:]); digest != want {
		t.Fatalf("favicon md5: got %s want %s", digest, want)
	}
}

func TestBase64EncodebytesLineBreaks(t *testing.T) {
	data57 := bytes.Repeat([]byte("a"), 57)
	encoded57 := base64.StdEncoding.EncodeToString(data57)
	if got, want := string(base64BytesWithNewlines(data57)), encoded57+"\n"; got != want {
		t.Fatalf("57-byte encoding:\n got %q\nwant %q", got, want)
	}
	data58 := bytes.Repeat([]byte("a"), 58)
	encoded58 := base64.StdEncoding.EncodeToString(data58)
	want58 := encoded58[:76] + "\n" + encoded58[76:] + "\n"
	if got := string(base64BytesWithNewlines(data58)); got != want58 {
		t.Fatalf("58-byte encoding:\n got %q\nwant %q", got, want58)
	}
	if got := base64BytesWithNewlines(nil); len(got) != 0 {
		t.Fatalf("empty encoding: %q", got)
	}
}

func TestProberFetchesFaviconHashes(t *testing.T) {
	icon := []byte("hello world")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/favicon.ico" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(icon)
	}))
	defer srv.Close()
	p := NewProber(2 * time.Second)
	mmh3, digest, ok := p.fetchFaviconHashes(context.Background(), srv.URL)
	if !ok {
		t.Fatal("favicon fetch failed")
	}
	wantMMH3, wantMD5 := faviconHashes(icon)
	if mmh3 != wantMMH3 || digest != wantMD5 {
		t.Fatalf("favicon hashes: got %d/%s want %d/%s", mmh3, digest, wantMMH3, wantMD5)
	}
}

func TestChineseTechnologyAliases(t *testing.T) {
	cases := []struct {
		tech string
		want string
	}{
		{"致远OA", "seeyon"},
		{"泛微 OA", "weaver"},
		{"通达OA", "tongda"},
		{"蓝凌OA", "landray"},
		{"用友 NC Cloud", "yonyou"},
		{"金蝶云星空", "kingdee"},
		{"帆软报表", "fanruan"},
		{"深信服 VPN", "sangfor"},
		{"天融信防火墙", "topsec"},
		{"华为AR Web管理平台", "huawei"},
		{"宝塔面板", "baota"},
		{"禅道项目管理软件", "zentao"},
	}
	for _, tc := range cases {
		aliases := TechnologyAliases(tc.tech)
		if !containsFold(aliases, tc.want) {
			t.Fatalf("aliases(%q) missing %q: %v", tc.tech, tc.want, aliases)
		}
	}
	if aliases := TechnologyAliases("OA"); len(aliases) != 0 {
		t.Fatalf("generic OA should not produce aliases: %v", aliases)
	}
	if aliases := TechnologyAliases("致远OA"); containsFold(aliases, "oa") {
		t.Fatalf("generic oa alias leaked: %v", aliases)
	}
}

func TestMatchTemplatesWithChineseFingerprint(t *testing.T) {
	metas := []TemplateMeta{
		{ID: 7, TemplateID: "seeyon-oa-log4j-rce", Name: "Seeyon OA Log4j RCE", Tags: []string{"seeyon", "oa", "rce"}},
		{ID: 8, TemplateID: "weaver-ecology-sqli", Name: "Weaver SQL Injection", Tags: []string{"weaver", "ecology"}},
	}
	ids := MatchTemplates([]string{"致远OA"}, metas)
	if fmt.Sprint(ids) != "[7]" {
		t.Fatalf("seeyon matched ids: %v", ids)
	}
}

func TestExternalMatcherCapAndNoKubernetesFalsePositive(t *testing.T) {
	techs := DetectTechnologies(http.Header{}, `{"major":"1","minor":"28"}`)
	if containsFold(techs, "kubernetes") {
		t.Fatalf("false positive kubernetes: %v", techs)
	}
	if len(techs) > maxDetectedTechnologies {
		t.Fatalf("cap exceeded: %v", techs)
	}
}

func TestGenericDefaultPageFalsePositive(t *testing.T) {
	h := http.Header{}
	h.Set("Server", "nginx")
	body := `<html><head><title>Welcome to nginx!</title></head><body>` +
		`<h1>Welcome to nginx!</h1><p>If you see this page, the nginx web server is successfully installed.</p></body></html>`
	techs := DetectTechnologies(h, body)
	if !containsFold(techs, "nginx") {
		t.Fatalf("nginx missing: %v", techs)
	}
	if containsFold(techs, "Dell-OpenManage-Switch-Administrator") {
		t.Fatalf("generic web server phrase matched a product: %v", techs)
	}
}

func TestGenericPathKeywordFalsePositive(t *testing.T) {
	body := `<html><body><img src="/seeyon/USER-DATA/IMAGES/LOGIN/login.gif"><a href="/login">login</a></body></html>`
	techs := DetectTechnologies(http.Header{}, body)
	if !containsFold(techs, "致远OA") {
		t.Fatalf("seeyon fingerprint missing: %v", techs)
	}
	if containsFold(techs, "宝塔-BT.cn") {
		t.Fatalf("generic /login path matched a product: %v", techs)
	}
}

func TestGenericBodyKeywordFalsePositive(t *testing.T) {
	body := `<html><head><title>Get the pikachu</title>` +
		`<link rel="stylesheet" href="/assets/bootstrap.min.css">` +
		`<script src="/assets/js/navbar-toggle.js"></script></head>` +
		`<body><a href="login.php">login</a><span>language</span>` +
		`<form action="check.php"><p>showMsg &copy; 2019</p></form></body></html>`
	techs := DetectTechnologies(http.Header{}, body)
	for _, bogus := range []string{"FastAdmin 框架", "Igenus邮件系统", "PHPOA 协同办公软件",
		"phpBB", "Cisco-DPC3848-DOCSIS-Gateway"} {
		if containsFold(techs, bogus) {
			t.Fatalf("generic body marker matched %s: %v", bogus, techs)
		}
	}
}

func TestBodyProductWordInProseDoesNotMatch(t *testing.T) {
	prose := `<html><body><p>一些集成软件来搭建这些基础环境,比如XAMPP,WAMP等。</p></body></html>`
	if techs := DetectTechnologies(http.Header{}, prose); containsFold(techs, "XAMPP") {
		t.Fatalf("prose mention matched XAMPP: %v", techs)
	}
	for _, markup := range []string{
		`<html><head><title>XAMPP</title></head><body></body></html>`,
		`<html><body><a href="/xampp/index.php">dashboard</a></body></html>`,
		`<html><body><meta name="generator" content="XAMPP"></body></html>`,
		`<html><body><script>var product = "XAMPP";</script></body></html>`,
	} {
		if techs := DetectTechnologies(http.Header{}, markup); !containsFold(techs, "XAMPP") {
			t.Fatalf("markup mention lost XAMPP for %q: %v", markup, techs)
		}
	}
	if !bodyKeywordNeedsMarkup([]string{"xampp"}) {
		t.Fatal("bare product token should require markup")
	}
	if bodyKeywordNeedsMarkup([]string{"xampp", "location http"}) || bodyKeywordNeedsMarkup([]string{"welcome to xampp"}) {
		t.Fatal("multi-keyword or phrase rule should not require markup")
	}
}

func TestGenericHeaderKeywordFalsePositive(t *testing.T) {
	h := http.Header{}
	h.Set("Server", "Apache/2.4.52 (Ubuntu)")
	h.Set("Set-Cookie", "PHPSESSID=abcdef012345; path=/")
	h.Set("Cache-Control", "no-store, no-cache, must-revalidate")
	h.Set("Pragma", "no-cache")
	techs := DetectTechnologies(h, "<html><body><h1>Get the pikachu</h1></body></html>")
	for _, bogus := range []string{"Eudemon8000E-X8", "HUAWEI-Secoway-USG2230", "SAMSUNG-SNB-2000", "Honeypot"} {
		if containsFold(techs, bogus) {
			t.Fatalf("generic header value matched %s: %v", bogus, techs)
		}
	}
}

func TestSpecificHeaderKeywordStillMatches(t *testing.T) {
	h := http.Header{}
	h.Set("Set-Cookie", "PbootSystem=abc123; Path=/")
	techs := DetectTechnologies(h, "")
	if !containsFold(techs, "PbootCMS") {
		t.Fatalf("specific cookie name lost: %v", techs)
	}
	if headerKeywordTooGeneric("server: jboss-5.0") {
		t.Fatal("versioned server banner wrongly filtered")
	}
	if !headerKeywordTooGeneric("SET-COOKIE:") || !headerKeywordTooGeneric("must-revalidate") {
		t.Fatal("generic keyword not filtered")
	}
}

func TestShortHeaderKeywordFalsePositive(t *testing.T) {
	h := http.Header{}
	h.Set("Server", "BaseHTTP/0.6 Python/3.11.9")
	techs := DetectTechnologies(h, "<html></html>")
	if containsFold(techs, "HP-ProCurve-Switch") {
		t.Fatalf("short header keyword matched a switch product: %v", techs)
	}
}

func TestVendorConflictResolved(t *testing.T) {
	if got := resolveVendorConflict("用友致远oa"); got != "致远OA" {
		t.Fatalf("conflict name not normalized: %q", got)
	}
	if got := resolveVendorConflict("用友 NC Cloud"); got != "用友 NC Cloud" {
		t.Fatalf("unrelated vendor renamed: %q", got)
	}
	aliases := TechnologyAliases(resolveVendorConflict("Yonyou-Seeyon-OA"))
	if containsFold(aliases, "yonyou") || containsFold(aliases, "ufida") {
		t.Fatalf("conflicting vendor leaked into aliases: %v", aliases)
	}
	if !containsFold(aliases, "seeyon") {
		t.Fatalf("seeyon alias missing: %v", aliases)
	}
}

func BenchmarkExternalBodyMatch(b *testing.B) {
	body := strings.Repeat(`<html><head><title>console</title></head><body><div class="app">`+
		`<script src="/static/app.js"></script><a href="/login">Login</a></div></body></html>`, 20)
	fp := loadExternalFingerprints()
	bodyLower := strings.ToLower(body)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = fp.body.match(bodyLower)
	}
}
