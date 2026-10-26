package scanner

import (
	"crypto/md5"
	_ "embed"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"math/bits"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"unicode"
)

//go:embed fpdata/fingerprints_merged.json
var externalFingerprintJSON []byte

const maxDetectedTechnologies = 10

type externalLibrary struct {
	Version     string                    `json:"version"`
	TotalRules  int                       `json:"total_rules"`
	Fingerprint []externalFingerprintRule `json:"fingerprint"`
}

type externalFingerprintRule struct {
	Name     string   `json:"name"`
	Method   string   `json:"method"`
	Keyword  []string `json:"keyword"`
	Level    string   `json:"level"`
	Category string   `json:"category"`
}

type externalTechnology struct {
	Name string
}

type externalFingerprints struct {
	technologies []externalTechnology
	body         *acMatcher
	header       *acMatcher
	url          *acMatcher
	bodyRules    map[int32][]string
	faviconMMH3  map[int32][]int32
	faviconMD5   map[string][]int32
}

var (
	externalOnce     sync.Once
	externalCompiled *externalFingerprints
)

func loadExternalFingerprints() *externalFingerprints {
	externalOnce.Do(func() {
		externalCompiled = compileExternalFingerprints()
	})
	return externalCompiled
}

func compileExternalFingerprints() *externalFingerprints {
	fp := &externalFingerprints{
		body:        newACMatcher(),
		header:      newACMatcher(),
		url:         newACMatcher(),
		bodyRules:   map[int32][]string{},
		faviconMMH3: map[int32][]int32{},
		faviconMD5:  map[string][]int32{},
	}
	var lib externalLibrary
	if err := json.Unmarshal(externalFingerprintJSON, &lib); err != nil {
		return fp
	}
	seen := map[string]bool{}
	for _, rule := range lib.Fingerprint {
		name := strings.TrimSpace(rule.Name)
		method := strings.ToLower(strings.TrimSpace(rule.Method))
		if name == "" || ignorableFingerprintName(name) {
			continue
		}
		name = resolveVendorConflict(name)
		keywords := fingerprintKeywords(rule.Keyword, method)
		if len(keywords) == 0 {
			continue
		}
		dedupeKey := name + "\x00" + method + "\x00" + strings.Join(keywords, "\x00")
		if seen[dedupeKey] {
			continue
		}
		seen[dedupeKey] = true

		id := int32(len(fp.technologies))
		fp.technologies = append(fp.technologies, externalTechnology{Name: name})
		switch method {
		case "body":
			fp.bodyRules[id] = keywords
			fp.body.addRule(id, keywords)
		case "header":
			fp.header.addRule(id, keywords)
		case "url":
			fp.url.addRule(id, keywords)
		case "faviconhash":
			for _, kw := range keywords {
				if n, err := strconv.ParseInt(kw, 10, 64); err == nil {
					if n >= -2147483648 && n <= 4294967295 {
						h := int32(uint32(n))
						fp.faviconMMH3[h] = append(fp.faviconMMH3[h], id)
					}
					continue
				}
				if len(kw) == 32 && isHexString(kw) {
					fp.faviconMD5[kw] = append(fp.faviconMD5[kw], id)
				}
			}
		}
	}
	fp.body.build()
	fp.header.build()
	fp.url.build()
	return fp
}

// ignorableFingerprintName drops rules whose "product" is just a generic
// session-cookie token; every PHP/Java page would otherwise list it as a
// detected technology.
func ignorableFingerprintName(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "phpsessid", "jsessionid", "aspsessionid", "asp.net_sessionid", "sessionid":
		return true
	}
	return false
}

var fingerprintGenericKeyword = map[string]bool{
	"login": true, "admin": true, "user": true, "password": true, "system": true,
	"manage": true, "manager": true, "management": true, "signin": true, "sign in": true,
	"logout": true, "log out": true, "register": true, "signup": true, "sign up": true,
	"用户名": true, "密码": true, "登录": true, "注册": true, "登出": true,
	"home": true, "page": true, "main": true, "default": true, "welcome": true,
	"dashboard": true, "console": true, "index": true, "homepage": true, "main page": true,
	"welcome page": true, "api": true, "version": true, "update": true, "help": true,
	"about": true, "rest": true, "graphql": true, "soap": true, "rpc": true, "endpoint": true,
	"contact": true, "service": true, "support": true, "copyright": true, "rights": true,
	"terms": true, "privacy": true, "javascript": true, "jquery": true, "script": true,
	"style": true, "css": true, "html": true, "font": true, "image": true, "img": true,
	"div": true, "span": true, "class": true, "id": true, "name": true, "type": true,
	"value": true, "button": true, "input": true, "form": true, "get": true, "post": true,
	"put": true, "delete": true, "patch": true, "options": true, "head": true,
	"200": true, "404": true, "500": true, "error": true, "success": true, "fail": true,
	"failed": true, "exception": true, "true": true, "false": true, "null": true,
	"undefined": true, "none": true, "empty": true, "www": true, "http": true,
	"https": true, "com": true, "cn": true, "net": true, "org": true, "io": true,
	"edu": true, "gov": true, "content": true, "data": true, "info": true, "message": true,
	"result": true, "status": true, "title": true, "header": true, "body": true,
	"request": true, "response": true, "client": true, "server": true, "database": true,
	"db": true, "token": true, "key": true, "secret": true, "access": true, "verify": true,
	"check": true, "test": true, "list": true, "item": true, "detail": true, "view": true,
	"show": true, "display": true, "render": true, "load": true, "save": true, "submit": true,
	"cancel": true, "close": true, "open": true, "create": true, "edit": true,
	"modify": true, "change": true, "set": true, "fetch": true, "pull": true,
	"ids": true, "uid": true, "uuid": true, "guid": true, "pid": true, "tid": true,
	"sid": true, "rid": true, "pages": true, "size": true, "limit": true, "offset": true,
	"skip": true, "take": true, "sort": true, "order": true, "filter": true, "search": true,
	"query": true, "where": true, "from": true, "select": true, "angular": true,
	"react": true, "vue": true, "svelte": true, "solid": true, "prototype": true,
	"node": true, "nodejs": true, "npm": true, "yarn": true, "webpack": true,
	"vite": true, "rollup": true, "online": true, "offline": true, "enable": true,
	"disable": true, "active": true, "inactive": true, "warning": true, "danger": true,
	"notice": true, "lang": true, "vpn": true, "jsp": true, "owa": true, "ntlm": true,
	"hasp": true, "perl": true, "powered by": true, "all rights reserved": true,
	"web server": true, "web server successfully installed": true, "welcome to nginx": true,
	"welcome to nginx!": true, "test page": true, "default page": true, "it works": true,
	"首页": true, "系统": true, "管理系统": true, "后台": true, "欢迎": true,
	"平台": true, "网站": true,
	// Single web words: a keyword built only from these matches nearly every
	// page, so it is dropped even when it carries path separators.
	"cache": true, "self": true, "location": true, "it": true, "works": true,
	"to": true, "of": true, "the": true, "and": true, "or": true, "is": true,
	"in": true, "on": true, "at": true, "by": true, "for": true,
	"with": true, "banner": true, "logo": true, "icon": true, "favicon": true,
	"meta": true, "link": true, "charset": true, "utf8": true, "encoding": true,
	"gzip": true, "deflate": true, "doctype": true, "html5": true, "text": true,
	"label": true, "click": true, "more": true, "next": true, "prev": true,
	"back": true, "please": true, "menu": true, "nav": true, "frame": true,
	"frameset": true, "noscript": true, "iframe": true, "embed": true,
	"object": true, "param": true, "src": true, "href": true, "alt": true,
	"target": true, "blank": true, "parent": true, "top": true,
}

// resolveVendorConflict drops the conflicting vendor from rule names that mix
// 致远OA (Seeyon) with 用友 (Yonyou). The upstream library mislabels a few
// rules, and keeping both vendors would make the alias set match unrelated
// 用友 POCs against a 致远 deployment.
func resolveVendorConflict(name string) string {
	lower := strings.ToLower(name)
	seeyon := strings.Contains(lower, "致远") || strings.Contains(lower, "seeyon") || strings.Contains(lower, "zhiyuan")
	yonyou := strings.Contains(lower, "用友") || strings.Contains(lower, "yonyou") || strings.Contains(lower, "ufida")
	if !seeyon || !yonyou {
		return name
	}
	return "致远OA"
}

// fingerprintKeywords keeps only keywords that can identify a product. A
// keyword made exclusively of generic web words ("/login", "User") matches
// almost any page, and short header keywords ("ehttp") match inside unrelated
// server banners, so both are dropped.
func fingerprintKeywords(raw []string, method string) []string {
	out := make([]string, 0, len(raw))
	seen := map[string]bool{}
	for _, kw := range raw {
		kw = strings.ToLower(strings.TrimSpace(kw))
		if kw == "" || fingerprintGenericKeyword[kw] || seen[kw] {
			continue
		}
		if len(kw) < 4 && isASCIIString(kw) {
			continue
		}
		if method == "header" && len(kw) < 6 && isASCIIString(kw) {
			continue
		}
		if fingerprintGenericTokensOnly(kw) {
			continue
		}
		if method == "header" && headerKeywordTooGeneric(kw) {
			continue
		}
		seen[kw] = true
		out = append(out, kw)
	}
	return out
}

// bodyKeywordNeedsMarkup reports whether a body rule relies on a single bare
// product token (for example "xampp"). Such tokens also appear in tutorial
// prose, comparisons and help text, so the match only counts inside markup.
func bodyKeywordNeedsMarkup(keywords []string) bool {
	if len(keywords) != 1 {
		return false
	}
	kw := keywords[0]
	if len(kw) < 3 || len(kw) > 24 {
		return false
	}
	for i := 0; i < len(kw); i++ {
		c := kw[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}

// keywordInMarkup reports whether kw occurs inside a tag, a title, or an
// inline script/style block, i.e. in a place where a product name identifies
// the page rather than merely being mentioned in visible text.
func keywordInMarkup(text, kw string) bool {
	for from := 0; from < len(text); {
		i := strings.Index(text[from:], kw)
		if i < 0 {
			return false
		}
		pos := from + i
		if posInMarkup(text, pos) {
			return true
		}
		from = pos + 1
	}
	return false
}

func posInMarkup(text string, pos int) bool {
	if pos < 0 || pos > len(text) {
		return false
	}
	if strings.LastIndexByte(text[:pos], '<') > strings.LastIndexByte(text[:pos], '>') {
		return true
	}
	for _, tag := range [...]string{"title", "script", "style"} {
		open := strings.LastIndex(text[:pos], "<"+tag)
		close := strings.LastIndex(text[:pos], "</"+tag)
		if open >= 0 && open > close {
			return true
		}
	}
	return false
}

// headerGenericNames are header names that appear on nearly every dynamic
// response; a rule whose only evidence is such a name matches unrelated pages.
var headerGenericNames = map[string]bool{
	"set-cookie": true, "cache-control": true, "content-type": true,
	"content-length": true, "content-encoding": true, "transfer-encoding": true,
	"connection": true, "keep-alive": true, "date": true, "expires": true,
	"last-modified": true, "etag": true, "vary": true, "pragma": true,
	"accept-ranges": true, "age": true, "x-frame-options": true,
	"x-content-type-options": true, "x-xss-protection": true,
	"strict-transport-security": true, "access-control-allow-origin": true,
}

// headerGenericValues are common server/cache values that cannot identify a
// product. The external library ships many rules such as
// ["set-cookie", "huawei eudemon8000e-x8"] whose keywords are matched with OR
// semantics, so leaving the generic half in place flags plain Apache sites as
// Huawei firewalls or honeypots.
var headerGenericValues = map[string]bool{
	"apache": true, "nginx": true, "openresty": true, "tengine": true,
	"tomcat": true, "jboss": true, "iis": true, "microsoft-iis": true,
	"jetty": true, "gunicorn": true, "uvicorn": true, "werkzeug": true,
	"express": true, "kestrel": true, "php": true, "asp.net": true,
	"must-revalidate": true, "no-cache": true, "no-store": true,
	"proxy-revalidate": true, "no-transform": true, "private": true,
	"public": true, "max-age": true, "s-maxage": true, "immutable": true,
}

// headerKeywordTooGeneric reports whether a header rule keyword is generic
// enough to match ordinary responses on its own.
func headerKeywordTooGeneric(kw string) bool {
	name, value, hasValue := strings.Cut(strings.ToLower(kw), ":")
	name = strings.TrimSpace(name)
	value = strings.TrimSpace(value)
	if !hasValue {
		return headerGenericValues[kw] || headerGenericNames[kw]
	}
	if value == "" {
		return headerGenericNames[name]
	}
	for _, tok := range strings.Split(value, ",") {
		tok = strings.TrimSpace(tok)
		if i := strings.IndexAny(tok, "/ "); i > 0 {
			tok = tok[:i]
		}
		if !headerGenericValues[tok] {
			return false
		}
	}
	return true
}

// fingerprintGenericTokensOnly reports whether every word of the keyword is a
// generic web word.
func fingerprintGenericTokensOnly(kw string) bool {
	tokens := splitKeywordTokens(kw)
	if len(tokens) == 0 {
		return false
	}
	for _, tok := range tokens {
		if !fingerprintGenericKeyword[tok] {
			return false
		}
	}
	return true
}

func splitKeywordTokens(s string) []string {
	out := make([]string, 0, 4)
	var b strings.Builder
	flush := func() {
		if b.Len() > 0 {
			out = append(out, b.String())
			b.Reset()
		}
	}
	for _, r := range strings.ToLower(s) {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'):
			b.WriteRune(r)
		case r > 0x7f:
			flush()
			out = append(out, string(r))
		default:
			flush()
		}
	}
	flush()
	return out
}

func isASCIIString(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

func isHexString(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// Fingerprint results are scored so a strong favicon/header hit is never pushed
// out of the result cap by lower-confidence body keywords.
const (
	scoreBuiltin         = 80
	scoreExternalFavicon = 100
	scoreExternalHeader  = 90
	scoreExternalBody    = 65
	scoreExternalURL     = 55
)

type techHit struct {
	Name   string
	Score  int
	Method string
}

func detectPageHits(h http.Header, body, rawURL string) []techHit {
	bodyLower := strings.ToLower(body)
	cookieLower := strings.ToLower(strings.Join(h.Values("Set-Cookie"), "; "))
	hits := make([]techHit, 0, 16)
	for _, rule := range fpRules {
		if fpMatch(rule, h, cookieLower, bodyLower) {
			hits = append(hits, techHit{Name: rule.name, Score: scoreBuiltin, Method: "builtin"})
		}
	}
	fp := loadExternalFingerprints()
	if fp == nil {
		return hits
	}
	for _, id := range fp.body.match(bodyLower) {
		keywords := fp.bodyRules[id]
		if bodyKeywordNeedsMarkup(keywords) && !keywordInMarkup(bodyLower, keywords[0]) {
			continue
		}
		hits = append(hits, techHit{Name: fp.technologies[id].Name, Score: scoreExternalBody, Method: "body"})
	}
	for _, id := range fp.header.match(headerMatchText(h)) {
		hits = append(hits, techHit{Name: fp.technologies[id].Name, Score: scoreExternalHeader, Method: "header"})
	}
	if rawURL != "" {
		for _, id := range fp.url.match(strings.ToLower(rawURL)) {
			hits = append(hits, techHit{Name: fp.technologies[id].Name, Score: scoreExternalURL, Method: "url"})
		}
	}
	return hits
}

func detectFaviconHits(mmh3 int32, md5Hex string) []techHit {
	fp := loadExternalFingerprints()
	if fp == nil {
		return nil
	}
	seen := map[int32]bool{}
	hits := make([]techHit, 0, 2)
	add := func(id int32) {
		if seen[id] {
			return
		}
		seen[id] = true
		if int(id) < len(fp.technologies) {
			hits = append(hits, techHit{Name: fp.technologies[id].Name, Score: scoreExternalFavicon, Method: "favicon"})
		}
	}
	for _, id := range fp.faviconMMH3[mmh3] {
		add(id)
	}
	if md5Hex != "" {
		for _, id := range fp.faviconMD5[md5Hex] {
			add(id)
		}
	}
	return hits
}

type techAggregate struct {
	Name    string
	Score   int
	Methods map[string]bool
}

func finalizeTechHits(hits []techHit) []string {
	if len(hits) == 0 {
		return []string{}
	}
	byKey := map[string]*techAggregate{}
	keys := make([]string, 0, len(hits))
	for _, hit := range hits {
		if strings.TrimSpace(hit.Name) == "" {
			continue
		}
		key := technologyKey(hit.Name)
		if key == "" {
			continue
		}
		a := byKey[key]
		if a == nil {
			a = &techAggregate{Name: hit.Name, Methods: map[string]bool{}}
			byKey[key] = a
			keys = append(keys, key)
		}
		if hit.Score > a.Score {
			a.Score = hit.Score
		}
		if hit.Method != "" {
			a.Methods[hit.Method] = true
		}
	}
	sort.SliceStable(keys, func(i, j int) bool {
		a, b := byKey[keys[i]], byKey[keys[j]]
		sa := a.Score + methodBonus(a.Methods)
		sb := b.Score + methodBonus(b.Methods)
		if sa != sb {
			return sa > sb
		}
		return strings.ToLower(a.Name) < strings.ToLower(b.Name)
	})
	if len(keys) > maxDetectedTechnologies {
		keys = keys[:maxDetectedTechnologies]
	}
	out := make([]string, 0, len(keys))
	for _, key := range keys {
		out = append(out, byKey[key].Name)
	}
	return out
}

func methodBonus(methods map[string]bool) int {
	if len(methods) <= 1 {
		return 0
	}
	bonus := (len(methods) - 1) * 5
	if bonus > 10 {
		bonus = 10
	}
	return bonus
}

func technologyKey(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(strings.TrimSpace(s)) {
		if unicode.IsSpace(r) || r == '-' || r == '_' || r == '.' {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func headerMatchText(h http.Header) string {
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		lk := strings.ToLower(k)
		for _, v := range h[k] {
			lv := strings.ToLower(v)
			b.WriteString(lk)
			b.WriteString(": ")
			b.WriteString(lv)
			b.WriteByte('\n')
			b.WriteString(lk)
			b.WriteByte(':')
			b.WriteString(lv)
			b.WriteByte('\n')
		}
	}
	return b.String()
}

// acMatcher is an Aho-Corasick automaton with flattened transition tables so
// the 20k+ body keywords from the external library do not turn every probe into
// a full rule-by-rule scan. Keywords of one library rule are ANDed: the rule
// only fires after every keyword has been seen. The upstream data pairs generic
// markers ("login.php", "&copy;") with product tokens, and OR-matching the raw
// array flags unrelated pages as FastAdmin/phpBB/etc.
type acMatcher struct {
	nodes      []acBuildNode
	childFirst []int32
	childCount []int32
	fail       []int32
	suffix     []int32
	outStart   []int32
	outCount   []int32
	outGroups  []int32
	edgeChar   []byte
	edgeNext   []int32
	groups     map[int32]uint64
}

type acBuildNode struct {
	char       byte
	sibling    int32
	firstChild int32
	fail       int32
	suffix     int32
	out        []int32
}

func newACMatcher() *acMatcher {
	m := &acMatcher{groups: map[int32]uint64{}}
	m.nodes = append(m.nodes, acBuildNode{firstChild: -1, sibling: -1})
	return m
}

// addRule registers one library rule as group; all its keywords must match.
func (m *acMatcher) addRule(group int32, keywords []string) {
	if len(keywords) == 0 {
		return
	}
	if len(keywords) > 32 {
		keywords = keywords[:32]
	}
	mask := uint64(1)<<uint(len(keywords)) - 1
	m.groups[group] = mask
	for i, kw := range keywords {
		m.add(kw, group<<5|int32(i))
	}
}

// add inserts one keyword pattern; the encoded value carries rule group and the
// keyword's bit inside that group.
func (m *acMatcher) add(pattern string, encoded int32) {
	node := int32(0)
	for i := 0; i < len(pattern); i++ {
		ch := pattern[i]
		next := int32(-1)
		for child := m.nodes[node].firstChild; child != -1; child = m.nodes[child].sibling {
			if m.nodes[child].char == ch {
				next = child
				break
			}
		}
		if next == -1 {
			next = int32(len(m.nodes))
			m.nodes = append(m.nodes, acBuildNode{
				char:       ch,
				sibling:    m.nodes[node].firstChild,
				firstChild: -1,
			})
			m.nodes[node].firstChild = next
		}
		node = next
	}
	m.nodes[node].out = append(m.nodes[node].out, encoded)
}

func (m *acMatcher) build() {
	n := len(m.nodes)
	m.childFirst = make([]int32, n)
	m.childCount = make([]int32, n)
	m.fail = make([]int32, n)
	m.suffix = make([]int32, n)
	m.outStart = make([]int32, n)
	m.outCount = make([]int32, n)
	m.edgeChar = make([]byte, 0, n)
	m.edgeNext = make([]int32, 0, n)
	for i := 0; i < n; i++ {
		m.childFirst[i] = int32(len(m.edgeChar))
		count := int32(0)
		for child := m.nodes[i].firstChild; child != -1; child = m.nodes[child].sibling {
			m.edgeChar = append(m.edgeChar, m.nodes[child].char)
			m.edgeNext = append(m.edgeNext, child)
			count++
		}
		m.childCount[i] = count
	}
	for i := 0; i < n; i++ {
		m.outStart[i] = int32(len(m.outGroups))
		m.outGroups = append(m.outGroups, m.nodes[i].out...)
		m.outCount[i] = int32(len(m.nodes[i].out))
	}
	queue := make([]int32, 0, n)
	for child := m.nodes[0].firstChild; child != -1; child = m.nodes[child].sibling {
		queue = append(queue, child)
	}
	for head := 0; head < len(queue); head++ {
		v := queue[head]
		for child := m.nodes[v].firstChild; child != -1; child = m.nodes[child].sibling {
			ch := m.nodes[child].char
			f := m.fail[v]
			for f != 0 {
				if next, ok := m.buildChild(f, ch); ok {
					f = next
					break
				}
				f = m.fail[f]
			}
			if f == 0 {
				if next, ok := m.buildChild(0, ch); ok && next != child {
					f = next
				}
			}
			m.fail[child] = f
			if len(m.nodes[f].out) > 0 {
				m.suffix[child] = f
			} else {
				m.suffix[child] = m.suffix[f]
			}
			queue = append(queue, child)
		}
	}
	m.nodes = nil
}

func (m *acMatcher) buildChild(node int32, ch byte) (int32, bool) {
	for child := m.nodes[node].firstChild; child != -1; child = m.nodes[child].sibling {
		if m.nodes[child].char == ch {
			return child, true
		}
	}
	return 0, false
}

func (m *acMatcher) transition(state int32, ch byte) (int32, bool) {
	start := m.childFirst[state]
	end := start + m.childCount[state]
	for i := start; i < end; i++ {
		if m.edgeChar[i] == ch {
			return m.edgeNext[i], true
		}
	}
	return 0, false
}

func (m *acMatcher) match(text string) []int32 {
	if len(m.outGroups) == 0 {
		return nil
	}
	hits := map[int32]uint64{}
	emit := func(state int32) {
		start := m.outStart[state]
		end := start + m.outCount[state]
		for i := start; i < end; i++ {
			encoded := m.outGroups[i]
			hits[encoded>>5] |= uint64(1) << uint(encoded&31)
		}
	}
	state := int32(0)
	for i := 0; i < len(text); i++ {
		ch := text[i]
		for {
			if next, ok := m.transition(state, ch); ok {
				state = next
				break
			}
			if state == 0 {
				break
			}
			state = m.fail[state]
		}
		if state == 0 {
			continue
		}
		emit(state)
		for suffix := m.suffix[state]; suffix != 0; suffix = m.suffix[suffix] {
			emit(suffix)
		}
	}
	if len(hits) == 0 {
		return nil
	}
	out := make([]int32, 0, len(hits))
	for group, mask := range hits {
		if want := m.groups[group]; want != 0 && mask&want == want {
			out = append(out, group)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func faviconHashes(data []byte) (int32, string) {
	sum := md5.Sum(data)
	encoded := base64BytesWithNewlines(data)
	return murmur3Sum32(encoded, 0), hex.EncodeToString(sum[:])
}

func base64BytesWithNewlines(data []byte) []byte {
	if len(data) == 0 {
		return nil
	}
	out := make([]byte, 0, base64.StdEncoding.EncodedLen(len(data))+len(data)/57+1)
	for len(data) > 0 {
		chunk := data
		if len(chunk) > 57 {
			chunk = chunk[:57]
		}
		var line [76]byte
		base64.StdEncoding.Encode(line[:], chunk)
		out = append(out, line[:base64.StdEncoding.EncodedLen(len(chunk))]...)
		out = append(out, '\n')
		data = data[len(chunk):]
	}
	return out
}

func murmur3Sum32(data []byte, seed uint32) int32 {
	const (
		c1 = 0xcc9e2d51
		c2 = 0x1b873593
	)
	h := seed
	blocks := len(data) / 4
	for i := 0; i < blocks; i++ {
		k := binary.LittleEndian.Uint32(data[i*4:])
		k *= c1
		k = bits.RotateLeft32(k, 15)
		k *= c2
		h ^= k
		h = bits.RotateLeft32(h, 13)
		h = h*5 + 0xe6546b64
	}
	tail := data[blocks*4:]
	var k uint32
	switch len(tail) {
	case 3:
		k ^= uint32(tail[2]) << 16
		fallthrough
	case 2:
		k ^= uint32(tail[1]) << 8
		fallthrough
	case 1:
		k ^= uint32(tail[0])
		k *= c1
		k = bits.RotateLeft32(k, 15)
		k *= c2
		h ^= k
	}
	h ^= uint32(len(data))
	h ^= h >> 16
	h *= 0x85ebca6b
	h ^= h >> 13
	h *= 0xc2b2ae35
	h ^= h >> 16
	return int32(h)
}
