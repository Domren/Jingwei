package scanner

import (
	"context"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// rePasswordInput matches an <input type="password"> element — the simplest
// reliable signal that a page hosts a login form.
var rePasswordInput = regexp.MustCompile(`(?is)<input[^>]*\btype\s*=\s*["']?password`)

// staticExts are link suffixes we never crawl: they cannot carry a login form
// and fetching them only burns the page budget.
var staticExts = []string{
	".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
	".woff", ".woff2", ".ttf", ".eot", ".map", ".pdf", ".zip",
}

// LoginFormOptions bounds login-form discovery.
type LoginFormOptions struct {
	MaxPages    int
	Concurrency int
	Timeout     time.Duration
	Logf        func(format string, args ...any)
}

func loginFormDefault(o LoginFormOptions) LoginFormOptions {
	if o.MaxPages <= 0 {
		o.MaxPages = 120
	}
	if o.Concurrency <= 0 {
		o.Concurrency = 8
	}
	if o.Timeout <= 0 {
		o.Timeout = 8 * time.Second
	}
	if o.Logf == nil {
		o.Logf = func(string, ...any) {}
	}
	return o
}

// DiscoverLoginForms crawls (bounded, same-host only) from the service roots and
// the app systems discovered by the app-layer phase, returning the URL of every
// page that actually contains a login form (a password input). The weak-password
// baseline feeds exactly these URLs to WebCrack instead of treating every system
// entry as a login page.
func DiscoverLoginForms(ctx context.Context, services []WebService, apps []AppSystem, opts LoginFormOptions) []string {
	opts = loginFormDefault(opts)
	prober := NewProber(opts.Timeout)

	type item struct {
		rawURL string
		ip     string
	}
	seen := map[string]bool{}
	var level []item
	add := func(rawURL, ip string) {
		rawURL = strings.TrimSpace(rawURL)
		if rawURL == "" || seen[rawURL] {
			return
		}
		seen[rawURL] = true
		level = append(level, item{rawURL, ip})
	}
	for _, s := range services {
		add(s.URL, s.IP)
	}
	for _, a := range apps {
		add(a.URL, a.IP)
	}

	var forms []string
	formSeen := map[string]bool{}

	// Two levels: seeds (roots + systems), then the same-host links they point
	// to. pikachu-style labs keep their login forms one hop below the category
	// pages, so one level of link-following is enough.
	for depth := 0; depth <= 1 && len(level) > 0; depth++ {
		var mu sync.Mutex
		var next []item
		var wg sync.WaitGroup
		sem := make(chan struct{}, opts.Concurrency)
		pages := 0
		for _, it := range level {
			if pages >= opts.MaxPages {
				break
			}
			pages++
			wg.Add(1)
			go func(it item) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				resp := appFetch(ctx, prober, it.rawURL, it.ip)
				if resp == nil || len(resp.body) == 0 {
					return
				}
				body := string(resp.body)
				if rePasswordInput.MatchString(body) {
					mu.Lock()
					if !formSeen[it.rawURL] {
						formSeen[it.rawURL] = true
						forms = append(forms, it.rawURL)
					}
					mu.Unlock()
				}
				if depth >= 1 {
					return
				}
				for _, m := range rePageRef.FindAllStringSubmatch(body, -1) {
					abs := sameHostResolve(it.rawURL, m[1])
					if abs == "" || isStaticURL(abs) {
						continue
					}
					mu.Lock()
					if !seen[abs] {
						seen[abs] = true
						next = append(next, item{abs, it.ip})
					}
					mu.Unlock()
				}
			}(it)
		}
		wg.Wait()
		level = next
	}

	sort.Strings(forms)
	return forms
}

// sameHostResolve resolves a (possibly relative) link against a base URL and
// enforces same-scheme + same-host. Unlike normalizeAppPath it also handles
// relative paths without a leading "/" (e.g. "vul/burteforce/bf.php").
func sameHostResolve(base, ref string) string {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return ""
	}
	b, err := url.Parse(base)
	if err != nil {
		return ""
	}
	r, err := url.Parse(ref)
	if err != nil {
		return ""
	}
	u := b.ResolveReference(r)
	if !strings.EqualFold(u.Scheme, b.Scheme) || !strings.EqualFold(u.Host, b.Host) {
		return ""
	}
	u.Fragment = ""
	return u.String()
}

func isStaticURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	p := strings.ToLower(u.Path)
	for _, ext := range staticExts {
		if strings.HasSuffix(p, ext) {
			return true
		}
	}
	return false
}
