package scanner

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

// 目录枚举（C1）：字典 + 扩展名 + 状态码/长度过滤 + 每行可复现的请求与响应字节。
//
// 误报控制的三道闸：
//  1. 软 404 基线：先请求一个随机路径，得到站点对「不存在」的默认响应；
//     与基线同状态、同长度的候选一律不报——SPA 和自定义 404 是误报的两大来源。
//  2. 同长同码去重：状态与长度都相同的条目只保留第一条，其余计数丢弃，
//     避免把「所有路径返回同一个页面」的站点灌满几千行。
//  3. 状态码过滤：默认排除 404；403 保留（它是「存在但禁止访问」的信号），
//     但会标在 source 上，报告里不与 200 混为一谈。
//
// 并发/限速/预算与弱口令引擎同一套纪律：速率限制用 ticker，预算用派生 context，
// 到点后剩余候选记为跳过并在结果里写明——少一条就是报告里的一句假话。

type DirFuzzOptions struct {
	Words       []string
	Extensions  []string
	Concurrency int
	RateLimit   int
	Budget      time.Duration
	MaxRequests int
	// ExcludeStatus 默认 [404]；Soft404Lengths 由基线自动填充。
	ExcludeStatus []int
	Proxy         string
	Logf          func(format string, args ...any)
}

type DirEntry struct {
	Path     string `json:"path"`
	URL      string `json:"url"`
	Status   int    `json:"status"`
	Length   int64  `json:"length"`
	Location string `json:"location,omitempty"`
	Source   string `json:"source"`
	// Request/Response 是逐字节证据（响应只保留头部+前 2KB 正文）。
	Request  []byte `json:"-"`
	Response []byte `json:"-"`
}

const (
	dirDefaultConcurrency = 20
	dirDefaultBudget      = 3 * time.Minute
	dirDefaultMaxRequests = 4000
	dirMaxBodyKeep        = 2 << 10
)

// dirWordlist 是内置的精简目录字典：高信号优先，不做全量爆破。
// 与 appPathDictionary 的区别：这里包含文件（备份、配置、源码）而不仅是目录，
// 扩展名由调用方组合；条目不带前导 /。
var dirWordlist = []string{
	"admin", "administrator", "login", "logout", "dashboard", "manage", "manager",
	"api", "api/v1", "api/v2", "v1", "v2", "graphql", "swagger", "swagger-ui",
	"openapi.json", "api-docs", "v2/api-docs", "v3/api-docs", "actuator", "actuator/health",
	"actuator/env", "health", "healthz", "status", "metrics", "debug", "info", "console",
	"druid", "druid/index.html", "jenkins", "solr", "kibana", "elasticsearch", "phpmyadmin",
	"pma", "adminer.php", "nacos", "eureka", "config", "config.json", "config.php",
	"config.yaml", "config.yml", "config.ini", ".env", ".git/config", ".svn/entries",
	".DS_Store", "robots.txt", "sitemap.xml", "crossdomain.xml", "clientaccesspolicy.xml",
	"install", "setup", "wizard", "backup", "bak", "old", "new", "temp", "tmp", "test",
	"demo", "dev", "docs", "doc", "readme", "readme.md", "README.md", "CHANGELOG.md",
	"upload", "uploads", "files", "file", "download", "static", "assets", "public",
	"web.config", "WEB-INF/web.xml", "META-INF/MANIFEST.MF", "server-status", "server-info",
	"phpinfo.php", "info.php", "test.php", "shell.php", "webshell.php", "cmd.php",
	"db.sql", "dump.sql", "database.sql", "backup.sql", "data.sql", "www.zip", "web.zip",
	"backup.zip", "backup.tar.gz", "site.tar.gz", "source.zip", "src.zip", "code.zip",
	"wwwroot.zip", "htaccess.txt", ".htaccess", ".htpasswd", "id_rsa", "id_dsa",
	"wp-admin", "wp-login.php", "wp-config.php", "xmlrpc.php", "wp-json",
	"user/login", "member/login", "admin/login", "login.do", "main.do", "index.php/admin",
	"console/login/LoginForm.jsp", "wls-wsat", "host-manager/html", "manager/html",
	"cgi-bin/", "ueditor", "kindeditor", "fckeditor", "ckeditor",
	"WEB-INF/classes/", "WEB-INF/lib/", "api/swagger.json", "api/openapi.json",
	"admin.php", "manage.php", "login.php", "index.php.bak", "index.php~",
}

func dirOptionsDefault(o DirFuzzOptions) DirFuzzOptions {
	if len(o.Words) == 0 {
		o.Words = dirWordlist
	}
	if o.Concurrency <= 0 {
		o.Concurrency = dirDefaultConcurrency
	}
	if o.Concurrency > 64 {
		o.Concurrency = 64
	}
	if o.Budget <= 0 {
		o.Budget = dirDefaultBudget
	}
	if o.MaxRequests <= 0 {
		o.MaxRequests = dirDefaultMaxRequests
	}
	if len(o.ExcludeStatus) == 0 {
		o.ExcludeStatus = []int{404}
	}
	return o
}

// dirCandidates 组合字典与扩展名。带 / 的条目与已带扩展名的条目不追加扩展名。
func dirCandidates(words, extensions []string) []string {
	seen := map[string]bool{}
	out := []string{}
	add := func(p string) {
		p = strings.TrimPrefix(strings.TrimSpace(p), "/")
		if p == "" || seen[p] {
			return
		}
		seen[p] = true
		out = append(out, p)
	}
	for _, w := range words {
		add(w)
		if strings.HasSuffix(w, "/") || strings.Contains(filepathBase(w), ".") {
			continue
		}
		for _, ext := range extensions {
			ext = strings.TrimPrefix(strings.TrimSpace(ext), ".")
			if ext != "" {
				add(w + "." + ext)
			}
		}
	}
	return out
}

func filepathBase(p string) string {
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[i+1:]
	}
	return p
}

// dirFetch 发一次请求并留下请求/响应字节。响应只保留头部与前 2KB 正文：
// 目录枚举的证据是「这个路径返回了什么」，不是整页源码。
func dirFetch(ctx context.Context, client *http.Client, rawURL string) (status int, length int64, location string, req, resp []byte, err error) {
	reqObj, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return 0, 0, "", nil, nil, err
	}
	ApplyBrowserUA(reqObj.Header.Set, reqObj.Header.Del)
	reqObj.Header.Set("Accept", "*/*")
	req = []byte(fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\n%sAccept: */*\r\n\r\n",
		reqObj.URL.RequestURI(), reqObj.URL.Host, uaHeaderLine()))
	res, err := client.Do(reqObj)
	if err != nil {
		return 0, 0, "", req, nil, err
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(res.Body, dirMaxBodyKeep+1))
	length = res.ContentLength
	if length < 0 {
		length = int64(len(body))
	}
	var head strings.Builder
	fmt.Fprintf(&head, "HTTP/1.1 %d %s\r\n", res.StatusCode, http.StatusText(res.StatusCode))
	for k, vs := range res.Header {
		for _, v := range vs {
			fmt.Fprintf(&head, "%s: %s\r\n", k, v)
		}
	}
	head.WriteString("\r\n")
	if len(body) > dirMaxBodyKeep {
		body = body[:dirMaxBodyKeep]
	}
	resp = append([]byte(head.String()), body...)
	return res.StatusCode, length, res.Header.Get("Location"), req, resp, nil
}

func dirClient(proxy string) (*http.Client, error) {
	tr := &http.Transport{MaxIdleConns: 64, MaxIdleConnsPerHost: 16, IdleConnTimeout: 30 * time.Second}
	if strings.TrimSpace(proxy) != "" {
		u, err := NormalizeProxyURL(proxy)
		if err != nil {
			return nil, err
		}
		pu, err := url.Parse(u)
		if err != nil {
			return nil, err
		}
		tr.Proxy = http.ProxyURL(pu)
	}
	return &http.Client{
		Transport: tr,
		Timeout:   10 * time.Second,
		// 重定向本身就是枚举结果（301/302 指向哪里是重要信号），不能被客户端悄悄跟走。
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}, nil
}

// DirFuzz 枚举 base 下的路径。返回的每一项都带请求与响应字节。
func DirFuzz(ctx context.Context, base string, opts DirFuzzOptions) ([]DirEntry, error) {
	opts = dirOptionsDefault(opts)
	baseURL, err := url.Parse(strings.TrimRight(base, "/") + "/")
	if err != nil {
		return nil, err
	}
	client, err := dirClient(opts.Proxy)
	if err != nil {
		return nil, err
	}
	logf := opts.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}
	runCtx, cancel := context.WithTimeout(ctx, opts.Budget)
	defer cancel()

	// 软 404 基线：随机 16 字节路径。
	randBuf := make([]byte, 16)
	_, _ = rand.Read(randBuf)
	probe := baseURL.ResolveReference(&url.URL{Path: "/" + hex.EncodeToString(randBuf)}).String()
	baseStatus, baseLen, _, _, _, err := dirFetch(runCtx, client, probe)
	if err != nil {
		return nil, fmt.Errorf("软 404 基线请求失败: %w", err)
	}
	logf("目录枚举基线：随机路径返回 %d / %d 字节", baseStatus, baseLen)

	candidates := dirCandidates(opts.Words, opts.Extensions)
	if len(candidates) > opts.MaxRequests {
		candidates = candidates[:opts.MaxRequests]
	}

	var rate <-chan time.Time
	if opts.RateLimit > 0 {
		tick := time.NewTicker(time.Second / time.Duration(opts.RateLimit))
		defer tick.Stop()
		rate = tick.C
	}

	excluded := map[int]bool{}
	for _, s := range opts.ExcludeStatus {
		excluded[s] = true
	}
	var mu sync.Mutex
	raw := []DirEntry{}

	sem := make(chan struct{}, opts.Concurrency)
	var wg sync.WaitGroup

	for _, cand := range candidates {
		if runCtx.Err() != nil {
			break
		}
		sem <- struct{}{}
		wg.Add(1)
		go func(p string) {
			defer wg.Done()
			defer func() { <-sem }()
			if rate != nil {
				select {
				case <-rate:
				case <-runCtx.Done():
					return
				}
			}
			u := baseURL.ResolveReference(&url.URL{Path: "/" + p}).String()
			status, length, location, req, resp, err := dirFetch(runCtx, client, u)
			if err != nil {
				return
			}
			if excluded[status] {
				return
			}
			// 与软 404 基线同状态同长度：这是站点对不存在路径的默认响应。
			if status == baseStatus && length == baseLen {
				return
			}
			source := "dict"
			if status == 403 {
				source = "dict-forbidden"
			}
			mu.Lock()
			raw = append(raw, DirEntry{Path: "/" + p, URL: u, Status: status,
				Length: length, Location: location, Source: source, Request: req, Response: resp})
			mu.Unlock()
		}(cand)
	}
	wg.Wait()
	// 同长同码去重必须确定：并发下「谁先到」是随机的，按到达顺序保留会让同一个
	// 站点两次跑出不同的入口清单。规则改成：同 (状态, 长度) 组里保留**最短路径**
	// （平局按字典序），其余计为抑制。
	type groupKey struct {
		status int
		length int64
	}
	best := map[groupKey]int{}
	for i, e := range raw {
		k := groupKey{e.Status, e.Length}
		if j, ok := best[k]; !ok || len(e.Path) < len(raw[j].Path) ||
			(len(e.Path) == len(raw[j].Path) && e.Path < raw[j].Path) {
			best[k] = i
		}
	}
	keep := map[int]bool{}
	for _, i := range best {
		keep[i] = true
	}
	results := []DirEntry{}
	suppressed := 0
	for i, e := range raw {
		if keep[i] {
			results = append(results, e)
		} else {
			suppressed++
		}
	}
	sort.SliceStable(results, func(i, j int) bool { return results[i].URL < results[j].URL })
	logf("目录枚举完成：候选 %d 个，有效 %d 条，同长同码抑制 %d 条（预算 %s）",
		len(candidates), len(results), suppressed, opts.Budget)
	return results, nil
}
