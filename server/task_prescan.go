package server

import (
	"context"
	"fmt"
	"log"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/jingwei/db"
	"github.com/Autumn-27/jingwei/scanner"
)

// prescanPortSpec keeps the prescan on the explicitly requested port when the
// goal names a non-standard one (e.g. a CTF sandbox at host:10800). Expanding
// to the whole web port set would reach unrelated services that share the same
// host/IP, which is out of scope for that goal.
func prescanPortSpec(port int) string {
	if port <= 0 || port == 80 || port == 443 {
		return "web"
	}
	return strconv.Itoa(port)
}

// prescanTask runs a bounded asset-discovery + POC pre-screen before the planner's
// first round, so an LLM task starts from structured reconnaissance instead of the
// goal text alone. This is the code-side enforcement of #96「先探测后渗透」: the
// discovery results are persisted as assets (and POC hits as findings), and a
// summary fact node is written so the planner's graph overview surfaces them.
// Best-effort: any failure is logged and the task proceeds without pre-scan data.
func (s *Server) prescanTask(ctx context.Context, t *Task) {
	if s.m == nil || s.m.Assets() == nil || t == nil {
		return
	}
	scheme, host, port, ok := parseTarget(t.Goal)
	if !ok {
		scheme, host, port, ok = parseTarget(t.Description)
	}
	if !ok {
		return
	}
	if gw := s.llmHost(); gw != "" && host == gw {
		return
	}
	rawURL := scheme + "://" + host
	if !(scheme == "https" && port == 443) && !(scheme == "http" && port == 80) {
		rawURL += ":" + strconv.Itoa(port)
	}
	targets, err := scanner.ParseTargets([]string{rawURL})
	if err != nil {
		log.Printf("[prescan] task %s: %v", t.ID, err)
		return
	}
	rules, err := s.m.PG().ListAssetInterceptRules()
	if err == nil {
		if reason, blocked := scanTargetBlockReason(rules, targets); blocked {
			log.Printf("[prescan] task %s: 目标命中拦截规则，跳过预扫: %s", t.ID, reason)
			return
		}
	}

	s.engine.emitActivity(t, db.Activity{Worker: "planner", Kind: "round", Summary: "第 0 轮资产发现 + POC 初筛"})

	res, err := scanner.Discover(ctx, targets, scanner.DiscoverOptions{
		Ports: prescanPortSpec(port), Concurrency: 200, Timeout: 900 * time.Millisecond,
		MaxProbes: 3000, MaxPortChecks: maxScanPortChecks,
		Logf: func(format string, args ...any) { log.Printf("[prescan "+t.ID+"] "+format, args...) },
	})
	if err != nil {
		log.Printf("[prescan] task %s: 资产发现失败: %v", t.ID, err)
		return
	}
	apps, _ := scanner.AppDiscover(ctx, res.Services, scanner.AppDiscoverOptions{
		MaxCandidates: 240, Concurrency: 8, Timeout: 8 * time.Second,
		Logf: func(format string, args ...any) { log.Printf("[prescan "+t.ID+"] "+format, args...) },
	})

	taskID, _ := strconv.ParseInt(t.ID, 10, 64)
	as := s.m.Assets()
	summary := prescanPersist(t, as, taskID, host, res, apps)

	templates := prescanTemplates(s.m.PG(), res.Services, apps)
	pocHits := 0
	if len(templates) > 0 {
		nrun := scanner.RunNuclei(ctx, templates, prescanNucleiTargets(res, targets, apps), scanner.NucleiOptions{
			RateLimit: 100, Concurrency: 8, TimeoutSeconds: 120,
		})
		pocHits = prescanPersistHits(ctx, t, taskID, res, apps, nrun.Results)
	}

	summary["poc_hits"] = pocHits
	if origin, err := t.Store.OriginFactID(); err == nil && origin > 0 {
		_, _ = t.Store.AddNode(db.KindFact, map[string]any{
			"text": fmt.Sprintf("预扫完成：开放端口 %d、Web 服务 %d、应用系统 %d、POC 命中 %d",
				summary["open_ports"], summary["services"], summary["app_systems"], pocHits),
			"prescan": summary,
		}, 5, "confirmed", "system", []int64{origin})
	}
	log.Printf("[prescan] task %s 完成: %v", t.ID, summary)
}

// prescanPersist writes discovery + app-layer results into the shared asset
// ledger (tagged with the task id and auto-scope) and returns a small digest.
func prescanPersist(t *Task, as *db.AssetStore, taskID int64, seedHost string, res *scanner.DiscoverResult, apps []scanner.AppSystem) map[string]any {
	summary := map[string]any{"resolved_ips": len(res.Resolved.IPs), "open_ports": len(res.Ports), "services": len(res.Services)}

	portsByIP := map[string][]db.PortService{}
	for _, pf := range res.Ports {
		label := pf.Service
		if label == "" {
			label = "tcp"
		}
		portsByIP[pf.IP] = append(portsByIP[pf.IP], db.PortService{Port: pf.Port, Service: label})
	}
	serviceIPs := map[string]bool{}
	for _, svc := range res.Services {
		if svc.IP != "" {
			serviceIPs[svc.IP] = true
		}
	}
	for _, ip := range res.Resolved.IPs {
		ports := portsByIP[ip]
		if len(ports) == 0 && !serviceIPs[ip] {
			continue
		}
		sort.Slice(ports, func(i, j int) bool { return ports[i].Port < ports[j].Port })
		id, err := as.UpsertIP(db.UpsertIPReq{IP: ip, OpenPorts: ports, TaskID: taskID})
		if err == nil && id > 0 {
			_ = as.SetTaskAssetSource(taskID, id, "task", "预扫端口探测", nil)
		}
	}
	for _, svc := range res.Services {
		status := svc.StatusCode
		length := svc.ContentLength
		id, err := as.UpsertHTTPService(db.UpsertHTTPServiceReq{
			URL: svc.URL, Technologies: svc.Technologies, StatusCode: &status,
			ContentLength: &length, PageTitle: svc.Title, IP: svc.IP, TaskID: taskID,
		})
		if err == nil && id > 0 {
			_ = as.SetTaskAssetSource(taskID, id, "task", "预扫 Web 服务", nil)
			_ = as.AddAutoScope(taskID, "service", "", svc.URL, svc.IP)
		}
	}
	for _, app := range apps {
		status := app.StatusCode
		length := app.ContentLength
		id, err := as.UpsertHTTPService(db.UpsertHTTPServiceReq{
			URL: app.URL, Technologies: app.Technologies, StatusCode: &status,
			ContentLength: &length, PageTitle: app.Title, IP: app.IP, TaskID: taskID,
		})
		if err == nil && id > 0 {
			_ = as.SetTaskAssetSource(taskID, id, "task", "预扫应用层系统", nil)
			_ = as.AddAutoScope(taskID, "service", "", app.URL, app.IP)
		}
	}
	summary["app_systems"] = len(apps)

	if net.ParseIP(seedHost) == nil {
		_ = as.AddAutoScope(taskID, "subdomain", seedHost, "", "")
	} else {
		_ = as.AddAutoScope(taskID, "service", "", rawURLOf(seedHost, 0), seedHost)
	}
	return summary
}

// prescanTemplates selects POC templates by fingerprint match (the same
// auto-mode logic as the LLM-free scanner), capped for a fast pre-screen.
func prescanTemplates(pg *db.DB, services []scanner.WebService, apps []scanner.AppSystem) []scanner.NucleiTemplate {
	techSet := map[string]bool{}
	all := append(append([]scanner.WebService{}, services...), appsToServices(apps)...)
	for _, svc := range all {
		for _, tech := range svc.Technologies {
			techSet[tech] = true
		}
	}
	techs := make([]string, 0, len(techSet))
	for tech := range techSet {
		techs = append(techs, tech)
	}
	sort.Strings(techs)
	if len(techs) == 0 {
		return nil
	}
	metas, err := pg.ListEnabledPOCMetadata()
	if err != nil {
		return nil
	}
	smeta := make([]scanner.TemplateMeta, 0, len(metas))
	for _, p := range metas {
		if p.Protocol == "workflow" {
			continue
		}
		smeta = append(smeta, scanner.TemplateMeta{ID: p.ID, TemplateID: p.TemplateID, Name: p.Name, Tags: p.Tags})
	}
	ids := scanner.MatchTemplates(techs, smeta)
	if len(ids) == 0 {
		return nil
	}
	if len(ids) > maxAutoTemplates {
		ids = ids[:maxAutoTemplates]
	}
	pocs, err := pg.POCTemplatesByIDs(ids)
	if err != nil {
		return nil
	}
	out := make([]scanner.NucleiTemplate, 0, len(pocs))
	seen := map[string]bool{}
	for _, p := range pocs {
		if p.Protocol == "workflow" || strings.TrimSpace(p.Content) == "" || seen[p.TemplateID] {
			continue
		}
		seen[p.TemplateID] = true
		out = append(out, scanner.NucleiTemplate{ID: p.TemplateID, Content: p.Content})
	}
	return out
}

func appsToServices(apps []scanner.AppSystem) []scanner.WebService {
	out := make([]scanner.WebService, 0, len(apps))
	for _, app := range apps {
		out = append(out, scanner.WebService{
			URL: app.URL, Host: app.Host, IP: app.IP, Port: app.Port, Scheme: app.Scheme,
			StatusCode: app.StatusCode, Title: app.Title, Server: app.Server,
			Technologies: app.Technologies, ContentLength: app.ContentLength,
		})
	}
	return out
}

// prescanNucleiTargets builds a small, high-signal target list for the pre-screen:
// every discovered web service plus non-web open ports.
func prescanNucleiTargets(res *scanner.DiscoverResult, raw []scanner.Target, apps []scanner.AppSystem) []string {
	seen := map[string]bool{}
	var out []string
	add := func(v string) {
		v = strings.TrimSpace(v)
		if v == "" || seen[v] {
			return
		}
		seen[v] = true
		out = append(out, v)
	}
	for _, svc := range res.Services {
		add(svc.URL)
	}
	for _, pf := range res.Ports {
		if scanner.IsWebPort(pf.Port) {
			continue
		}
		add(net.JoinHostPort(pf.IP, strconv.Itoa(pf.Port)))
	}
	if len(out) == 0 {
		for _, t := range raw {
			if t.Kind == scanner.KindURL {
				add(t.URL)
			} else if t.Kind != scanner.KindCIDR {
				add(t.Host)
			}
		}
	}
	return out
}

// prescanPersistHits records nuclei POC hits as findings in the exploration graph
// so the planner's list_findings can see them.
func prescanPersistHits(ctx context.Context, t *Task, taskID int64, res *scanner.DiscoverResult, apps []scanner.AppSystem, results []scanner.NucleiResult) int {
	if t == nil || t.Store == nil {
		return 0
	}
	count := 0
	for _, r := range results {
		sev := strings.ToLower(strings.TrimSpace(r.Severity))
		if sev == "" {
			sev = "info"
		}
		in := db.RecordFindingInput{
			TaskID: taskID, ExplorationID: t.ExpID,
			VulnClass:   "nuclei-" + r.TemplateID,
			Name:        firstNonEmpty(r.Name, r.TemplateID),
			Severity:    sev,
			Summary:     fmt.Sprintf("POC 初筛命中：%s 于 %s", r.TemplateID, r.Host),
			Evidence:    firstNonEmpty(r.Curl, r.MatchedAt),
			Worker:      "prescan",
			Protocol:    "http",
			RawRequest:  r.Request,
			RawResponse: r.Response,
		}
		if _, err := t.Store.RecordFinding(ctx, in); err != nil {
			log.Printf("[prescan] task %s: 写入 POC 命中失败 %s: %v", t.ID, r.TemplateID, err)
			continue
		}
		count++
	}
	return count
}

func firstNonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}

func rawURLOf(host string, port int) string {
	if port == 0 {
		return "http://" + host
	}
	return "http://" + net.JoinHostPort(host, strconv.Itoa(port))
}
