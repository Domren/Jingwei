package db

import (
	"encoding/json"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// Finding systems — the「按任务 → 系统」view of the global findings list.
//
// 一条发现的「系统」取它关联资产里最具体的一台主机/服务:service → endpoint →
// app → subdomain → ip → root_domain。端口可用时 key 为 "svc:<host>:<port>",
// 否则为 "host:<host>";没有任何可用资产时归入 "__none__"。同一条发现只归一个
// 系统,计数不会重复。
// ---------------------------------------------------------------------------

// FindingUnassignedSystem is the system key for findings without a resolvable
// linked asset (none linked, or all linked assets deleted).
const FindingUnassignedSystem = "__none__"

// FindingSystemGroup is one system bucket: a host:port (or bare host) and the
// matching findings' counts.
type FindingSystemGroup struct {
	System      string    `json:"system"`
	Label       string    `json:"label"`
	Host        string    `json:"host,omitempty"`
	Port        int       `json:"port,omitempty"`
	Service     string    `json:"service,omitempty"`
	Count       int       `json:"count"`
	Critical    int       `json:"critical"`
	High        int       `json:"high"`
	Medium      int       `json:"medium"`
	Low         int       `json:"low"`
	LastFoundAt time.Time `json:"last_found_at"`
}

// systemAsset is the asset subset needed to resolve a finding's system.
type systemAsset struct {
	kind        string
	domain      string
	ip          string
	url         string
	port        int
	serviceType string
	serviceName string
	appName     string
}

// systemRank orders asset kinds by specificity; lower wins.
func systemRank(kind string) int {
	switch kind {
	case "service":
		return 0
	case "endpoint":
		return 1
	case "app":
		return 2
	case "subdomain":
		return 3
	case "ip":
		return 4
	case "root_domain":
		return 5
	}
	return 9
}

// systemInfo derives the system key/label for one asset. ok=false when the asset
// carries no usable host (e.g. an app row with only a name is handled separately).
func (a systemAsset) systemInfo() (key, label, host string, port int, service string) {
	host = strings.TrimSpace(a.domain)
	if host == "" {
		host = strings.TrimSpace(a.ip)
	}
	port = a.port
	if a.url != "" {
		uh, up := splitURLHost(a.url)
		if host == "" {
			host = uh
		}
		if port == 0 {
			port = up
		}
	}
	switch a.kind {
	case "service":
		service = a.serviceName
		if service == "" {
			service = a.serviceType
		}
	case "endpoint":
		service = "http"
	case "app":
		service = "app"
	}
	if host == "" {
		if a.kind == "app" && a.appName != "" {
			host = a.appName
			key = "app:" + host
			return key, host, host, 0, service
		}
		return "", "", "", 0, ""
	}
	host = strings.ToLower(host)
	label = host
	if port > 0 {
		key = "svc:" + host + ":" + strconv.Itoa(port)
		label = host + ":" + strconv.Itoa(port)
	} else {
		key = "host:" + host
	}
	return key, label, host, port, service
}

// splitURLHost parses the host and effective port from a URL. Scheme-less values
// are accepted ("10.0.0.1:8080/login"), and http/https default ports applied.
func splitURLHost(raw string) (string, int) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", 0
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		u, err = url.Parse("//" + raw)
		if err != nil {
			return "", 0
		}
	}
	host := u.Hostname()
	if host == "" {
		return "", 0
	}
	port := 0
	if p := u.Port(); p != "" {
		port, _ = strconv.Atoi(p)
	}
	if port == 0 {
		switch strings.ToLower(u.Scheme) {
		case "http":
			port = 80
		case "https":
			port = 443
		}
	}
	return host, port
}

// findingSystemHit is one finding matched by the current filter, resolved to its
// primary system.
type findingSystemHit struct {
	id        int64
	severity  string
	createdAt time.Time
	key       string
	label     string
	host      string
	port      int
	service   string
}

// findingSystemHits resolves every finding matching f (system filter ignored) to
// its primary system. Assets referenced by the matched findings are loaded in one
// query; findings whose assets are all missing fall into FindingUnassignedSystem.
func (d *DB) findingSystemHits(f FindingFilter) ([]findingSystemHit, error) {
	f.System = ""
	f.systemFilter = false
	f.systemIDs = nil
	where, args := f.where()
	rows, err := d.Query(`SELECT f.id, COALESCE(f.severity,''), f.created_at, COALESCE(f.asset_ids::text,'[]')
FROM findings f LEFT JOIN tasks t ON f.task_id = t.id`+where, args...)
	if err != nil {
		return nil, err
	}
	type rawHit struct {
		id       int64
		severity string
		created  time.Time
		assetIDs []int64
	}
	var raw []rawHit
	want := map[int64]bool{}
	for rows.Next() {
		var h rawHit
		var aidsJSON string
		if err := rows.Scan(&h.id, &h.severity, &h.created, &aidsJSON); err != nil {
			rows.Close()
			return nil, err
		}
		_ = json.Unmarshal([]byte(aidsJSON), &h.assetIDs)
		for _, id := range h.assetIDs {
			if id > 0 {
				want[id] = true
			}
		}
		raw = append(raw, h)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()

	assets := map[int64]systemAsset{}
	if len(want) > 0 {
		ids := make([]int64, 0, len(want))
		for id := range want {
			ids = append(ids, id)
		}
		arows, err := d.Query(`SELECT id, type, COALESCE(domain,''), COALESCE(ip,''), COALESCE(url,''),
       COALESCE(port,0), COALESCE(service_type,''), COALESCE(service_name,''), COALESCE(app_name,'')
FROM assets WHERE id = ANY($1::bigint[])`, ids)
		if err != nil {
			return nil, err
		}
		for arows.Next() {
			var id int64
			var a systemAsset
			if err := arows.Scan(&id, &a.kind, &a.domain, &a.ip, &a.url, &a.port,
				&a.serviceType, &a.serviceName, &a.appName); err != nil {
				arows.Close()
				return nil, err
			}
			assets[id] = a
		}
		if err := arows.Err(); err != nil {
			arows.Close()
			return nil, err
		}
		arows.Close()
	}

	out := make([]findingSystemHit, 0, len(raw))
	for _, h := range raw {
		hit := findingSystemHit{id: h.id, severity: h.severity, createdAt: h.created}
		best := 10
		for _, id := range h.assetIDs {
			a, ok := assets[id]
			if !ok {
				continue
			}
			key, label, host, port, service := a.systemInfo()
			if key == "" {
				continue
			}
			if rank := systemRank(a.kind); rank < best {
				best = rank
				hit.key, hit.label, hit.host, hit.port, hit.service = key, label, host, port, service
			}
		}
		if hit.key == "" {
			hit.key, hit.label = FindingUnassignedSystem, "未关联系统"
		}
		out = append(out, hit)
	}
	return out, nil
}

// applySystemScope resolves f.System (a system key) to the ids of findings whose
// primary system matches, so every list/group/export query can share the same
// definition. An unknown key yields an empty id set (and therefore no rows).
func (d *DB) applySystemScope(f FindingFilter) (FindingFilter, error) {
	f.systemFilter, f.systemIDs = false, nil
	key := strings.TrimSpace(f.System)
	if key == "" {
		return f, nil
	}
	hits, err := d.findingSystemHits(f)
	if err != nil {
		return f, err
	}
	f.systemFilter = true
	for _, h := range hits {
		if h.key == key {
			f.systemIDs = append(f.systemIDs, h.id)
		}
	}
	return f, nil
}

// applyFindingScopes applies both the asset-tree and system filters. Callers that
// reach a list query must go through this so the two filters compose.
func (d *DB) applyFindingScopes(f FindingFilter) (FindingFilter, error) {
	f, err := d.applyAssetScope(f)
	if err != nil {
		return f, err
	}
	return d.applySystemScope(f)
}

// ListFindingSystemGroups returns the system buckets of the findings matching f,
// optionally scoped to one task via f.TaskID (the UI expands a task group with
// that filter). Groups are ordered by severity weight, then size, then recency;
// the counts are independent of pagination.
func (d *DB) ListFindingSystemGroups(f FindingFilter, page, pageSize int) ([]FindingSystemGroup, int, int, error) {
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 {
		pageSize = 50
	}
	requested := strings.TrimSpace(f.System)
	hits, err := d.findingSystemHits(f)
	if err != nil {
		return nil, 0, 0, err
	}
	byKey := map[string]*FindingSystemGroup{}
	findingTotal := 0
	for _, h := range hits {
		if requested != "" && h.key != requested {
			continue
		}
		g := byKey[h.key]
		if g == nil {
			g = &FindingSystemGroup{
				System: h.key, Label: h.label, Host: h.host, Port: h.port, Service: h.service,
			}
			byKey[h.key] = g
		}
		g.Count++
		findingTotal++
		switch h.severity {
		case "critical":
			g.Critical++
		case "high":
			g.High++
		case "medium":
			g.Medium++
		case "low":
			g.Low++
		}
		if h.createdAt.After(g.LastFoundAt) {
			g.LastFoundAt = h.createdAt
		}
	}
	groups := make([]FindingSystemGroup, 0, len(byKey))
	for _, g := range byKey {
		groups = append(groups, *g)
	}
	sort.SliceStable(groups, func(i, j int) bool {
		a, b := groups[i], groups[j]
		wa := a.Critical*1000 + a.High*100 + a.Medium*10 + a.Low
		wb := b.Critical*1000 + b.High*100 + b.Medium*10 + b.Low
		if wa != wb {
			return wa > wb
		}
		if a.Count != b.Count {
			return a.Count > b.Count
		}
		if !a.LastFoundAt.Equal(b.LastFoundAt) {
			return a.LastFoundAt.After(b.LastFoundAt)
		}
		return a.Label < b.Label
	})
	total := len(groups)
	start := (page - 1) * pageSize
	if start >= total {
		return []FindingSystemGroup{}, total, findingTotal, nil
	}
	end := start + pageSize
	if end > total {
		end = total
	}
	return groups[start:end], total, findingTotal, nil
}
