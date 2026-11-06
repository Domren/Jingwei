package server

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/jingwei/db"
	"github.com/Autumn-27/jingwei/scanner"
)

// 子域名枚举（C3）：任务、执行与资产落库。
//
// 三条纪律：
//
//   - **范围闸问两次**。第一次在建任务与执行前：根域名不在客户授权清单里就整单拒绝；
//     第二次在端口探测前：解析出来的 IP 是新主机，授权清单里可能根本没写过它们，
//     这时只跳过探测、不销毁已经拿到的名字，并把「为什么没探」写进任务日志。
//     探测会真发包，跳过它永远是更安全的那一边。
//   - **公开接口默认关**。查 crt.sh 会把客户的根域名发给第三方，这件事授权清单管不住，
//     所以必须由操作员显式勾选，且界面与报告都要说明发出去了什么。
//   - **结果两处都记**。台账（subdomain_results）回答「这一轮枚举出了什么、哪来的」，
//     资产（subdomain/ip 行）让拓扑图与端口探测拿得到东西。只记一处就是要人手工搬运。

const (
	subdomainProgressPeriod = 2 * time.Second
	subdomainDefaultPorts   = "top100"
	subdomainDefaultTimeout = 3
	subdomainDefaultProbeMS = 900
)

// 引擎入口做成变量：用例换成假引擎，就能在没有 DNS、没有外网的环境里验证
// 「结果如何落库、范围闸何时生效」这些真正会出错的部分。
var (
	subdomainEnumerate = scanner.EnumerateSubdomains
	subdomainDiscover  = scanner.Discover
	subdomainResolver  = func(timeout time.Duration) scanner.SubdomainResolver {
		return scanner.NewSystemSubdomainResolver(timeout)
	}
)

type subdomainManager struct {
	s    *Server
	wake chan struct{}

	mu     sync.Mutex
	cancel map[int64]context.CancelFunc
}

func newSubdomainManager(s *Server) *subdomainManager {
	return &subdomainManager{s: s, wake: make(chan struct{}, 1), cancel: map[int64]context.CancelFunc{}}
}

func (m *subdomainManager) start(ctx context.Context) {
	if m == nil || m.s.m.pg == nil {
		return
	}
	if n, err := m.s.m.pg.RecoverInterruptedSubdomainTasks(); err != nil {
		log.Printf("[subdomain] recover interrupted tasks: %v", err)
	} else if n > 0 {
		log.Printf("[subdomain] 启动时将 %d 个中断的子域名枚举任务标记为失败", n)
	}
	go m.loop(ctx)
}

func (m *subdomainManager) wakeup() {
	select {
	case m.wake <- struct{}{}:
	default:
	}
}

func (m *subdomainManager) loop(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		if ctx.Err() != nil {
			return
		}
		for {
			task, err := m.s.m.pg.ClaimNextSubdomainTask()
			if err != nil {
				log.Printf("[subdomain] claim queued task: %v", err)
				break
			}
			if task == nil {
				break
			}
			m.run(ctx, task)
		}
		select {
		case <-ctx.Done():
			return
		case <-m.wake:
		case <-ticker.C:
		}
	}
}

func (m *subdomainManager) cancelTask(id int64) bool {
	m.mu.Lock()
	cancel, ok := m.cancel[id]
	m.mu.Unlock()
	if ok {
		cancel()
	}
	return ok
}

func (m *subdomainManager) run(parent context.Context, task *db.SubdomainTask) {
	ctx, cancel := context.WithCancel(parent)
	m.mu.Lock()
	m.cancel[task.ID] = cancel
	m.mu.Unlock()
	defer func() {
		cancel()
		m.mu.Lock()
		delete(m.cancel, task.ID)
		m.mu.Unlock()
	}()

	r := &subdomainRun{s: m.s, pg: m.s.m.pg, task: task, ctx: ctx}
	status, errMsg, summary := r.execute()
	if err := m.s.m.pg.FinishSubdomainTask(task.ID, status, summary, errMsg); err != nil {
		log.Printf("[subdomain %d] finish: %v", task.ID, err)
	}
}

// subdomainRun 是一次枚举执行的全部上下文。
type subdomainRun struct {
	s    *Server
	pg   *db.DB
	task *db.SubdomainTask
	ctx  context.Context
}

// subdomainSettings 是任务 options 里操作员能改的东西。
type subdomainSettings struct {
	Words        []string
	Concurrency  int
	TimeoutSecs  int
	MaxQueries   int
	Sources      []string
	KeepWildcard bool
	ProbePorts   bool
	Ports        string
	ProbeTimeout int // 毫秒
}

func subdomainSettingsFrom(options map[string]any) subdomainSettings {
	set := subdomainSettings{
		Concurrency:  subOptionInt(options["concurrency"], 16),
		TimeoutSecs:  subOptionInt(options["timeout_seconds"], subdomainDefaultTimeout),
		MaxQueries:   subOptionInt(options["max_queries"], 20000),
		Ports:        strings.TrimSpace(asString(options["ports"])),
		ProbeTimeout: subOptionInt(options["probe_timeout_ms"], subdomainDefaultProbeMS),
		ProbePorts:   true,
	}
	if v, ok := options["probe_ports"].(bool); ok {
		set.ProbePorts = v
	}
	if v, ok := options["keep_wildcard"].(bool); ok {
		set.KeepWildcard = v
	}
	if raw, ok := options["words"].(string); ok {
		for _, w := range strings.FieldsFunc(raw, func(r rune) bool {
			return r == '\n' || r == ',' || r == ' ' || r == '\t'
		}) {
			if w = strings.TrimSpace(w); w != "" {
				set.Words = append(set.Words, w)
			}
		}
	}
	if arr, ok := options["words"].([]any); ok {
		for _, v := range arr {
			if w := strings.TrimSpace(asString(v)); w != "" {
				set.Words = append(set.Words, w)
			}
		}
	}
	if arr, ok := options["public_sources"].([]any); ok {
		for _, v := range arr {
			if s := strings.ToLower(strings.TrimSpace(asString(v))); s != "" {
				set.Sources = append(set.Sources, s)
			}
		}
	}
	if set.Concurrency <= 0 || set.Concurrency > 64 {
		set.Concurrency = 16
	}
	if set.TimeoutSecs <= 0 || set.TimeoutSecs > 30 {
		set.TimeoutSecs = subdomainDefaultTimeout
	}
	if set.MaxQueries <= 0 {
		set.MaxQueries = 20000
	}
	if set.Ports == "" {
		set.Ports = subdomainDefaultPorts
	}
	return set
}

// execute 按「解析目标 → 问范围 → 枚举 → 落库 → （再问一次范围）端口探测」执行。
func (r *subdomainRun) execute() (status, errMsg string, summary map[string]any) {
	fail := func(format string, args ...any) (string, string, map[string]any) {
		msg := fmt.Sprintf(format, args...)
		_ = r.pg.AppendSubdomainTaskLog(r.task.ID, "失败："+msg)
		return db.SubdomainTaskFailed, msg, map[string]any{}
	}
	roots, err := scanner.SubdomainRootsFromTargets(r.task.Targets)
	if err != nil {
		return fail("%v", err)
	}
	set := subdomainSettingsFrom(r.task.Options)

	// 第一道范围闸：根域名本身。授权清单没写这个域名，整单不做。
	if deny, warn := guardCheckTargets(r.s.admissionPolicy(), nil, roots); deny != "" {
		return fail("目标被平台拒绝，未发起任何查询：%s", deny)
	} else if warn != "" {
		_ = r.pg.AppendSubdomainTaskLog(r.task.ID, "告警："+warn)
	}

	opts := scanner.SubdomainOptions{
		Words:        set.Words,
		Concurrency:  set.Concurrency,
		Timeout:      time.Duration(set.TimeoutSecs) * time.Second,
		MaxQueries:   set.MaxQueries,
		Sources:      set.Sources,
		KeepWildcard: set.KeepWildcard,
		Resolver:     subdomainResolver(time.Duration(set.TimeoutSecs) * time.Second),
		Logf: func(format string, args ...any) {
			_ = r.pg.AppendSubdomainTaskLog(r.task.ID, fmt.Sprintf(format, args...))
		},
		OnProgress: subdomainProgressWriter(r.pg, r.task.ID, len(roots)*len(set.Words)),
	}
	if opts.Timeout <= 0 {
		opts.Timeout = time.Duration(subdomainDefaultTimeout) * time.Second
	}

	_ = r.pg.SetSubdomainTaskStage(r.task.ID, "resolving", map[string]any{
		"roots": roots, "public_sources": set.Sources, "probe_ports": set.ProbePorts,
	})
	outcome, err := subdomainEnumerate(r.ctx, roots, opts)
	if err != nil {
		return fail("%v", err)
	}

	// 结果与资产：一条名字先落台账，再按记录类型逐条写进资产（A/AAAA/CNAME 各一行，
	// 与资产模型里 (domain, record_type) 的唯一键一致）。
	_ = r.pg.SetSubdomainTaskStage(r.task.ID, "persisting", map[string]any{"found": len(outcome.Found)})
	persisted, assetRows, persistErr := r.persistSubdomains(outcome)
	if persistErr != nil {
		// 台账没落全就不能报完成：少一行等于宣称那一轮查过了。
		return fail("结果写入失败：%v", persistErr)
	}
	_ = r.pg.AppendSubdomainTaskLog(r.task.ID, fmt.Sprintf(
		"枚举完成：命中 %d 条 · 写入台账 %d 条 · 资产行 %d 行 · %s",
		len(outcome.Found), persisted, assetRows, outcome.SubdomainText()))

	probe := r.probeResolvedIPs(outcome)

	summary = outcome.SubdomainSummary()
	summary["stopped_text"] = outcome.SubdomainText()
	summary["persisted"] = persisted
	summary["asset_rows"] = assetRows
	for k, v := range probe {
		summary[k] = v
	}
	if r.ctx.Err() != nil {
		return db.SubdomainTaskCanceled, "已手动停止", summary
	}
	return db.SubdomainTaskDone, "", summary
}

// persistSubdomains 把引擎的每条发现写进台账与资产。返回写入台账的条数与资产行数。
func (r *subdomainRun) persistSubdomains(outcome scanner.SubdomainOutcome) (int, int, error) {
	if len(outcome.Found) == 0 {
		return 0, 0, nil
	}
	results := make([]db.SubdomainResult, 0, len(outcome.Found))
	for _, f := range outcome.Found {
		records := make([]db.SubdomainRecord, 0, len(f.Records))
		for _, rec := range f.Records {
			records = append(records, db.SubdomainRecord{Type: rec.Type, Values: rec.Values})
		}
		results = append(results, db.SubdomainResult{
			Name: f.Name, Root: f.Root, Source: f.Source,
			Records: records, IPs: f.IPs, Wildcard: f.Wildcard,
		})
	}
	if err := r.pg.InsertSubdomainResults(r.task.ID, results); err != nil {
		// 台账写不进去就是整轮结果不可交付：继续写资产只会让「报告说有三条、
		// 台账一条都查不到」这种不一致落地。
		return 0, 0, err
	}
	assetRows := 0
	for i, f := range outcome.Found {
		var linked int64
		for _, rec := range f.Records {
			id, err := r.s.m.Assets().UpsertSubdomain(db.UpsertSubdomainReq{
				Domain: f.Name, RecordType: rec.Type, RecordValue: rec.Values,
			})
			if err != nil {
				_ = r.pg.AppendSubdomainTaskLog(r.task.ID, fmt.Sprintf(
					"%s 的 %s 记录写入资产台账失败：%v（结果仍在，重跑或手工补登）", f.Name, rec.Type, err))
				continue
			}
			assetRows++
			if rec.Type == scanner.SubdomainRecordA || (rec.Type == scanner.SubdomainRecordAAAA && linked == 0) {
				linked = id
			}
		}
		if linked > 0 {
			if err := r.pg.SetSubdomainResultAsset(r.task.ID, outcome.Found[i].Name, linked); err != nil {
				_ = r.pg.AppendSubdomainTaskLog(r.task.ID, "关联资产编号失败 "+f.Name+"："+err.Error())
			}
		}
	}
	return len(results), assetRows, nil
}

// probeResolvedIPs 是「不需要手工搬运」那一步：把解析出来的 IP 直接送去端口探测。
//
// 探测前再问一次范围，是因为这些 IP 对授权清单来说是**新主机**——客户常常只写了域名
// 或另一段 IP。被拒时只跳过探测、保留名字，并把原因写进日志与摘要：
// 覆盖面少了一段，必须让人看得见，而不是静默变成「这一片没有开放端口」。
func (r *subdomainRun) probeResolvedIPs(outcome scanner.SubdomainOutcome) map[string]any {
	res := map[string]any{"probed_ips": 0, "open_ports": 0, "services": 0}
	if !subdomainSettingsFrom(r.task.Options).ProbePorts {
		res["probe_skipped"] = "任务设置里没开端口探测"
		return res
	}
	var ips []string
	seen := map[string]bool{}
	for _, f := range outcome.Found {
		for _, ip := range f.IPs {
			if !seen[ip] {
				seen[ip] = true
				ips = append(ips, ip)
			}
		}
	}
	if len(ips) == 0 {
		res["probe_skipped"] = "没有解析出 IP，无从探测"
		return res
	}
	if r.ctx.Err() != nil {
		res["probe_skipped"] = "任务已停止"
		return res
	}
	// 直接拼 Target，不绕 ParseTargets：那个文本解析只认 IPv4（C6 的账），
	// 而枚举引擎刻意保留了 AAAA 记录。绕过去会让整批 IP 因为一个 IPv6 全部探测不到，
	// 报告于是把「没探」写成「没有开放端口」。Discover 自己按 JoinHostPort 拨号，IPv6 可用。
	targets := make([]scanner.Target, 0, len(ips))
	for _, ip := range ips {
		if net.ParseIP(ip) == nil {
			continue
		}
		targets = append(targets, scanner.Target{Raw: ip, Kind: scanner.KindIP, Host: ip})
	}
	if len(targets) == 0 {
		res["probe_skipped"] = "解析出的地址都不是可用 IP"
		return res
	}
	urls, hosts, gerr := guardProbeTargets(targets)
	if gerr != nil {
		res["probe_skipped"] = gerr.Error()
		return res
	}
	if deny, warn := guardCheckTargets(r.s.admissionPolicy(), urls, hosts); deny != "" {
		res["probe_skipped"] = deny
		_ = r.pg.AppendSubdomainTaskLog(r.task.ID, "端口探测被平台拒绝，只保留名字："+deny)
		return res
	} else if warn != "" {
		_ = r.pg.AppendSubdomainTaskLog(r.task.ID, "端口探测告警："+warn)
	}

	set := subdomainSettingsFrom(r.task.Options)
	_ = r.pg.SetSubdomainTaskStage(r.task.ID, "probing", map[string]any{"ips": len(ips)})
	dres, err := subdomainDiscover(r.ctx, targets, scanner.DiscoverOptions{
		Ports: set.Ports, Concurrency: 32,
		Timeout:       time.Duration(set.ProbeTimeout) * time.Millisecond,
		MaxProbes:     2000,
		MaxPortChecks: 20000,
		Logf: func(format string, args ...any) {
			_ = r.pg.AppendSubdomainTaskLog(r.task.ID, "探测："+fmt.Sprintf(format, args...))
		},
	})
	if err != nil {
		res["probe_skipped"] = "端口探测失败：" + err.Error()
		return res
	}
	portsByIP := map[string][]db.PortService{}
	for _, pf := range dres.Ports {
		label := pf.Service
		if label == "" {
			label = "tcp"
		}
		portsByIP[pf.IP] = append(portsByIP[pf.IP], db.PortService{Port: pf.Port, Service: label})
	}
	written := 0
	for ip, ports := range portsByIP {
		sort.Slice(ports, func(i, j int) bool { return ports[i].Port < ports[j].Port })
		if _, err := r.s.m.Assets().UpsertIP(db.UpsertIPReq{IP: ip, OpenPorts: ports}); err != nil {
			_ = r.pg.AppendSubdomainTaskLog(r.task.ID, fmt.Sprintf("写入 IP 资产失败 %s：%v", ip, err))
			continue
		}
		written++
	}
	for _, svc := range dres.Services {
		status := svc.StatusCode
		length := svc.ContentLength
		if _, err := r.s.m.Assets().UpsertHTTPService(db.UpsertHTTPServiceReq{
			URL: svc.URL, Technologies: svc.Technologies, StatusCode: &status,
			ContentLength: &length, PageTitle: svc.Title, IP: svc.IP,
		}); err != nil {
			_ = r.pg.AppendSubdomainTaskLog(r.task.ID, fmt.Sprintf("写入 Web 资产失败 %s：%v", svc.URL, err))
		}
	}
	res["probed_ips"] = len(ips)
	res["open_ports"] = len(dres.Ports)
	res["services"] = len(dres.Services)
	res["ip_assets_written"] = written
	_ = r.pg.AppendSubdomainTaskLog(r.task.ID, fmt.Sprintf(
		"端口探测：%d 个 IP · 开放端口 %d · Web 服务 %d · 写入 IP 资产 %d",
		len(ips), len(dres.Ports), len(dres.Services), written))
	return res
}

// subdomainProgressWriter 限频写进度，避免每个名字都刷一次库。
func subdomainProgressWriter(pg *db.DB, taskID int64, total int) func(queries, found int) {
	var last time.Time
	return func(queries, found int) {
		if time.Since(last) < subdomainProgressPeriod {
			return
		}
		last = time.Now()
		_ = pg.SetSubdomainTaskStage(taskID, "resolving", map[string]any{
			"queried": queries, "found": found, "total": total,
		})
	}
}

// ---------- HTTP 接口 ----------

// createSubdomainTask 建一条子域名枚举任务。
//
// 这里就把目标摊开问一遍范围：建任务不发包，但「排队中的任务」会在下一次认领时发包，
// 拦在门口比拦在执行器里少跑一趟空。
func (s *Server) createSubdomainTask(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req struct {
		Name    string          `json:"name"`
		Targets []string        `json:"targets"`
		Options *map[string]any `json:"options"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "请求格式错误")
		return
	}
	if len(req.Targets) == 0 {
		writeErr(w, 400, "至少填写一个根域名（example.com 或 www.example.com）")
		return
	}
	roots, err := scanner.SubdomainRootsFromTargets(req.Targets)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if deny, _ := guardCheckTargets(s.admissionPolicy(), nil, roots); deny != "" {
		writeErr(w, 400, "目标被平台拒绝，未发起任何查询："+deny)
		return
	}
	options := map[string]any{}
	if req.Options != nil {
		options = *req.Options
	}
	if srcs, ok := options["public_sources"].([]any); ok && len(srcs) > 0 {
		options["public_disclosed"] = true // 报告与界面据此再提醒一次：根域名会被发给第三方
	}
	task, err := pg.CreateSubdomainTask(db.SubdomainTaskInput{
		Name: req.Name, Targets: req.Targets, Options: options,
	})
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if s.subMgr != nil {
		s.subMgr.wakeup()
	}
	writeJSON(w, 200, task)
}

func (s *Server) listSubdomainTasks(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	list, err := pg.ListSubdomainTasks(atoiDefault(r.URL.Query().Get("limit"), 50))
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	// 与弱口令检测同一形状（{tasks: []}）：前端两套列表各读一种结构，早晚会读错一个。
	writeJSON(w, 200, map[string]any{"tasks": list})
}

func (s *Server) getSubdomainTask(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, 400, "任务编号无效")
		return
	}
	task, err := pg.GetSubdomainTask(id)
	if errors.Is(err, db.ErrSubdomainTaskNotFound) {
		writeErr(w, 404, "任务不存在")
		return
	}
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	n, _ := pg.SubdomainResultCount(id)
	writeJSON(w, 200, map[string]any{"task": task, "result_count": n})
}

func (s *Server) listSubdomainResults(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, 400, "任务编号无效")
		return
	}
	list, err := pg.ListSubdomainResults(id, r.URL.Query().Get("root"),
		strings.ToLower(strings.TrimSpace(r.URL.Query().Get("source"))),
		atoiDefault(r.URL.Query().Get("limit"), 2000))
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	// 与弱口令检测同一形状（{results, total}）。
	total, _ := pg.SubdomainResultCount(id)
	writeJSON(w, 200, map[string]any{"results": list, "total": total})
}

func (s *Server) cancelSubdomainTask(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, 400, "任务编号无效")
		return
	}
	changed, err := pg.CancelSubdomainTask(id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if !changed {
		writeErr(w, 409, "任务已结束，无法取消")
		return
	}
	if s.subMgr != nil {
		s.subMgr.cancelTask(id)
	}
	writeJSON(w, 200, map[string]any{"canceled": true})
}

func (s *Server) batchDeleteSubdomainTasks(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	var req struct {
		IDs []int64 `json:"ids"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "请求格式错误")
		return
	}
	if len(req.IDs) == 0 {
		writeErr(w, 400, "没有要删除的任务")
		return
	}
	n, err := pg.DeleteSubdomainTasks(req.IDs)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"deleted": n})
}

// subdomainOptions 把引擎可调的口径与默认值交给界面，避免前端自己抄一份常量。
func (s *Server) subdomainOptions(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{
		"builtin_words":   len(scanner.SubdomainWordlist),
		"public_sources":  scanner.SubdomainSourceNames(),
		"default_ports":   subdomainDefaultPorts,
		"default_timeout": subdomainDefaultTimeout,
		"max_queries":     20000,
		"note": "公开接口会把根域名发给第三方（crt.sh 是公开证书透明度日志），默认关闭；" +
			"字典爆破的 DNS 查询发往本机配置的解析器，不发给目标。",
	})
}

// subdomainReportMarkdown 给一次任务生成可直接贴进交付报告的 Markdown。
func (s *Server) subdomainReportMarkdown(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, 400, "任务编号无效")
		return
	}
	task, err := pg.GetSubdomainTask(id)
	if errors.Is(err, db.ErrSubdomainTaskNotFound) {
		writeErr(w, 404, "任务不存在")
		return
	}
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	results, err := pg.ListSubdomainResults(id, "", "", 5000)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"markdown": subdomainMarkdown(task, results)})
}

// subdomainMarkdown 渲染「范围 → 结论一句话 → 逐条名字」。
// 结论那句由引擎的口径生成（泛解析、未判定、预算、公开接口），这里不重写一遍，
// 免得两处措辞不一致时没人知道哪个是真的。
func subdomainMarkdown(task *db.SubdomainTask, results []db.SubdomainResult) string {
	var b strings.Builder
	fmt.Fprintf(&b, "## 子域名枚举（任务 #%d）\n\n", task.ID)
	if name := strings.TrimSpace(task.Name); name != "" {
		fmt.Fprintf(&b, "%s\n\n", name)
	}
	fmt.Fprintf(&b, "目标：%s · 状态：%s\n\n", strings.Join(task.Targets, "、"), subdomainStatusText(task.Status))
	if note := subdomainSummaryNote(task); note != "" {
		fmt.Fprintf(&b, "> %s\n\n", note)
	}
	if len(results) == 0 {
		b.WriteString("本轮没有确认存在的子域名。\n")
		return b.String()
	}
	b.WriteString("| 子域名 | 来源 | 记录 | 结论 |\n| :-- | :-- | :-- | :-- |\n")
	for _, res := range results {
		recs := make([]string, 0, len(res.Records))
		for _, rec := range res.Records {
			recs = append(recs, rec.Type+" "+strings.Join(rec.Values, ","))
		}
		// 措辞与界面同一套：交付报告与页面上同一件事不该有两种说法。
		verdict := "已解析并进资产"
		if res.Wildcard {
			verdict = "与泛解析基线一致（待人工确认）"
		}
		if res.AssetID == nil && !res.Wildcard {
			verdict = "已解析，但未写入资产台账"
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", res.Name,
			subdomainSourceText(res.Source), strings.Join(recs, " / "), verdict)
	}
	return b.String()
}

func subdomainSummaryNote(task *db.SubdomainTask) string {
	if strings.TrimSpace(task.Error) != "" {
		return task.Error
	}
	if v, ok := task.Summary["stopped_text"].(string); ok && strings.TrimSpace(v) != "" {
		return v
	}
	parts := make([]string, 0, 4)
	if n, ok := task.Summary["found"].(int); ok {
		parts = append(parts, fmt.Sprintf("确认存在 %d 条", n))
	}
	if w, ok := task.Summary["wildcard_dropped"].(int); ok && w > 0 {
		parts = append(parts, fmt.Sprintf("泛解析剔除 %d 条", w))
	}
	if u, ok := task.Summary["unresolved"].(int); ok && u > 0 {
		parts = append(parts, fmt.Sprintf("未判定 %d 次（不等于不存在）", u))
	}
	if p, ok := task.Summary["probe_skipped"].(string); ok && strings.TrimSpace(p) != "" {
		parts = append(parts, "端口探测未执行："+p)
	}
	return strings.Join(parts, "；")
}

func subdomainStatusText(status string) string {
	switch status {
	case db.SubdomainTaskQueued:
		return "排队中"
	case db.SubdomainTaskRunning:
		return "进行中"
	case db.SubdomainTaskDone:
		return "已完成"
	case db.SubdomainTaskFailed:
		return "失败"
	case db.SubdomainTaskCanceled:
		return "已取消"
	}
	return status
}

func subdomainSourceText(source string) string {
	switch source {
	case scanner.SubdomainSourceInput:
		return "直接给出"
	case scanner.SubdomainSourceDict:
		return "字典命中"
	case scanner.SubdomainSourcePublic:
		return "公开接口"
	}
	return source
}

// subOptionInt 容忍 JSON 解出来的三种数字形态（float64/int/字符串）。
func subOptionInt(v any, def int) int {
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	case string:
		return atoiDefault(strings.TrimSpace(n), def)
	}
	return def
}
