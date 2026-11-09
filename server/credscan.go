package server

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/jingwei/db"
	"github.com/Autumn-27/jingwei/report"
	"github.com/Autumn-27/jingwei/scanner"
)

// 弱口令检测（界面名）的任务框架与 API。内部标识保持 credscan。
//
// 与漏扫任务同样的形状：任务落库、进程内单执行器、可取消、重启后把中断的任务标失败。
// 差别在于结果形态：漏扫产出「发现」，这里产出「某端点某组凭据的判定」，六态一行不少。
// 执行器只做编排——端口决策、握手、六态判定都在 scanner 里，两边不各写一套。

const (
	credMaxTargets     = 100
	credMaxBudgetSec   = 2 * 60 * 60
	credMinBudgetSec   = 30
	credDefaultBudget  = 600
	credProgressPeriod = 2 * time.Second
	credFlushBatch     = 50
)

type credManager struct {
	s    *Server
	wake chan struct{}

	mu     sync.Mutex
	cancel map[int64]context.CancelFunc
}

func newCredManager(s *Server) *credManager {
	return &credManager{s: s, wake: make(chan struct{}, 1), cancel: map[int64]context.CancelFunc{}}
}

func (m *credManager) start(ctx context.Context) {
	if m == nil || m.s.m.pg == nil {
		return
	}
	if n, err := m.s.m.pg.RecoverInterruptedCredTasks(); err != nil {
		log.Printf("[credscan] recover interrupted tasks: %v", err)
	} else if n > 0 {
		log.Printf("[credscan] 启动时将 %d 个中断的弱口令任务标记为失败", n)
	}
	go m.loop(ctx)
}

func (m *credManager) wakeup() {
	select {
	case m.wake <- struct{}{}:
	default:
	}
}

func (m *credManager) loop(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		if ctx.Err() != nil {
			return
		}
		for {
			task, err := m.s.m.pg.ClaimNextCredTask()
			if err != nil {
				log.Printf("[credscan] claim queued task: %v", err)
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

// cancelTask 取消进程内的执行；任务状态由 API 侧同时改库，界面不必等执行器收尾。
func (m *credManager) cancelTask(id int64) bool {
	m.mu.Lock()
	cancel, ok := m.cancel[id]
	m.mu.Unlock()
	if ok {
		cancel()
	}
	return ok
}

func (m *credManager) run(parent context.Context, task *db.CredTask) {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()

	m.mu.Lock()
	m.cancel[task.ID] = cancel
	m.mu.Unlock()
	defer func() {
		m.mu.Lock()
		delete(m.cancel, task.ID)
		m.mu.Unlock()
	}()

	run := &credRun{s: m.s, pg: m.s.m.pg, task: task, ctx: ctx}
	status, errMsg, summary := run.execute()
	if summary == nil {
		summary = map[string]any{}
	}
	if err := m.s.m.pg.FinishCredTask(task.ID, status, summary, errMsg); err != nil {
		log.Printf("[credscan %d] finish: %v", task.ID, err)
	}
}

// credRun 是一次任务执行的全部上下文。
type credRun struct {
	s    *Server
	pg   *db.DB
	task *db.CredTask
	ctx  context.Context
}

// execute 按「解析目标 → 出端点计划 → 装字典 → 跑引擎 → 逐行落库」执行，返回终态与摘要。
func (r *credRun) execute() (status, errMsg string, summary map[string]any) {
	fail := func(format string, args ...any) (string, string, map[string]any) {
		msg := fmt.Sprintf(format, args...)
		_ = r.pg.AppendCredTaskLog(r.task.ID, "失败："+msg)
		return db.CredTaskFailed, msg, map[string]any{}
	}

	targets, err := scanner.ParseTargets(r.task.Targets)
	if err != nil {
		return fail("目标解析失败：%v", err)
	}
	// 这一版没有「指纹给出的服务」可复用：资产侧的服务表来自漏扫，接上之前只用
	// 输入里的端口与协议默认端口表。三级决策的中间一级留给 B9 之后的联调。
	plan, err := scanner.CredPlan(targets, nil, r.task.Protocols)
	if err != nil {
		return fail("没有可测端点：%v", err)
	}
	// 建任务与真正开跑之间，客户授权清单可能已经变了（到期、被删、目标挪出范围）。
	// 认证包一旦发出去就收不回来，所以执行前再问一次，拒绝就一个包都不发。
	urls, hosts, gerr := guardProbeTargets(targets)
	if gerr != nil {
		return fail("%v", gerr)
	}
	if deny, warn := guardCheckTargets(r.s.admissionPolicy(), urls, hosts); deny != "" {
		return fail("目标被平台拒绝，未发起任何连接：%s", deny)
	} else if warn != "" {
		_ = r.pg.AppendCredTaskLog(r.task.ID, "告警："+warn)
	}
	creds, dictProfile, err := r.loadDictionary()
	if err != nil {
		return fail("%v", err)
	}
	opts, budget := credOptionsFrom(r.task.Options)

	_ = r.pg.SetCredTaskStage(r.task.ID, "testing", map[string]any{
		"endpoints": len(plan), "credentials": len(creds),
	})
	_ = r.pg.AppendCredTaskLog(r.task.ID, fmt.Sprintf(
		"端点 %d 个 · 凭据 %d 组（字典 %s）· 并发 %d · 限速 %s · 预算 %s",
		len(plan), len(creds), dictProfile, opts.Concurrency, credRateText(opts.RateLimit), budget))

	pg := &credProgress{
		pg: r.pg, taskID: r.task.ID, started: time.Now(),
		endpoints: len(plan), credentials: len(creds), counts: map[string]int{},
	}
	epByKey := make(map[string]scanner.CredEndpoint, len(plan))
	for _, ep := range plan {
		epByKey[credEndpointKey(ep.Host, ep.Port, ep.Protocol)] = ep
	}

	progressCtx, stopProgress := context.WithCancel(r.ctx)
	progressDone := make(chan struct{})
	go pg.loop(progressCtx, progressDone)

	err = scanner.CredRun(r.ctx, plan, creds, opts, func(a scanner.CredAttempt) {
		pg.emit(a, epByKey)
	})
	stopProgress()
	<-progressDone

	flushErr := pg.finish()
	switch {
	case errors.Is(r.ctx.Err(), context.Canceled):
		status = db.CredTaskCanceled
		errMsg = "已手动停止"
	case flushErr != nil:
		// 结果没落全就不能报完成：报告里少一行等于宣称那个端点测过了。
		status = db.CredTaskFailed
		errMsg = "结果写入失败：" + flushErr.Error()
	case err != nil:
		status = db.CredTaskFailed
		errMsg = err.Error()
	default:
		status = db.CredTaskDone
	}
	summary = pg.summary(budget)
	_ = r.pg.AppendCredTaskLog(r.task.ID, credSummaryLine(summary))
	_ = r.pg.SetCredTaskStage(r.task.ID, status, pg.snapshot())
	if n, _ := summary["hit"].(int); n > 0 {
		r.persistFacts()
	}
	return status, errMsg, summary
}

// persistFacts 把命中落成三条事实：资产服务行、发现、凭据台账。
//
// 只写事实，不触发任何动作：不登录、不执行命令、不把它喂给自动利用。用不用这组
// 凭据是操作员的决定——B9 的验收里「没有任何动作被自动触发」是硬条件。
func (r *credRun) persistFacts() {
	const pageSize = 500
	offset, saved := 0, 0
	for {
		rows, total, err := r.pg.ListCredResults(r.task.ID,
			db.CredResultFilter{Outcome: "hit", Offset: offset, Limit: pageSize})
		if err != nil {
			_ = r.pg.AppendCredTaskLog(r.task.ID, "事实落库失败："+err.Error())
			return
		}
		for _, row := range rows {
			if r.persistHit(row) {
				saved++
			}
		}
		offset += len(rows)
		if len(rows) == 0 || offset >= total {
			break
		}
	}
	if saved > 0 {
		_ = r.pg.AppendCredTaskLog(r.task.ID,
			fmt.Sprintf("事实落库：%d 条命中已登记到资产 / 发现 / 凭据库（不触发任何动作）", saved))
	}
}

func (r *credRun) persistHit(row *db.CredResult) bool {
	host := strings.TrimSpace(row.Host)
	serviceReq := db.UpsertOtherServiceReq{
		Port: row.Port, ServiceName: row.Protocol,
		Extra: map[string]any{"source": "credscan"},
	}
	if row.Banner != "" {
		serviceReq.Extra["banner"] = row.Banner
	}
	if row.TLS {
		serviceReq.Extra["tls"] = true
	}
	if ip := net.ParseIP(host); ip != nil {
		serviceReq.IP = host
	} else {
		serviceReq.Domain = host
	}
	if row.Username != "" || row.Password != "" {
		serviceReq.Auth = []map[string]any{{"username": row.Username, "password": row.Password}}
	}
	assetID, err := r.pg.Assets().UpsertOtherService(serviceReq)
	if err != nil {
		_ = r.pg.AppendCredTaskLog(r.task.ID,
			fmt.Sprintf("写服务资产失败 %s:%d：%v", host, row.Port, err))
	}

	proto := strings.ToUpper(row.Protocol)
	var name, summaryText string
	switch {
	case row.Username != "" && row.Password != "":
		name = fmt.Sprintf("%s 弱口令（%s）", proto, row.Username)
		summaryText = fmt.Sprintf("%s:%d 的 %s 存在可用凭据 %s/%s（弱口令检测 #%d）",
			host, row.Port, row.Protocol, row.Username, row.Password, r.task.ID)
	case row.Password != "":
		name = fmt.Sprintf("%s 弱口令（仅口令认证）", proto)
		summaryText = fmt.Sprintf("%s:%d 的 %s 接受该口令（弱口令检测 #%d）",
			host, row.Port, row.Protocol, r.task.ID)
	default:
		name = fmt.Sprintf("%s 未启用认证", proto)
		summaryText = fmt.Sprintf("%s:%d 的 %s 无需任何凭据即可访问（弱口令检测 #%d）",
			host, row.Port, row.Protocol, r.task.ID)
	}
	var assetIDs []int64
	if assetID > 0 {
		assetIDs = []int64{assetID}
	}
	dedupe := fmt.Sprintf("credscan:%s:%d:%s:%s", strings.ToLower(host), row.Port, row.Protocol, row.Username)
	findingID, _, err := r.pg.UpsertFinding(0, 0, "weak-credential", name, "high", summaryText,
		row.Evidence, fmt.Sprintf("credscan:%d", r.task.ID), assetIDs, dedupe)
	if err != nil {
		_ = r.pg.AppendCredTaskLog(r.task.ID,
			fmt.Sprintf("写入弱口令发现失败 %s:%d：%v", host, row.Port, err))
	}

	// 凭据台账要求用户名与口令都非空；「未开认证」没有可复用的凭据，
	// 只留发现，不往台账里塞一条假记录。
	if row.Username == "" || row.Password == "" {
		return findingID > 0
	}
	if _, err := r.pg.UpsertIntranetCredential(db.IntranetCredentialInput{
		Host: host, Port: row.Port, Protocol: row.Protocol,
		Username: row.Username, Password: row.Password, Source: "credscan",
		FindingID: findingID,
		Evidence:  fmt.Sprintf("%s:%d %s 弱口令命中（弱口令检测 #%d）", host, row.Port, row.Protocol, r.task.ID),
	}); err != nil {
		_ = r.pg.AppendCredTaskLog(r.task.ID,
			fmt.Sprintf("登记凭据台账失败 %s:%d：%v", host, row.Port, err))
	}
	return findingID > 0
}

// loadDictionary 解析任务选的字典档：builtin 在代码里，其余是操作员导入、存在库里。
// 解析出的组数会写进任务日志——报告需要能回答「拿什么字典测的」。
func (r *credRun) loadDictionary() ([]scanner.Credential, string, error) {
	profile := strings.ToLower(strings.TrimSpace(r.task.DictProfile))
	if profile == "" || profile == "builtin" {
		d, err := scanner.CredDictionaryByName(profile)
		return d.Credentials, "builtin", err
	}
	content, err := r.pg.GetCredDict(profile)
	if errors.Is(err, db.ErrCredDictNotFound) {
		return nil, profile, fmt.Errorf("字典档不存在：%s", profile)
	}
	if err != nil {
		return nil, profile, err
	}
	creds, err := scanner.ParseCredDictionary(content)
	return creds, profile, err
}

func credEndpointKey(host string, port int, protocol string) string {
	return fmt.Sprintf("%s|%d|%s", host, port, protocol)
}

func credRateText(rate int) string {
	if rate <= 0 {
		return "不限"
	}
	return fmt.Sprintf("%d/s", rate)
}

// credOptionsFrom 把任务里存的操作员选项翻译成引擎边界。
// 预算单位是秒，界面上人写的也是秒；引擎里是 Duration，转换只在这一处发生。
func credOptionsFrom(opts map[string]any) (scanner.CredOptions, time.Duration) {
	var o scanner.CredOptions
	o.Concurrency = credIntOption(opts, "concurrency", 0)
	o.RateLimit = credIntOption(opts, "rate_limit", 0)
	o.StopLossAfter = credIntOption(opts, "stop_loss_after", 0)
	o.StopAfterDenies = credIntOption(opts, "stop_after_denies", 0)
	secs := credIntOption(opts, "budget_seconds", credDefaultBudget)
	if secs < credMinBudgetSec {
		secs = credMinBudgetSec
	}
	if secs > credMaxBudgetSec {
		secs = credMaxBudgetSec
	}
	o.Budget = time.Duration(secs) * time.Second
	return o, o.Budget
}

func credIntOption(opts map[string]any, key string, def int) int {
	v, ok := opts[key]
	if !ok {
		return def
	}
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	case int64:
		return int(n)
	case string:
		if i, err := strconv.Atoi(strings.TrimSpace(n)); err == nil {
			return i
		}
	}
	return def
}

// credProgress 收集引擎交出的结果并分批落库，同时维持进度快照。
// 引擎保证 emit 串行调用；这里仍加锁，因为进度写入与 flush 是另一个 goroutine。
type credProgress struct {
	pg     *db.DB
	taskID int64

	mu          sync.Mutex
	buf         []db.CredResult
	counts      map[string]int
	attempts    int
	endpoints   int
	credentials int
	started     time.Time
	flushErr    error
}

func (p *credProgress) emit(a scanner.CredAttempt, eps map[string]scanner.CredEndpoint) {
	ep := eps[credEndpointKey(a.Host, a.Port, a.Protocol)]
	row := db.CredResult{
		Host: a.Host, Port: a.Port, Protocol: a.Protocol,
		ProtocolSource: ep.ProtocolSource, ProtocolConfirmed: ep.ProtocolConfirmed,
		Params:   ep.Params,
		Username: a.Cred.Username, Password: a.Cred.Password,
		Outcome: string(a.Outcome), Banner: a.Banner, Evidence: a.Evidence(),
		TLS: a.TLS, Reason: a.Reason, Attempts: a.Attempts,
		ElapsedMS: a.Elapsed.Milliseconds(),
	}
	p.mu.Lock()
	p.buf = append(p.buf, row)
	p.counts[string(a.Outcome)]++
	p.attempts += a.Attempts
	var batch []db.CredResult
	if len(p.buf) >= credFlushBatch {
		batch, p.buf = p.buf, nil
	}
	p.mu.Unlock()
	if len(batch) > 0 {
		p.insert(batch)
	}
}

// insert 落一批；失败时把行放回缓冲区，等下一轮重试。绝不丢弃：
// 少一行就是报告里的假话，宁可任务最终判失败。
func (p *credProgress) insert(batch []db.CredResult) {
	if err := p.pg.InsertCredResults(p.taskID, batch); err != nil {
		p.mu.Lock()
		p.buf = append(batch, p.buf...)
		if p.flushErr == nil {
			p.flushErr = err
		}
		p.mu.Unlock()
	}
}

func (p *credProgress) loop(ctx context.Context, done chan<- struct{}) {
	defer close(done)
	ticker := time.NewTicker(credProgressPeriod)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.flush()
			_ = p.pg.SetCredTaskStage(p.taskID, "testing", p.snapshot())
		}
	}
}

func (p *credProgress) flush() {
	p.mu.Lock()
	batch := p.buf
	p.buf = nil
	p.mu.Unlock()
	if len(batch) > 0 {
		p.insert(batch)
	}
}

// finish 做最后一次 flush 并返回累计的写入错误。
func (p *credProgress) finish() error {
	p.flush()
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.flushErr
}

func (p *credProgress) snapshot() map[string]any {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := map[string]any{
		"endpoints":   p.endpoints,
		"credentials": p.credentials,
		"attempts":    p.attempts,
		"elapsed_ms":  time.Since(p.started).Milliseconds(),
	}
	for _, k := range db.CredTaskOutcomes {
		if n := p.counts[k]; n > 0 {
			out[k] = n
		}
	}
	return out
}

func (p *credProgress) summary(budget time.Duration) map[string]any {
	out := p.snapshot()
	out["budget_seconds"] = int(budget.Seconds())
	total := 0
	for _, n := range p.counts {
		total += n
	}
	out["total"] = total
	return out
}

// credSummaryLine 把摘要写成一行中文日志，任务详情页直接可读。
func credSummaryLine(summary map[string]any) string {
	part := func(key, label string) string {
		n, _ := summary[key].(int)
		if n == 0 {
			return ""
		}
		return fmt.Sprintf("%s %d", label, n)
	}
	parts := make([]string, 0, 6)
	for _, kv := range [][2]string{
		{"hit", "命中"}, {"deny", "拒绝"}, {"unreachable", "连不上"},
		{"locked", "锁定"}, {"inconclusive", "不可判定"}, {"unsupported", "不支持"},
	} {
		if s := part(kv[0], kv[1]); s != "" {
			parts = append(parts, s)
		}
	}
	if len(parts) == 0 {
		return "收尾：没有任何结果行（任务没有真正开跑）"
	}
	return "收尾：" + strings.Join(parts, " · ")
}

// ── HTTP ─────────────────────────────────────────────────────────────────────

// credProtocols 给前端协议选择器：哪些能勾、什么端口、用什么字典档。
func (s *Server) credProtocols(w http.ResponseWriter, r *http.Request) {
	dicts := []*db.CredDict{}
	if pg := s.m.pg; pg != nil {
		if list, err := pg.ListCredDicts(); err == nil {
			dicts = list
		}
	}
	names := append([]string{"builtin"}, make([]string, 0, len(dicts))...)
	for _, d := range dicts {
		names = append(names, d.Name)
	}
	writeJSON(w, 200, map[string]any{
		"protocols":    scanner.CredProtocolCatalog(),
		"dictionaries": names,
		"dicts":        dicts,
		"outcomes":     db.CredTaskOutcomes,
	})
}

// credDictExists 校验字典档：builtin 恒可用，导入档必须在库里。
func (s *Server) credDictExists(pg *db.DB, profile string) error {
	name := strings.ToLower(strings.TrimSpace(profile))
	if name == "" || name == "builtin" {
		return nil
	}
	if _, err := pg.GetCredDict(name); err != nil {
		if errors.Is(err, db.ErrCredDictNotFound) {
			return fmt.Errorf("字典档不存在：%s", name)
		}
		return err
	}
	return nil
}

// 字典档管理：导入 / 列表 / 删除。内置档不可覆盖也不可删。
func (s *Server) listCredDicts(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	dicts, err := pg.ListCredDicts()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"dicts": dicts})
}

func (s *Server) saveCredDict(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req struct {
		Name    string `json:"name"`
		Content string `json:"content"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "请求格式错误")
		return
	}
	creds, err := scanner.ParseCredDictionary(req.Content)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	dict, err := pg.SaveCredDict(req.Name, req.Content, len(creds))
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, dict)
}

func (s *Server) deleteCredDict(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	ok, err := pg.DeleteCredDict(r.PathValue("name"))
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if !ok {
		writeErr(w, 404, "字典档不存在")
		return
	}
	writeJSON(w, 200, map[string]any{"deleted": true})
}

type credTaskCreateRequest struct {
	Name        string         `json:"name"`
	Targets     []string       `json:"targets"`
	Protocols   []string       `json:"protocols"`
	Options     map[string]any `json:"options"`
	DictProfile string         `json:"dict_profile"`
}

func (s *Server) createCredTask(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req credTaskCreateRequest
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "请求格式错误")
		return
	}
	targets := make([]string, 0, len(req.Targets))
	for _, t := range req.Targets {
		if t = strings.TrimSpace(t); t != "" {
			targets = append(targets, t)
		}
	}
	if len(targets) == 0 {
		writeErr(w, 400, "至少需要一个目标")
		return
	}
	if len(targets) > credMaxTargets {
		writeErr(w, 400, fmt.Sprintf("目标过多（%d），单次最多 %d 个", len(targets), credMaxTargets))
		return
	}
	if len(req.Protocols) == 0 {
		writeErr(w, 400, "至少勾选一个协议")
		return
	}
	for _, p := range req.Protocols {
		name := strings.ToLower(strings.TrimSpace(p))
		if !scanner.CredProtocolSupported(name) || scanner.CredAdapterFor(name) == nil {
			// B5：不支持的协议在创建阶段就拒掉，一条连接都不发。比「建一个全是
			// unsupported 行的任务」更干净——后者会被误读成「测过了但没实现」。
			msg := "该协议暂不支持：" + name
			if r := scanner.CredUnsupportedReason(name); r != "" {
				msg += "（" + r + "）"
			} else if !scanner.CredProtocolKnown(name) {
				// 名字都不在目录里：要么是拼错了，要么是本平台明确不测的协议
				// （Oracle/WebLogic/WinRM/CobaltStrike 于 2026-11-09 删除）。
				// 说「未知」比留一句「暂不支持」更好——后者会让人等一个永远不来的版本。
				msg += "（本平台不测该协议，未发起连接）"
			}
			writeErr(w, 400, msg)
			return
		}
	}
	if err := s.credDictExists(pg, req.DictProfile); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	// 目标语法与端点计划在建任务时就验一遍：等到执行器里才发现「目标解析失败」，
	// 操作员看到的是一场空跑。
	parsed, err := scanner.ParseTargets(targets)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if _, err := scanner.CredPlan(parsed, nil, req.Protocols); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	// 目标策略：弱口令检测会主动发认证包，打错地方不只是越界，还会把别人家的账号打进锁定。
	// 这道闸原先只挂在 agent 工具与内网执行上，从界面建的任务完全绕过（见 guard_targets.go）。
	urls, hosts, err := guardProbeTargets(parsed)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	deny, warn := guardCheckTargets(s.admissionPolicy(), urls, hosts)
	if deny != "" {
		writeErr(w, 400, "目标被平台拒绝，未发起任何连接："+deny)
		return
	}

	task, err := pg.CreateCredTask(db.CredTaskInput{
		Name: req.Name, Targets: targets, Protocols: req.Protocols,
		Options: req.Options, DictProfile: req.DictProfile,
	})
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if warn != "" {
		_ = pg.AppendCredTaskLog(task.ID, "告警："+warn)
	}
	if s.credMgr != nil {
		s.credMgr.wakeup()
	}
	writeJSON(w, 200, task)
}

func (s *Server) listCredTasks(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	tasks, err := pg.ListCredTasks(atoiDefault(r.URL.Query().Get("limit"), 50))
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	// 列表不带日志正文：一条任务的日志可能很长，列表页只需要计数与状态。
	for _, t := range tasks {
		t.Log = ""
	}
	writeJSON(w, 200, map[string]any{"tasks": tasks})
}

func (s *Server) getCredTask(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, 400, "任务编号无效")
		return
	}
	task, err := pg.GetCredTask(id)
	if errors.Is(err, db.ErrCredTaskNotFound) {
		writeErr(w, 404, err.Error())
		return
	}
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	counts, err := pg.CredTaskOutcomeCounts(id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"task": task, "counts": counts})
}

func (s *Server) cancelCredTask(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, 400, "任务编号无效")
		return
	}
	okCancel, err := pg.CancelCredTask(id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if okCancel && s.credMgr != nil {
		s.credMgr.cancelTask(id)
	}
	writeJSON(w, 200, map[string]any{"canceled": okCancel})
}

func (s *Server) deleteCredTask(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, 400, "任务编号无效")
		return
	}
	n, err := pg.DeleteCredTasks([]int64{id})
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if n == 0 {
		writeErr(w, 400, "任务不存在或仍在运行，不能删除")
		return
	}
	writeJSON(w, 200, map[string]any{"deleted": n})
}

// batchDeleteCredTasks 一次请求删多条：列表页全选删除不该发 N 个请求。
func (s *Server) batchDeleteCredTasks(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req struct {
		IDs []int64 `json:"ids"`
	}
	if err := decode(r, &req); err != nil || len(req.IDs) == 0 {
		writeErr(w, 400, "请求格式错误")
		return
	}
	n, err := pg.DeleteCredTasks(req.IDs)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"deleted": n})
}

// credTaskReport 出任务报告（Markdown）。内部版含全部结果与报文附录；对外版只放
// 已确认命中并给口令打码，但「未测/不支持」会显式列出——那两项不能靠留白表达。
func (s *Server) credTaskReport(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, 400, "任务编号无效")
		return
	}
	task, err := pg.GetCredTask(id)
	if errors.Is(err, db.ErrCredTaskNotFound) {
		writeErr(w, 404, err.Error())
		return
	}
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	rows := []*db.CredResult{}
	for offset := 0; ; {
		page, total, err := pg.ListCredResults(id, db.CredResultFilter{Offset: offset, Limit: 1000})
		if err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		rows = append(rows, page...)
		offset += len(page)
		if len(page) == 0 || offset >= total {
			break
		}
	}
	internal := r.URL.Query().Get("internal") != "0"
	md := report.CredscanMarkdown(report.CredReportInput{
		TaskID: task.ID, Name: task.Name, Targets: task.Targets, Protocols: task.Protocols,
		DictProfile: task.DictProfile, Status: task.Status,
		CreatedAt: task.CreatedAt, StartedAt: task.StartedAt, FinishedAt: task.FinishedAt,
		Summary: task.Summary, Rows: rows, GeneratedAt: time.Now(), Internal: internal,
	})
	suffix := "internal"
	if !internal {
		suffix = "external"
	}
	w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
	w.Header().Set("Content-Disposition",
		fmt.Sprintf(`attachment; filename="credscan-%d-%s.md"`, task.ID, suffix))
	_, _ = w.Write([]byte(md))
}

func (s *Server) listCredTaskResults(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, 400, "任务编号无效")
		return
	}
	q := r.URL.Query()
	results, total, err := pg.ListCredResults(id, db.CredResultFilter{
		Outcome: strings.TrimSpace(q.Get("outcome")),
		Host:    strings.TrimSpace(q.Get("host")),
		Offset:  atoiDefault(q.Get("offset"), 0),
		Limit:   atoiDefault(q.Get("limit"), 200),
	})
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"results": results, "total": total})
}
