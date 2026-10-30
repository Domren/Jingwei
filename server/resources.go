package server

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/jingwei/db"
	"github.com/Autumn-27/jingwei/scanner"
)

// resourceManager owns the lifecycle of resources the platform creates on its
// own host or on the target: callback ports, webshells and (later) tunnels.
// It persists them in managed_resources, expires them by TTL, and runs the
// in-process cleanup registered for a resource when it is released.
type resourceManager struct {
	s *Server

	mu      sync.Mutex
	cleanup map[int64]func(context.Context)
}

func newResourceManager(s *Server) *resourceManager {
	return &resourceManager{s: s, cleanup: map[int64]func(context.Context){}}
}

func (m *resourceManager) start(ctx context.Context) {
	if m == nil || m.s.m.pg == nil {
		return
	}
	// Recover from a crash first: anything already overdue must not sit active.
	m.reap(ctx)
	go m.loop(ctx)
}

func (m *resourceManager) loop(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.reap(ctx)
		}
	}
}

// register persists a resource and remembers its in-process cleanup.
func (m *resourceManager) register(in db.ManagedResourceInput, cleanup func(context.Context)) (*db.ManagedResource, error) {
	if m == nil || m.s.m.pg == nil {
		return nil, fmt.Errorf("数据库未初始化")
	}
	res, err := m.s.m.pg.RegisterManagedResource(in)
	if err != nil {
		return nil, err
	}
	if cleanup != nil {
		m.mu.Lock()
		m.cleanup[res.ID] = cleanup
		m.mu.Unlock()
	}
	return res, nil
}

// release runs the cleanup and marks the resource released. DB release happens
// even when cleanup fails, because the ledger must not keep lying about state.
func (m *resourceManager) release(ctx context.Context, id int64, note string) (bool, error) {
	if m == nil || m.s.m.pg == nil {
		return false, fmt.Errorf("数据库未初始化")
	}
	m.mu.Lock()
	fn := m.cleanup[id]
	delete(m.cleanup, id)
	m.mu.Unlock()
	if fn != nil {
		fn(ctx)
	}
	res, found, err := m.s.m.pg.ReleaseManagedResource(id, note)
	if err != nil || !found {
		return found, err
	}
	if res.Kind == db.ManagedKindCallback {
		m.maybeStopJNDI(ctx)
	}
	return true, nil
}

// releaseTask releases every resource owned by a task (used when a task ends or
// is canceled and its external artifacts must not outlive it).
func (m *resourceManager) releaseTask(ctx context.Context, taskID int64, note string) int {
	if m == nil || m.s.m.pg == nil || taskID <= 0 {
		return 0
	}
	rows, _, err := m.s.m.pg.ListManagedResources("", db.ManagedActive, 500, 0)
	if err != nil {
		return 0
	}
	released := 0
	for _, r := range rows {
		if r.TaskID != nil && *r.TaskID == taskID {
			if ok, _ := m.release(ctx, r.ID, note); ok {
				released++
			}
		}
	}
	return released
}

func (m *resourceManager) reap(ctx context.Context) {
	if m == nil || m.s.m.pg == nil {
		return
	}
	rows, err := m.s.m.pg.ExpireManagedResources(time.Now())
	if err != nil {
		log.Printf("[resources] expire: %v", err)
		return
	}
	for _, r := range rows {
		m.mu.Lock()
		fn := m.cleanup[r.ID]
		delete(m.cleanup, r.ID)
		m.mu.Unlock()
		if fn != nil {
			fn(ctx)
		}
		log.Printf("[resources] 资源 #%d（%s %s）已过期回收", r.ID, r.Kind, r.Endpoint)
	}
	if len(rows) > 0 {
		m.maybeStopJNDI(ctx)
	}
}

// maybeStopJNDI closes the shared JNDI listener once the last managed callback
// is gone. The java-chains service itself stays up; only the exposed JNDI port
// is stopped, matching the "callback ports closed after use" rule.
func (m *resourceManager) maybeStopJNDI(ctx context.Context) {
	if m == nil || m.s.m.pg == nil {
		return
	}
	n, err := m.s.m.pg.CountActiveManagedResources(db.ManagedKindCallback)
	if err != nil || n > 0 {
		return
	}
	cfg := scanner.JavaChainsConfigFromEnv()
	if !cfg.Configured() {
		return
	}
	client := scanner.NewJavaChainsClient(cfg, 8*time.Second)
	callCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	active, err := client.ActiveJNDIPublications(callCtx)
	if err != nil || active > 0 {
		return
	}
	if err := client.StopJNDI(callCtx); err != nil {
		log.Printf("[resources] 停止空闲 JNDI 服务: %v", err)
	} else {
		log.Printf("[resources] 已停止空闲 JNDI 服务")
	}
}

// ---------------------------------------------------------------- Webshell 台账

func webshellTTL() time.Duration {
	hours := 168 // 7 days
	if raw := strings.TrimSpace(os.Getenv("JINGWEI_WEBSHELL_TTL_HOURS")); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			hours = n
		}
	}
	return time.Duration(hours) * time.Hour
}

func ptrTime(t time.Time) *time.Time { return &t }

// registerWebshellResource puts a newly created/uploaded webshell into the
// shared ledger with a TTL. It never blocks the caller: a ledger failure is
// logged and the webshell remains usable.
func (s *Server) registerWebshellResource(ws *db.Webshell, uploadURL, landURL string) {
	if s == nil || s.resourceMgr == nil || ws == nil {
		return
	}
	endpoint := strings.TrimSpace(ws.URL)
	if endpoint == "" {
		endpoint = strings.TrimSpace(uploadURL)
	}
	if endpoint == "" {
		return
	}
	meta := map[string]any{
		"webshell_id": ws.ID,
		"shell_type":  ws.ShellType,
		"upload_url":  uploadURL,
		"land_url":    landURL,
	}
	if ws.TaskID != nil {
		meta["task_id"] = *ws.TaskID
	}
	if _, err := s.resourceMgr.register(db.ManagedResourceInput{
		Kind:      db.ManagedKindWebshell,
		Name:      displayOr(ws.Name, "webshell"),
		Endpoint:  endpoint,
		Target:    ws.Target,
		Owner:     "webshell:" + displayOr(ws.Source, "manual"),
		TaskID:    ws.TaskID,
		ExpiresAt: ptrTime(time.Now().Add(webshellTTL())),
		Metadata:  meta,
		Note:      "webshell 生命周期跟踪",
	}, nil); err != nil {
		log.Printf("[resources] 登记 webshell #%d: %v", ws.ID, err)
	}
}

func (s *Server) releaseWebshellResource(id int64, note string) {
	if s == nil || s.m == nil || s.m.pg == nil {
		return
	}
	if err := s.m.pg.ReleaseManagedResourceByWebshell(id, note); err != nil {
		log.Printf("[resources] 释放 webshell #%d 台账: %v", id, err)
	}
}

// ---------------------------------------------------------------- 端口审计

// PortListener is one local listening socket.
type PortListener struct {
	Proto       string `json:"proto"`
	Address     string `json:"address"`
	Port        int    `json:"port"`
	PID         int    `json:"pid,omitempty"`
	Process     string `json:"process,omitempty"`
	Scope       string `json:"scope"` // loopback | wildcard | interface
	Managed     bool   `json:"managed"`
	ManagedID   int64  `json:"managed_id,omitempty"`
	ManagedKind string `json:"managed_kind,omitempty"`
	Platform    bool   `json:"platform"`
}

// PortAuditResult is the outcome of comparing listeners with the ledger.
type PortAuditResult struct {
	CheckedAt time.Time      `json:"checked_at"`
	Listeners []PortListener `json:"listeners"`
	Unmanaged []PortListener `json:"unmanaged"`
	AllowList []int          `json:"allow_ports"`
}

type rawListener struct {
	proto string
	ip    net.IP
	port  int
	inode string
}

func (s *Server) auditLocalPorts(ctx context.Context) PortAuditResult {
	out := PortAuditResult{CheckedAt: time.Now(), Listeners: []PortListener{}, Unmanaged: []PortListener{}}
	allow := portAuditAllowList()
	out.AllowList = allow
	managed := map[int]db.ManagedResource{}
	if s.m != nil && s.m.pg != nil {
		if rows, _, err := s.m.pg.ListManagedResources("", db.ManagedActive, 500, 0); err == nil {
			for _, r := range rows {
				switch r.Kind {
				case db.ManagedKindCallback, db.ManagedKindListener, db.ManagedKindTunnel:
				default:
					continue
				}
				if port := endpointPort(r.Endpoint); port > 0 {
					managed[port] = *r
				}
			}
		}
	}
	owners := socketOwners()
	self := os.Getpid()
	for _, raw := range collectListeners() {
		l := PortListener{
			Proto:   raw.proto,
			Address: raw.ip.String(),
			Port:    raw.port,
			Scope:   listenerScope(raw.ip),
		}
		if pid, ok := owners[raw.inode]; ok {
			l.PID = pid
			l.Process = processName(pid)
			if pid == self && l.Scope != "loopback" {
				l.Platform = true
			}
		}
		if r, ok := managed[raw.port]; ok {
			l.Managed = true
			l.ManagedID = r.ID
			l.ManagedKind = r.Kind
		}
		if !l.Managed && !l.Platform && sliceContainsInt(allow, raw.port) && l.Scope != "loopback" {
			l.Platform = true
		}
		out.Listeners = append(out.Listeners, l)
		if !l.Managed && !l.Platform && l.Scope != "loopback" {
			out.Unmanaged = append(out.Unmanaged, l)
		}
	}
	return out
}

// portAuditAllowList returns ports that are expected to be platform/infra
// listeners. JINGWEI_PORT_AUDIT_ALLOW augments the built-in defaults.
func portAuditAllowList() []int {
	out := []int{8787, 8788, 9790}
	for _, key := range []string{"JINGWEI_PORT_AUDIT_ALLOW"} {
		for _, part := range strings.Split(os.Getenv(key), ",") {
			if n, err := strconv.Atoi(strings.TrimSpace(part)); err == nil && n > 0 && !sliceContainsInt(out, n) {
				out = append(out, n)
			}
		}
	}
	return out
}

func sliceContainsInt(items []int, want int) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}

func listenerScope(ip net.IP) string {
	if ip.IsLoopback() {
		return "loopback"
	}
	if ip.IsUnspecified() {
		return "wildcard"
	}
	return "interface"
}

func collectListeners() []rawListener {
	out := []rawListener{}
	for _, spec := range []struct{ path, proto string }{
		{"/proc/net/tcp", "tcp"},
		{"/proc/net/tcp6", "tcp6"},
	} {
		out = append(out, readProcNet(spec.path, spec.proto)...)
	}
	return out
}

func readProcNet(path, proto string) []rawListener {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Scan() // header
	out := []rawListener{}
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		// sl local rem st tx:rx tr:when retrnsmt uid timeout inode
		if len(fields) < 10 || fields[3] != "0A" {
			continue
		}
		ip, port, ok := parseProcAddr(fields[1])
		if !ok {
			continue
		}
		out = append(out, rawListener{proto: proto, ip: ip, port: port, inode: fields[9]})
	}
	return out
}

// parseProcAddr decodes the kernel's hex address form (little-endian u32 words).
func parseProcAddr(s string) (net.IP, int, bool) {
	host, portHex, ok := strings.Cut(s, ":")
	if !ok {
		return nil, 0, false
	}
	port, err := strconv.ParseUint(portHex, 16, 16)
	if err != nil {
		return nil, 0, false
	}
	switch len(host) {
	case 8:
		v, err := strconv.ParseUint(host, 16, 32)
		if err != nil {
			return nil, 0, false
		}
		return net.IPv4(byte(v), byte(v>>8), byte(v>>16), byte(v>>24)), int(port), true
	case 32:
		b := make([]byte, 16)
		for i := 0; i < 4; i++ {
			w, err := strconv.ParseUint(host[i*8:(i+1)*8], 16, 32)
			if err != nil {
				return nil, 0, false
			}
			b[i*4] = byte(w)
			b[i*4+1] = byte(w >> 8)
			b[i*4+2] = byte(w >> 16)
			b[i*4+3] = byte(w >> 24)
		}
		return net.IP(b), int(port), true
	}
	return nil, 0, false
}

func socketOwners() map[string]int {
	out := map[string]int{}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return out
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		fdDir := filepath.Join("/proc", e.Name(), "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}
		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil || !strings.HasPrefix(link, "socket:[") {
				continue
			}
			inode := strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]")
			if inode != "" {
				out[inode] = pid
			}
		}
	}
	return out
}

func processName(pid int) string {
	if pid <= 0 {
		return ""
	}
	if b, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "comm")); err == nil {
		return strings.TrimSpace(string(b))
	}
	return ""
}

// endpointPort extracts the port from "host:port" or a URL endpoint.
func endpointPort(endpoint string) int {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return 0
	}
	if strings.Contains(endpoint, "://") {
		u, err := url.Parse(endpoint)
		if err != nil {
			return 0
		}
		if p := u.Port(); p != "" {
			n, _ := strconv.Atoi(p)
			return n
		}
		switch u.Scheme {
		case "http":
			return 80
		case "https":
			return 443
		}
		return 0
	}
	if _, port, err := net.SplitHostPort(endpoint); err == nil {
		n, _ := strconv.Atoi(port)
		return n
	}
	return 0
}

// ---------------------------------------------------------------- HTTP API

func (s *Server) listManagedResources(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	q := r.URL.Query()
	rows, total, err := pg.ListManagedResources(q.Get("kind"), q.Get("status"),
		atoiDefault(q.Get("limit"), 100), atoiDefault(q.Get("offset"), 0))
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"resources": rows, "total": total})
}

func (s *Server) releaseManagedResource(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id := int64(atoiDefault(r.PathValue("id"), 0))
	if id <= 0 {
		writeErr(w, 400, "invalid id")
		return
	}
	if s.resourceMgr != nil {
		ok, err := s.resourceMgr.release(r.Context(), id, "手动释放")
		if err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		if !ok {
			writeErr(w, 404, "资源不存在或已释放")
			return
		}
		writeJSON(w, 200, map[string]any{"released": true})
		return
	}
	res, found, err := pg.ReleaseManagedResource(id, "手动释放")
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if !found {
		writeErr(w, 404, "资源不存在或已释放")
		return
	}
	writeJSON(w, 200, map[string]any{"released": true, "resource": res})
}

func (s *Server) auditLocalPortsHandler(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, s.auditLocalPorts(r.Context()))
}
