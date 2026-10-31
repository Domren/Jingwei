package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/jingwei/db"
	actool "github.com/Autumn-27/norma/tool"
)

// 内网信息收集：一次会话命令拿回本机地址、路由、/etc/hosts、ARP 邻居和监听
// 端口，解析成结构化结果；发现的内网主机可一键提交为 pending 范围审批。
// 解析函数都是纯函数，便于用真实命令输出做单元测试。

const (
	intranetReconMarker    = "__JW_RECON__"
	intranetReconMaxHosts  = 20
	intranetReconTimeout   = 45 * time.Second
	intranetReconMaxList   = 200
	intranetReconMaxOutput = 8000
)

const intranetReconScript = `printf '__JW_RECON__addr\n'
(ip -o addr 2>/dev/null || ifconfig -a 2>/dev/null) | head -n 300
printf '__JW_RECON__route\n'
(ip route 2>/dev/null || route -n 2>/dev/null) | head -n 200
printf '__JW_RECON__hosts\n'
head -n 300 /etc/hosts 2>/dev/null
printf '__JW_RECON__neigh\n'
(ip neigh 2>/dev/null || arp -an 2>/dev/null) | head -n 300
printf '__JW_RECON__listen\n'
(ss -lnt 2>/dev/null || netstat -lnt 2>/dev/null) | head -n 300
printf '__JW_RECON__end\n'
: # must not exit: intranetScript appends the cwd/exit-code trailer after this
`

// intranetReconScriptWindows must stay on one line: cmd.exe invoked by PHP
// system() only executes the first line of a multi-line command.
const intranetReconScriptWindows = intranetWindowsCodepage + `echo __JW_RECON__addr & ipconfig /all & echo __JW_RECON__route & route print & echo __JW_RECON__hosts & type "%SystemRoot%\System32\drivers\etc\hosts" & echo __JW_RECON__neigh & arp -a & echo __JW_RECON__listen & netstat -ano & echo __JW_RECON__end`

type intranetRoute struct {
	Destination string `json:"destination"`
	Gateway     string `json:"gateway,omitempty"`
	Iface       string `json:"iface,omitempty"`
}

type intranetHostEntry struct {
	IP    string   `json:"ip"`
	Names []string `json:"names,omitempty"`
}

type intranetNeighbor struct {
	IP    string `json:"ip"`
	MAC   string `json:"mac,omitempty"`
	Iface string `json:"iface,omitempty"`
	State string `json:"state,omitempty"`
}

type intranetListener struct {
	Address string `json:"address"`
	Port    int    `json:"port"`
	Scope   string `json:"scope"` // all | interface | local
}

type intranetReconInfo struct {
	IPs       []string            `json:"ips"`
	Routes    []intranetRoute     `json:"routes"`
	Hosts     []intranetHostEntry `json:"hosts"`
	Neighbors []intranetNeighbor  `json:"neighbors"`
	Listeners []intranetListener  `json:"listeners"`
	Raw       string              `json:"raw,omitempty"`
}

type intranetReconResult struct {
	SessionID     int64                      `json:"session_id"`
	Info          intranetReconInfo          `json:"info"`
	Result        intranetExecOutcome        `json:"result"`
	Candidates    []string                   `json:"candidates,omitempty"`
	ScopeRequests []*db.IntranetScopeRequest `json:"scope_requests,omitempty"`
	Warnings      []string                   `json:"warnings,omitempty"`
}

func intranetUsableIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return false
	}
	return !ip.Equal(net.IPv4bcast)
}

func splitIntranetReconSections(raw string) map[string]string {
	sections := map[string]string{}
	current := ""
	var buf strings.Builder
	flush := func() {
		if current != "" {
			sections[current] = buf.String()
			buf.Reset()
		}
	}
	for _, line := range strings.Split(raw, "\n") {
		trim := strings.TrimSpace(line)
		if strings.HasPrefix(trim, intranetReconMarker) {
			flush()
			current = strings.TrimSpace(strings.TrimPrefix(trim, intranetReconMarker))
			continue
		}
		if current != "" {
			buf.WriteString(line)
			buf.WriteByte('\n')
		}
	}
	flush()
	return sections
}

var (
	reIntranetInet = regexp.MustCompile(`\binet6?\s+(?:addr:)?([0-9a-fA-F:.]+)(?:/\d+)?`)
	// ipconfig /all: "IPv4 Address. . . . . . : 10.0.0.5(Preferred)", any locale.
	reIntranetWinIPv4 = regexp.MustCompile(`(?i)IPv4[^:]*:\s*([0-9]{1,3}(?:\.[0-9]{1,3}){3})`)
)

func parseIntranetReconAddrs(section string) []string {
	out := []string{}
	seen := map[string]bool{}
	add := func(raw string) bool {
		ip := net.ParseIP(strings.TrimSpace(raw))
		if !intranetUsableIP(ip) {
			return false
		}
		v := ip.String()
		if seen[v] {
			return false
		}
		seen[v] = true
		out = append(out, v)
		return len(out) >= intranetReconMaxList
	}
	for _, line := range strings.Split(section, "\n") {
		for _, m := range reIntranetInet.FindAllStringSubmatch(line, -1) {
			if add(m[1]) {
				return out
			}
		}
		for _, m := range reIntranetWinIPv4.FindAllStringSubmatch(line, -1) {
			if add(m[1]) {
				return out
			}
		}
	}
	return out
}

func parseIntranetReconRoutes(section string) []intranetRoute {
	out := []intranetRoute{}
	seen := map[string]bool{}
	add := func(r intranetRoute) {
		key := r.Destination + "|" + r.Gateway + "|" + r.Iface
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, r)
	}
	for _, line := range strings.Split(section, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		switch fields[0] {
		case "Kernel", "Destination", "Routing", "Internet", "IPv4", "IPv6":
			continue
		}
		if ip := net.ParseIP(fields[0]); ip != nil && len(fields) >= 8 {
			// netstat -rn: Destination Gateway Genmask Flags Metric Ref Use Iface
			dest := ip.String()
			if dest == "0.0.0.0" {
				dest = "default"
			}
			gw := fields[1]
			if gw == "0.0.0.0" {
				gw = ""
			}
			add(intranetRoute{Destination: dest, Gateway: gw, Iface: fields[len(fields)-1]})
		} else if ip := net.ParseIP(fields[0]); ip != nil && len(fields) >= 5 &&
			net.ParseIP(fields[1]) != nil && net.ParseIP(fields[3]) != nil {
			// Windows route print: Destination Netmask Gateway Interface Metric.
			// The gateway column is localized ("On-link"/在链路上) for direct
			// routes, so keep the route and drop a non-IP gateway instead of
			// falling through to the destination-only branch.
			dest := ip.String()
			if dest == "0.0.0.0" {
				dest = "default"
			}
			gw := ""
			if parsed := net.ParseIP(fields[2]); parsed != nil && !parsed.IsUnspecified() {
				gw = fields[2]
			}
			add(intranetRoute{Destination: dest, Gateway: gw, Iface: fields[3]})
		} else {
			// ip route: default via 172.17.0.1 dev eth0 / 10.0.0.0/8 dev eth0 ...
			dest := fields[0]
			switch dest {
			case "broadcast", "local", "multicast", "unreachable", "blackhole", "prohibit", "throw":
				continue
			}
			if dest != "default" && net.ParseIP(dest) == nil && !strings.Contains(dest, "/") {
				continue
			}
			r := intranetRoute{Destination: dest}
			for i := 1; i < len(fields)-1; i++ {
				switch fields[i] {
				case "via":
					r.Gateway = fields[i+1]
				case "dev":
					r.Iface = fields[i+1]
				}
			}
			add(r)
		}
		if len(out) >= intranetReconMaxList {
			break
		}
	}
	return out
}

func parseIntranetReconHosts(section string) []intranetHostEntry {
	out := []intranetHostEntry{}
	for _, line := range strings.Split(section, "\n") {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		ip := net.ParseIP(fields[0])
		if !intranetUsableIP(ip) {
			continue
		}
		out = append(out, intranetHostEntry{IP: ip.String(), Names: append([]string{}, fields[1:]...)})
		if len(out) >= intranetReconMaxList {
			break
		}
	}
	return out
}

var (
	reIntranetArp    = regexp.MustCompile(`\(([^)]+)\)\s+at\s+(\S+)(?:\s+\[[^\]]+\])?(?:\s+on\s+(\S+))?`)
	reIntranetWinMac = regexp.MustCompile(`^([0-9a-fA-F]{2}[-:]){5}[0-9a-fA-F]{2}$`)
)

func parseIntranetReconNeighbors(section string) []intranetNeighbor {
	out := []intranetNeighbor{}
	seen := map[string]bool{}
	add := func(n intranetNeighbor) {
		key := n.IP + "|" + n.MAC
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, n)
	}
	for _, line := range strings.Split(section, "\n") {
		switch {
		case strings.Contains(line, "lladdr"):
			// ip neigh: 172.17.0.1 dev eth0 lladdr 02:42:... REACHABLE
			fields := strings.Fields(line)
			ip := net.ParseIP(fields[0])
			if !intranetUsableIP(ip) {
				continue
			}
			n := intranetNeighbor{IP: ip.String()}
			if len(fields) > 0 {
				n.State = fields[len(fields)-1]
			}
			for i := 1; i < len(fields)-1; i++ {
				switch fields[i] {
				case "lladdr":
					n.MAC = fields[i+1]
				case "dev":
					n.Iface = fields[i+1]
				}
			}
			add(n)
		case strings.Contains(line, ") at "):
			// arp -an: ? (172.17.0.1) at 02:42:... [ether] on eth0
			m := reIntranetArp.FindStringSubmatch(line)
			if len(m) == 0 {
				continue
			}
			ip := net.ParseIP(strings.TrimSpace(m[1]))
			if !intranetUsableIP(ip) {
				continue
			}
			mac := strings.TrimSpace(m[2])
			if strings.Contains(mac, "incomplete") || mac == "" {
				continue
			}
			add(intranetNeighbor{IP: ip.String(), MAC: mac, Iface: m[3]})
		default:
			// Windows arp -a: 10.0.0.1  00-11-22-33-44-55  dynamic
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				if ip := net.ParseIP(fields[0]); intranetUsableIP(ip) && reIntranetWinMac.MatchString(fields[1]) {
					add(intranetNeighbor{IP: ip.String(), MAC: fields[1], State: fields[len(fields)-1]})
				}
			}
		}
		if len(out) >= intranetReconMaxList {
			break
		}
	}
	return out
}

// splitIntranetReconHostPort splits "0.0.0.0:22", "[::]:22" and ":::22".
func splitIntranetReconHostPort(s string) (string, int, bool) {
	s = strings.TrimSpace(s)
	idx := strings.LastIndex(s, ":")
	if idx <= 0 || idx == len(s)-1 {
		return "", 0, false
	}
	host := strings.Trim(s[:idx], "[]")
	port, err := strconv.Atoi(s[idx+1:])
	if err != nil || port <= 0 || port > 65535 {
		return "", 0, false
	}
	if host == "" {
		host = "::"
	}
	return host, port, true
}

func parseIntranetReconListeners(section string) []intranetListener {
	out := []intranetListener{}
	seen := map[string]bool{}
	add := func(host string, port int) {
		key := host + ":" + strconv.Itoa(port)
		if seen[key] {
			return
		}
		seen[key] = true
		scope := "interface"
		switch host {
		case "*", "0.0.0.0", "::":
			scope = "all"
		default:
			if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
				scope = "local"
			}
		}
		out = append(out, intranetListener{Address: host, Port: port, Scope: scope})
	}
	for _, line := range strings.Split(section, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		switch strings.ToLower(fields[0]) {
		case "listen":
			// ss -lnt: LISTEN 0 128 0.0.0.0:22 0.0.0.0:*
			if host, port, ok := splitIntranetReconHostPort(fields[3]); ok {
				add(host, port)
			}
		case "tcp", "tcp6":
			// netstat -lnt: tcp 0 0 0.0.0.0:22 0.0.0.0:* LISTEN
			// netstat -ano: TCP local foreign LISTENING pid
			local := fields[3]
			if strings.EqualFold(local, "LISTENING") && len(fields) >= 5 {
				local = fields[1]
			}
			if host, port, ok := splitIntranetReconHostPort(local); ok {
				add(host, port)
			}
		}
		if len(out) >= intranetReconMaxList {
			break
		}
	}
	return out
}

func parseIntranetRecon(raw string) intranetReconInfo {
	sections := splitIntranetReconSections(raw)
	return intranetReconInfo{
		IPs:       parseIntranetReconAddrs(sections["addr"]),
		Routes:    parseIntranetReconRoutes(sections["route"]),
		Hosts:     parseIntranetReconHosts(sections["hosts"]),
		Neighbors: parseIntranetReconNeighbors(sections["neigh"]),
		Listeners: parseIntranetReconListeners(sections["listen"]),
	}
}

// intranetReconScopeCandidates lists hosts worth asking for scope approval:
// neighbors, /etc/hosts entries, interface-bound listeners and gateways, minus
// the host's own addresses and loopback noise.
func intranetReconScopeCandidates(info intranetReconInfo) []string {
	local := map[string]bool{}
	for _, ip := range info.IPs {
		local[ip] = true
	}
	out := []string{}
	seen := map[string]bool{}
	add := func(raw string) {
		if len(out) >= intranetReconMaxHosts {
			return
		}
		ip := net.ParseIP(strings.TrimSpace(raw))
		if !intranetUsableIP(ip) {
			return
		}
		v := ip.String()
		if local[v] || seen[v] {
			return
		}
		seen[v] = true
		out = append(out, v)
	}
	for _, n := range info.Neighbors {
		switch strings.ToUpper(strings.TrimSpace(n.State)) {
		case "FAILED", "INCOMPLETE":
			continue
		}
		if strings.EqualFold(strings.ReplaceAll(n.MAC, ":", "-"), "ff-ff-ff-ff-ff-ff") {
			continue // 广播地址不是可探测主机
		}
		add(n.IP)
	}
	for _, h := range info.Hosts {
		add(h.IP)
	}
	for _, l := range info.Listeners {
		if l.Scope == "interface" {
			add(l.Address)
		}
	}
	for _, r := range info.Routes {
		add(r.Gateway)
	}
	return out
}

func (s *Server) intranetRecon(ctx context.Context, pg *db.DB, sess *db.IntranetSession, requestScope bool) intranetReconResult {
	res := intranetReconResult{SessionID: sess.ID}
	script := intranetReconScript
	if s.intranetOS(ctx, pg, sess) == intranetOSWindows {
		script = intranetReconScriptWindows
	}
	out := s.intranetRun(ctx, pg, sess, script, intranetReconTimeout)
	res.Result = out
	info := parseIntranetRecon(out.Output)
	info.Raw = truncateIntranetOutput(strings.TrimSpace(out.Output), intranetReconMaxOutput)
	res.Info = info
	res.Candidates = intranetReconScopeCandidates(info)
	summary := fmt.Sprintf("内网信息收集：本机地址 %d、路由 %d、hosts %d、邻居 %d、监听 %d",
		len(info.IPs), len(info.Routes), len(info.Hosts), len(info.Neighbors), len(info.Listeners))
	_ = pg.AddIntranetSessionEvent(sess.ID, "recon", summary+"\n"+strings.TrimSpace(out.Output), truncateIntranetOutput(out.Output, intranetReconMaxOutput), out.IsError)
	if !requestScope || len(res.Candidates) == 0 {
		return res
	}
	taskID := int64(0)
	if sess.TaskID != nil {
		taskID = *sess.TaskID
	}
	if taskID <= 0 {
		res.Warnings = append(res.Warnings, "会话未绑定任务，未自动提交范围审批")
		return res
	}
	inScope, err := intranetTaskScopeNets(pg, taskID)
	if err != nil {
		res.Warnings = append(res.Warnings, "读取任务范围失败: "+err.Error())
	}
	for _, host := range res.Candidates {
		if inScope(host) {
			continue
		}
		row, _, cerr := pg.CreateIntranetScopeRequest(db.IntranetScopeRequestInput{
			TaskID: taskID, Host: host, Reason: fmt.Sprintf("信息收集发现内网主机（会话 #%d）", sess.ID), SessionID: sess.ID,
		})
		if cerr != nil {
			res.Warnings = append(res.Warnings, fmt.Sprintf("提交 %s 范围申请失败: %v", host, cerr))
			continue
		}
		if row != nil {
			res.ScopeRequests = append(res.ScopeRequests, row)
		}
	}
	return res
}

// intranetTaskScopeNets returns an IP-containment predicate for the task's
// registered scope, so recon does not file duplicate requests for known hosts.
func intranetTaskScopeNets(pg *db.DB, taskID int64) (func(host string) bool, error) {
	scope, err := pg.Assets().ListTaskScope(taskID)
	if err != nil {
		return func(string) bool { return false }, err
	}
	nets := make([]*net.IPNet, 0, len(scope))
	hosts := map[string]bool{}
	for _, sc := range scope {
		if sc.Net != "" {
			if _, n, perr := net.ParseCIDR(sc.Net); perr == nil {
				nets = append(nets, n)
			}
		}
		if sc.Value != "" {
			hosts[strings.ToLower(strings.TrimSpace(sc.Value))] = true
		}
	}
	return func(host string) bool {
		host = strings.ToLower(strings.TrimSpace(host))
		if hosts[host] {
			return true
		}
		ip := net.ParseIP(host)
		if ip == nil {
			return false
		}
		for _, n := range nets {
			if n.Contains(ip) {
				return true
			}
		}
		return false
	}, nil
}

func (s *Server) reconIntranetSession(w http.ResponseWriter, r *http.Request) {
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, 400, "无效的会话 ID")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req struct {
		RequestScope bool `json:"request_scope"`
	}
	_ = decode(r, &req)
	pg := s.pg(w)
	if pg == nil {
		return
	}
	sess, err := s.intranetSession(pg, id)
	if err != nil {
		writeErr(w, 404, err.Error())
		return
	}
	res := s.intranetRecon(r.Context(), pg, sess, req.RequestScope)
	code := 200
	if res.Result.IsError && strings.TrimSpace(res.Info.Raw) == "" {
		code = 400
	}
	writeJSON(w, code, res)
}

// ---------------------------------------------------------------------------
// LLM 工具
// ---------------------------------------------------------------------------

func (s *Server) toolIntranetRecon() actool.CoreTool {
	return wrTool("intranet_recon",
		"对内网会话所在主机执行一次信息收集：本机地址、路由、/etc/hosts、ARP 邻居、监听端口，返回结构化结果与原始输出。request_scope=true 时把发现的内网主机提交为 pending 范围审批（不会自动获批，仍需人工批准）。",
		objSchema(map[string]any{
			"session_id":    intranetIntParam("会话 ID（必填）"),
			"request_scope": map[string]any{"type": "boolean", "description": "是否把发现的内网主机提交范围审批（可选，默认 false）"},
		}, "session_id"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				SessionID    int64 `json:"session_id"`
				RequestScope bool  `json:"request_scope"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf("参数格式错误"), nil
			}
			if a.SessionID <= 0 {
				return actool.Errorf("session_id 必填"), nil
			}
			pg, err := s.intranetToolPG()
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			sess, err := s.intranetSession(pg, a.SessionID)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			res := s.intranetRecon(ctx, pg, sess, a.RequestScope)
			return jsonResult(res)
		})
}
