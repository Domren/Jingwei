// Package scanner implements the deterministic, LLM-free scanning pipeline:
// target parsing, port discovery, HTTP probing/fingerprinting, POC matching and
// nuclei execution. It has no dependency on the agent or LLM layers.
package scanner

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// TargetKind classifies one user-supplied target.
type TargetKind string

const (
	KindURL    TargetKind = "url"
	KindIP     TargetKind = "ip"
	KindCIDR   TargetKind = "cidr"
	KindDomain TargetKind = "domain"
)

// Target is one parsed user input.
type Target struct {
	Raw  string     `json:"raw"`
	Kind TargetKind `json:"kind"`
	Host string     `json:"host"` // domain, IP or CIDR
	URL  string     `json:"url,omitempty"`
}

var domainRE = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$`)

// ParseTargets parses and deduplicates raw targets. It accepts URLs, IPv4
// addresses, CIDR blocks (/24 or narrower) and DNS names.
func ParseTargets(raws []string) ([]Target, error) {
	out := make([]Target, 0, len(raws))
	seen := map[string]bool{}
	for _, raw := range raws {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		t, err := ParseTarget(raw)
		if err != nil {
			return nil, err
		}
		key := string(t.Kind) + "|" + strings.ToLower(t.Host) + "|" + t.URL
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, t)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("至少需要一个有效目标")
	}
	return out, nil
}

// ParseTarget parses one target.
func ParseTarget(raw string) (Target, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return Target{}, fmt.Errorf("目标不能为空")
	}
	if strings.Contains(raw, "://") {
		u, err := url.Parse(raw)
		if err != nil || u.Hostname() == "" {
			return Target{}, fmt.Errorf("无效 URL: %s", raw)
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return Target{}, fmt.Errorf("URL 仅支持 http/https: %s", raw)
		}
		u.Fragment = ""
		if u.Path == "" {
			u.Path = "/"
		}
		return Target{Raw: raw, Kind: KindURL, Host: u.Hostname(), URL: u.String()}, nil
	}
	if strings.Contains(raw, "/") {
		ip, ipnet, err := net.ParseCIDR(raw)
		if err != nil {
			return Target{}, fmt.Errorf("无效 CIDR: %s", raw)
		}
		ip4 := ip.To4()
		if ip4 == nil {
			return Target{}, fmt.Errorf("仅支持 IPv4 CIDR: %s", raw)
		}
		ones, bits := ipnet.Mask.Size()
		if bits != 32 || ones < 24 {
			return Target{}, fmt.Errorf("CIDR 最多支持 /24（256 个地址）: %s", raw)
		}
		return Target{Raw: raw, Kind: KindCIDR, Host: (&net.IPNet{IP: ip4.Mask(ipnet.Mask), Mask: ipnet.Mask}).String()}, nil
	}
	if ip := net.ParseIP(raw); ip != nil {
		ip4 := ip.To4()
		if ip4 == nil {
			return Target{}, fmt.Errorf("仅支持 IPv4: %s", raw)
		}
		return Target{Raw: raw, Kind: KindIP, Host: ip4.String()}, nil
	}
	host := strings.TrimSuffix(strings.ToLower(raw), ".")
	if len(host) > 253 || !domainRE.MatchString(host) || numericTLD(host) {
		return Target{}, fmt.Errorf("无效域名或 IP: %s", raw)
	}
	return Target{Raw: raw, Kind: KindDomain, Host: host}, nil
}

// numericTLD rejects IPv4-shaped strings that failed net.ParseIP (e.g.
// 300.1.1.1) instead of silently treating them as DNS names.
func numericTLD(host string) bool {
	i := strings.LastIndex(host, ".")
	if i < 0 || i == len(host)-1 {
		return false
	}
	for _, r := range host[i+1:] {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// InterceptCandidates returns the raw domain/IP/URL strings used by the asset
// intercept gate.
func (t Target) InterceptCandidates() (domains, ips, urls []string) {
	switch t.Kind {
	case KindDomain:
		domains = []string{t.Host}
	case KindIP:
		ips = []string{t.Host}
	case KindCIDR:
		// CIDR is checked after expansion by the caller.
	case KindURL:
		urls = []string{t.URL}
		if u, err := url.Parse(t.URL); err == nil {
			if net.ParseIP(u.Hostname()) != nil {
				ips = []string{u.Hostname()}
			} else {
				domains = []string{u.Hostname()}
			}
		}
	}
	return domains, ips, urls
}

// Resolved holds the network destinations of all targets.
type Resolved struct {
	IPs         []string            `json:"ips"`
	DomainsByIP map[string][]string `json:"domains_by_ip"`
	Domains     []string            `json:"domains"`
	FixedURLs   []string            `json:"fixed_urls"`
}

// Resolve expands CIDRs, resolves domains and returns a deduplicated IP set.
// maxHosts caps the total number of IPs (<=0 uses 256).
func Resolve(ctx context.Context, targets []Target, maxHosts int) (*Resolved, error) {
	if maxHosts <= 0 {
		maxHosts = 256
	}
	r := &Resolved{DomainsByIP: map[string][]string{}}
	ipSeen := map[string]bool{}
	addIP := func(ip, domain string) error {
		if !ipSeen[ip] {
			if len(r.IPs) >= maxHosts {
				return fmt.Errorf("目标展开后超过 %d 个 IP，请缩小范围", maxHosts)
			}
			r.IPs = append(r.IPs, ip)
			ipSeen[ip] = true
		}
		if domain != "" && !containsFold(r.DomainsByIP[ip], domain) {
			r.DomainsByIP[ip] = append(r.DomainsByIP[ip], domain)
		}
		return nil
	}
	domainSeen := map[string]bool{}
	for _, t := range targets {
		switch t.Kind {
		case KindIP:
			if err := addIP(t.Host, ""); err != nil {
				return nil, err
			}
		case KindURL:
			r.FixedURLs = append(r.FixedURLs, t.URL)
			if u, err := url.Parse(t.URL); err == nil {
				host := u.Hostname()
				if net.ParseIP(host) != nil {
					if ip4 := net.ParseIP(host).To4(); ip4 != nil {
						if err := addIP(ip4.String(), ""); err != nil {
							return nil, err
						}
					}
				} else if !domainSeen[host] {
					domainSeen[host] = true
					r.Domains = append(r.Domains, host)
					ips, err := resolveHost(ctx, host)
					if err != nil {
						return nil, err
					}
					for _, ip := range ips {
						if err := addIP(ip, host); err != nil {
							return nil, err
						}
					}
				}
			}
		case KindDomain:
			if domainSeen[t.Host] {
				continue
			}
			domainSeen[t.Host] = true
			r.Domains = append(r.Domains, t.Host)
			ips, err := resolveHost(ctx, t.Host)
			if err != nil {
				return nil, err
			}
			for _, ip := range ips {
				if err := addIP(ip, t.Host); err != nil {
					return nil, err
				}
			}
		case KindCIDR:
			ips, err := expandCIDR(t.Host)
			if err != nil {
				return nil, err
			}
			for _, ip := range ips {
				if err := addIP(ip, ""); err != nil {
					return nil, err
				}
			}
		}
	}
	sort.Strings(r.IPs)
	for ip := range r.DomainsByIP {
		sort.Strings(r.DomainsByIP[ip])
	}
	return r, nil
}

func resolveHost(ctx context.Context, host string) ([]string, error) {
	lookupCtx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupIPAddr(lookupCtx, host)
	if err != nil {
		return nil, fmt.Errorf("解析 %s 失败: %w", host, err)
	}
	out := make([]string, 0, len(addrs))
	seen := map[string]bool{}
	for _, a := range addrs {
		ip4 := a.IP.To4()
		if ip4 == nil {
			continue
		}
		s := ip4.String()
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
		if len(out) >= 16 {
			break
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s 没有可用的 IPv4 地址", host)
	}
	return out, nil
}

func expandCIDR(cidr string) ([]string, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	ones, bits := ipnet.Mask.Size()
	if bits != 32 || ones < 24 {
		return nil, fmt.Errorf("CIDR 最多支持 /24: %s", cidr)
	}
	base := ipnet.IP.To4()
	if base == nil {
		return nil, fmt.Errorf("仅支持 IPv4 CIDR: %s", cidr)
	}
	start := uint32(base[0])<<24 | uint32(base[1])<<16 | uint32(base[2])<<8 | uint32(base[3])
	total := uint32(1) << uint(32-ones)
	first, last := start, start+total-1
	if ones < 31 { // skip network and broadcast
		first++
		last--
	}
	out := make([]string, 0, int(last-first)+1)
	for v := first; v <= last; v++ {
		out = append(out, fmt.Sprintf("%d.%d.%d.%d", byte(v>>24), byte(v>>16), byte(v>>8), byte(v)))
	}
	return out, nil
}

func containsFold(list []string, s string) bool {
	for _, v := range list {
		if strings.EqualFold(v, s) {
			return true
		}
	}
	return false
}

var webPorts = []int{
	80, 81, 443, 3000, 4443, 5000, 5601, 7001, 7002, 8000, 8001, 8008, 8080, 8081,
	8088, 8090, 8161, 8180, 8443, 8888, 9000, 9001, 9043, 9090, 9443, 10000, 15672, 50000,
}

// commonServicePorts extends the high-port range with well-known services that
// are not in the top-100 list (databases, middleware, container APIs, alt web).
// It feeds the top1000 preset together with 1-1024.
var commonServicePorts = []int{
	1080, 1090, 1099, 1433, 1521, 1723, 1883, 2049, 2082, 2083, 2086, 2087, 2121,
	2181, 2222, 2375, 2376, 2379, 2380, 25565, 3000, 3001, 3128, 3260, 3306, 3389,
	3690, 4000, 4040, 4369, 4443, 4505, 4506, 4848, 4899, 5000, 5001, 5005, 5006,
	5432, 5555, 5601, 5672, 5678, 5900, 5901, 5984, 5985, 5986, 6000, 6379, 6443,
	7001, 7002, 7077, 8000, 8001, 8002, 8003, 8004, 8005, 8006, 8007, 8008, 8009,
	8010, 8020, 8030, 8040, 8050, 8060, 8070, 8080, 8081, 8082, 8083, 8084, 8085,
	8086, 8087, 8088, 8089, 8090, 8091, 8100, 8161, 8180, 8200, 8300, 8400, 8443,
	8500, 8888, 9000, 9001, 9042, 9090, 9091, 9092, 9160, 9200, 9300, 9418, 9443,
	10000, 10051, 10250, 11211, 15672, 27017, 27018, 50000, 50070, 61616,
}

// top1000Ports is the default discovery set: every privileged/well-known port
// (1-1024) plus the common service ports above. It is named for the UI preset and
// deliberately deterministic instead of a third-party "top N" ranking.
var top1000Ports = buildTop1000Ports()

func buildTop1000Ports() []int {
	seen := map[int]bool{}
	out := make([]int, 0, 1200)
	add := func(p int) {
		if p >= 1 && p <= 65535 && !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	for _, p := range topPorts {
		add(p)
	}
	for p := 1; p <= 1024; p++ {
		add(p)
	}
	for _, p := range commonServicePorts {
		add(p)
	}
	sort.Ints(out)
	return out
}

var topPorts = []int{
	21, 22, 23, 25, 53, 80, 81, 88, 110, 111, 135, 139, 143, 161, 389, 443, 445, 465,
	514, 587, 631, 636, 873, 993, 995, 1025, 1080, 1099, 1433, 1521, 1723, 2049, 2082,
	2083, 2086, 2087, 2121, 2222, 2375, 2376, 2379, 3000, 3128, 3260, 3306, 3389, 3690, 4000,
	4040, 4369, 4443, 4505, 4506, 5000, 5432, 5601, 5672, 5678, 5900, 5901, 5984, 5985,
	5986, 6000, 6379, 6443, 7001, 7002, 7077, 8000, 8001, 8008, 8080, 8081, 8088, 8089,
	8090, 8161, 8180, 8443, 8500, 8888, 9000, 9001, 9042, 9090, 9091, 9092, 9200, 9300,
	9443, 10000, 10051, 10250, 11211, 15672, 27017, 50000, 50070, 61616,
}

// WebPorts returns a copy of the built-in web port preset.
func WebPorts() []int {
	out := make([]int, len(webPorts))
	copy(out, webPorts)
	return out
}

// IsWebPort reports whether a port should receive an HTTP probe even when it
// is not explicitly part of the configured preset.
func IsWebPort(port int) bool {
	for _, p := range webPorts {
		if p == port {
			return true
		}
	}
	return false
}

// ParsePortSpec accepts web, top100, top1000, full, or a comma-separated port
// list with ranges (e.g. "80,443,8000-8100"). Empty spec means top1000.
func ParsePortSpec(spec string) ([]int, error) {
	spec = strings.ToLower(strings.TrimSpace(spec))
	switch spec {
	case "", "top1000":
		return append([]int(nil), top1000Ports...), nil
	case "top100":
		return append([]int(nil), topPorts...), nil
	case "web":
		return WebPorts(), nil
	case "full":
		out := make([]int, 65535)
		for i := range out {
			out[i] = i + 1
		}
		return out, nil
	}
	seen := map[int]bool{}
	out := []int{}
	for _, part := range strings.FieldsFunc(spec, func(r rune) bool { return r == ',' || r == ' ' || r == ';' }) {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "-") {
			bits := strings.SplitN(part, "-", 2)
			lo, err1 := strconv.Atoi(strings.TrimSpace(bits[0]))
			hi, err2 := strconv.Atoi(strings.TrimSpace(bits[1]))
			if err1 != nil || err2 != nil || lo < 1 || hi > 65535 || lo > hi {
				return nil, fmt.Errorf("无效端口范围: %s", part)
			}
			for p := lo; p <= hi; p++ {
				if !seen[p] {
					seen[p] = true
					out = append(out, p)
				}
			}
			continue
		}
		p, err := strconv.Atoi(part)
		if err != nil || p < 1 || p > 65535 {
			return nil, fmt.Errorf("无效端口: %s", part)
		}
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("端口列表为空")
	}
	sort.Ints(out)
	return out, nil
}

// portLabels names well-known services so assets show something readable
// before banner/TLS fingerprinting runs. Unknown ports stay empty.
var portLabels = map[int]string{
	21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 69: "tftp",
	80: "http", 81: "http", 88: "kerberos", 110: "pop3", 111: "rpcbind",
	135: "msrpc", 139: "netbios", 143: "imap", 161: "snmp", 389: "ldap",
	443: "https", 445: "smb", 465: "smtps", 512: "exec", 513: "login",
	514: "shell", 587: "submission", 631: "ipp", 636: "ldaps", 873: "rsync",
	993: "imaps", 995: "pop3s", 1080: "socks", 1099: "rmi", 1433: "mssql",
	1521: "oracle", 1723: "pptp", 1883: "mqtt", 2049: "nfs", 2082: "cpanel",
	2083: "cpanel-ssl", 2181: "zookeeper", 2222: "ssh-alt", 2375: "docker",
	2376: "docker-tls", 2379: "etcd", 2380: "etcd-peer", 3000: "http-dev",
	3128: "squid", 3260: "iscsi", 3306: "mysql", 3389: "rdp", 3690: "svn",
	4369: "epmd", 4443: "https-alt", 4848: "glassfish", 5000: "http-alt",
	5432: "postgresql", 5555: "adb", 5601: "kibana", 5672: "amqp",
	5900: "vnc", 5901: "vnc-alt", 5984: "couchdb", 5985: "winrm",
	5986: "winrm-tls", 6379: "redis", 6443: "kubernetes", 7001: "weblogic",
	7002: "weblogic-ssl", 7077: "spark", 8000: "http-alt", 8008: "http-alt",
	8009: "ajp", 8010: "http-alt", 8020: "http-alt", 8030: "http-alt",
	8040: "http-alt", 8050: "http-alt", 8060: "http-alt", 8070: "http-alt",
	8080: "http-alt", 8081: "http-alt", 8082: "http-alt", 8083: "http-alt",
	8084: "http-alt", 8085: "http-alt", 8086: "http-alt", 8087: "http-alt",
	8088: "http-alt", 8089: "http-alt", 8090: "http-alt", 8091: "http-alt",
	8100: "http-alt", 8161: "activemq", 8180: "http-alt", 8200: "vault",
	8300: "consul", 8400: "http-alt", 8443: "https-alt", 8500: "consul",
	8888: "http-alt", 9000: "http-alt", 9001: "http-alt", 9042: "cassandra",
	9090: "http-alt", 9091: "http-alt", 9092: "kafka", 9160: "cassandra-thrift",
	9200: "elasticsearch", 9300: "elasticsearch-transport", 9418: "git",
	9443: "https-alt", 10000: "webmin", 10051: "zabbix", 10250: "kubelet",
	11211: "memcached", 15672: "rabbitmq-mgmt", 27017: "mongodb",
	27018: "mongodb-alt", 50000: "db2", 50070: "hdfs", 61616: "activemq-openwire",
}

// PortLabel renders a port list compactly for logs and fallback asset names.
func PortLabel(port int) string {
	return portLabels[port]
}
