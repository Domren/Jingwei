package scanner

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	bannerReadTimeout = 700 * time.Millisecond
	bannerMaxBytes    = 512
	fpTLSTimeout      = 2500 * time.Millisecond
	fpMaxConcurrency  = 128
)

// ServiceFingerprint is the passive result for one open non-HTTP port: a banner
// read without sending application data, plus an optional TLS handshake that
// only collects certificate metadata.
type ServiceFingerprint struct {
	IP      string `json:"ip"`
	Port    int    `json:"port"`
	Service string `json:"service,omitempty"`
	Banner  string `json:"banner,omitempty"`
	// BannerRaw keeps the bytes exactly as read from the socket; Banner is the
	// readable/hex-compacted excerpt stored on assets. The raw copy is what the
	// report turns into a reproducible protocol packet.
	BannerRaw  []byte `json:"-"`
	TLS        bool   `json:"tls,omitempty"`
	CertCN     string `json:"cert_cn,omitempty"`
	CertIssuer string `json:"cert_issuer,omitempty"`
	TLSVersion string `json:"tls_version,omitempty"`
}

// Key is the (ip,port) lookup key shared with coveredServicePorts.
func (f ServiceFingerprint) Key() string { return fingerprintKey(f.IP, f.Port) }

func fingerprintKey(ip string, port int) string {
	return ip + "|" + strconv.Itoa(port)
}

// CoveredServicePorts marks every (ip,port) already covered by an HTTP service so
// fingerprinting and the extra HTTP pass skip them. A domain-based service also
// covers the IP:port it resolved to.
func CoveredServicePorts(services []WebService, domainsByIP map[string][]string) map[string]bool {
	covered := map[string]bool{}
	for _, svc := range services {
		covered[fingerprintKey(svc.IP, svc.Port)] = true
		host := urlHostname(svc.URL)
		if host == "" {
			continue
		}
		covered[host+"|"+strconv.Itoa(svc.Port)] = true
		for ip, domains := range domainsByIP {
			for _, d := range domains {
				if strings.EqualFold(d, host) {
					covered[fingerprintKey(ip, svc.Port)] = true
				}
			}
		}
	}
	return covered
}

func urlHostname(raw string) string {
	if i := strings.Index(raw, "://"); i >= 0 {
		raw = raw[i+3:]
	}
	if i := strings.IndexAny(raw, "/?#"); i >= 0 {
		raw = raw[:i]
	}
	if host, _, err := net.SplitHostPort(raw); err == nil {
		return host
	}
	return raw
}

// FingerprintPorts classifies open ports that have no HTTP service yet. It reads
// whatever banner the server volunteers, then tries a TLS handshake for
// certificate/service hints. It never sends protocol-specific commands.
func FingerprintPorts(ctx context.Context, open []PortFinding, covered map[string]bool, logf func(string, ...any)) map[string]ServiceFingerprint {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	todo := make([]PortFinding, 0, len(open))
	for _, pf := range open {
		if covered[fingerprintKey(pf.IP, pf.Port)] {
			continue
		}
		todo = append(todo, pf)
	}
	out := map[string]ServiceFingerprint{}
	if len(todo) == 0 {
		return out
	}
	logf("开始识别 %d 个非 HTTP 端口的服务指纹", len(todo))

	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, fpMaxConcurrency)
	for _, pf := range todo {
		pf := pf
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case <-ctx.Done():
				return
			case sem <- struct{}{}:
			}
			defer func() { <-sem }()
			fp := fingerprintOne(ctx, pf)
			mu.Lock()
			out[fp.Key()] = fp
			mu.Unlock()
		}()
	}
	wg.Wait()

	named := 0
	for _, fp := range out {
		if fp.Service != "" {
			named++
		}
	}
	logf("服务指纹完成：%d 个端口，识别出 %d 个服务类型", len(out), named)
	return out
}

func fingerprintOne(ctx context.Context, pf PortFinding) ServiceFingerprint {
	fp := ServiceFingerprint{IP: pf.IP, Port: pf.Port, Service: PortLabel(pf.Port)}
	addr := net.JoinHostPort(pf.IP, strconv.Itoa(pf.Port))

	// Passive banner: connect, read, never write.
	if banner := readBanner(ctx, addr); banner != "" {
		fp.BannerRaw = []byte(banner)
		fp.Banner = sanitizeBanner(banner)
		if svc := classifyBanner(banner); svc != "" {
			fp.Service = svc
		}
	}
	if ctx.Err() != nil {
		return fp
	}
	// Banner-only protocols (SSH/FTP/SMTP/...) would just log a bad handshake.
	if fp.Banner != "" && !tlsCandidateService(fp.Service) {
		return fp
	}
	if cn, issuer, version, ok := probeTLS(ctx, addr); ok {
		fp.TLS = true
		fp.CertCN, fp.CertIssuer, fp.TLSVersion = cn, issuer, version
		if fp.Service == "" {
			if pf.Port == 443 || pf.Port == 8443 || pf.Port == 4443 || pf.Port == 9443 {
				fp.Service = "https"
			} else {
				fp.Service = "tls"
			}
		}
	}
	return fp
}

func readBanner(ctx context.Context, addr string) string {
	dialer := net.Dialer{Timeout: 2 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return ""
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(bannerReadTimeout))
	buf := make([]byte, bannerMaxBytes)
	n, _ := conn.Read(buf)
	if n <= 0 {
		return ""
	}
	return string(buf[:n])
}

func probeTLS(ctx context.Context, addr string) (cn, issuer, version string, ok bool) {
	dialer := &net.Dialer{Timeout: fpTLSTimeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return "", "", "", false
	}
	defer conn.Close()
	state := conn.ConnectionState()
	version = tlsVersionName(state.Version)
	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		cn = cert.Subject.CommonName
		if cn == "" && len(cert.DNSNames) > 0 {
			cn = cert.DNSNames[0]
		}
		issuer = cert.Issuer.CommonName
		if issuer == "" && len(cert.Issuer.Organization) > 0 {
			issuer = cert.Issuer.Organization[0]
		}
	}
	return cn, issuer, version, true
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS1.0"
	case tls.VersionTLS11:
		return "TLS1.1"
	case tls.VersionTLS12:
		return "TLS1.2"
	case tls.VersionTLS13:
		return "TLS1.3"
	}
	return "TLS"
}

// tlsCandidateService reports whether a banner-classified service still makes
// sense to TLS-probe (HTTP-ish ports may answer both HTTP and HTTPS).
func tlsCandidateService(service string) bool {
	switch service {
	case "", "http", "https", "http-alt", "https-alt", "tls", "unknown":
		return true
	}
	return false
}

var (
	reSSHBanner   = regexp.MustCompile(`^SSH-\d`)
	reFTPBanner   = regexp.MustCompile(`(?i)^220[- ].*(ftp|proftpd|vsftpd|filezilla)`)
	reSMTPBanner  = regexp.MustCompile(`(?i)^220[- ].*(smtp|mail|postfix|exim)`)
	rePOP3Banner  = regexp.MustCompile(`(?i)^\+OK`)
	reIMAPBanner  = regexp.MustCompile(`(?i)^\* OK`)
	reVNCBanner   = regexp.MustCompile(`^RFB \d`)
	reMySQLBanner = regexp.MustCompile(`(?i)mysql_native_password|caching_sha2_password`)
	reAMQPBanner  = regexp.MustCompile(`^AMQP`)
	reRDPBanner   = regexp.MustCompile(`^\x03\x00\x00`)
	reSMBBanner   = regexp.MustCompile(`(?s)^\x00\x00\x00.\xffSMB`)
	reHTTPBanner  = regexp.MustCompile(`^HTTP/\d`)
	reRedisBanner = regexp.MustCompile(`(?i)^-ERR|^\+PONG|^\$\d+\r\n`)
)

// classifyBanner maps a server-first banner to a service name. Unknown banners
// stay empty on purpose: the extra HTTP pass still gets a chance.
func classifyBanner(banner string) string {
	switch {
	case reSSHBanner.MatchString(banner):
		return "ssh"
	case reHTTPBanner.MatchString(banner):
		return "http"
	case reFTPBanner.MatchString(banner):
		return "ftp"
	case reSMTPBanner.MatchString(banner):
		return "smtp"
	case rePOP3Banner.MatchString(banner):
		return "pop3"
	case reIMAPBanner.MatchString(banner):
		return "imap"
	case reVNCBanner.MatchString(banner):
		return "vnc"
	case reMySQLBanner.MatchString(banner):
		return "mysql"
	case reAMQPBanner.MatchString(banner):
		return "amqp"
	case reRDPBanner.MatchString(banner):
		return "rdp"
	case reSMBBanner.MatchString(banner):
		return "smb"
	case reRedisBanner.MatchString(banner):
		return "redis"
	}
	if strings.HasPrefix(banner, "\xff\xfd") || strings.HasPrefix(banner, "\xff\xfb") {
		return "telnet"
	}
	return ""
}

// sanitizeBanner keeps a readable single-line excerpt; binary protocol bytes are
// rendered as hex so the asset record stays valid UTF-8.
func sanitizeBanner(raw string) string {
	if raw == "" {
		return ""
	}
	printable := true
	for _, r := range raw {
		if r < 0x20 && r != '\r' && r != '\n' && r != '\t' {
			printable = false
			break
		}
	}
	var out string
	if printable {
		out = strings.Join(strings.Fields(raw), " ")
	} else {
		if len(raw) > 64 {
			raw = raw[:64]
		}
		out = "hex:" + hex.EncodeToString([]byte(raw))
	}
	if len(out) > 200 {
		out = out[:200]
	}
	return out
}
