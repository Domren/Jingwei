package guard

import (
	"encoding/json"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// hostTools are the common interaction tools whose positional argument is a
// target host / host:port / IP literal. The list is deliberately narrow: a bare
// hostname that isn't unambiguously a target (e.g. a file name) must not be
// treated as one.
var hostTools = map[string]bool{
	"curl": true, "wget": true, "nc": true, "ncat": true, "netcat": true,
	"nmap": true, "ssh": true, "ping": true, "telnet": true, "dig": true,
	"host": true, "nslookup": true, "masscan": true, "httpx": true,
	"hydra": true, "smbclient": true, "rpcclient": true, "rdesktop": true,
	"xfreerdp": true,
}

// valueFlags take a non-host value as the next token; that token must not be
// mistaken for a target.
var valueFlags = map[string]bool{
	"-p": true, "-o": true, "-oA": true, "-oX": true, "-oN": true, "-oG": true,
	"-iL": true, "-i": true, "-e": true, "-w": true, "-t": true, "-c": true,
	"-H": true, "-A": true, "-U": true, "-d": true, "-x": true, "-u": true,
	"-F": true, "-b": true, "-m": true, "-l": true, "-P": true,
	"--data": true, "--header": true, "--proxy": true, "--user-agent": true,
	"--connect-timeout": true, "--max-time": true, "--output": true,
	"--cacert": true, "--cert": true, "--key": true,
	"--top-ports": true, "--min-rate": true, "--max-rate": true,
}

// targetKeys are JSON field names whose values name a network target. Only
// these fields are inspected (plus host-tool command lines); free text and
// notes are never parsed for hosts.
var targetKeys = map[string]bool{
	"target": true, "targets": true,
	"url": true, "urls": true, "uri": true,
	"base_url": true, "target_url": true,
	"upload_url": true, "land_url": true, "callback_url": true, "shell_url": true,
	"host": true, "hosts": true, "hostname": true,
	"remote_host": true, "listen_host": true, "connect_host": true,
	"domain": true, "domains": true, "ip": true, "ips": true,
	"endpoint": true, "address": true, "addr": true,
}

var (
	reSchemeURL = regexp.MustCompile(`(?i)\b[a-z][a-z0-9+.-]*://[^\s'"<>|\\^` + "`" + `]+`)
	// A bare hostname needs at least one dot and an alphabetic TLD. Numeric-only
	// "TLDs" are rejected so version strings and file names don't leak in.
	reHostName  = regexp.MustCompile(`^(?i)[a-z0-9]([a-z0-9-]*\.)+[a-z]{2,}$`)
	reHostLabel = regexp.MustCompile(`^(?i)[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)
	reShellSep  = regexp.MustCompile(`[\s<>(){}]+`)
	// reCmdSep splits a compound command line into independently-parsed
	// segments, so a host tool's positional context never bleeds into the next
	// command (e.g. "curl ... | tee out.txt" must not treat out.txt as a target).
	reCmdSep = regexp.MustCompile(`[|;&\n]+`)
)

// targetExemptTools describe stored metadata instead of an outgoing
// interaction. insert_assets has its own task-level gate (block + allow) and
// must stay able to record out-of-scope discoveries; add_task_scope exists
// precisely to widen the scope.
var targetExemptTools = map[string]bool{
	"insert_assets":          true,
	"add_task_scope":         true,
	"add_company_scope":      true,
	"intranet_request_scope": true,
	"list_assets":            true,
	"list_untested_assets":   true,
	"list_companies":         true,
}

// ExtractTargets returns the network targets a tool call interacts with:
// URLs and hosts mentioned on a shell command line plus target-shaped JSON
// fields. Conservative by design — when a target cannot be identified with
// confidence it is simply not returned ("no target" means "no scope check").
func ExtractTargets(toolName string, input json.RawMessage, cmd string) (urls, hosts []string) {
	var b targetBuilder
	if cmd != "" {
		b.fromCommand(cmd)
	}
	if len(input) > 0 && !targetExemptTools[toolName] {
		var v any
		if json.Unmarshal(input, &v) == nil {
			b.fromJSON(v)
		}
	}
	return b.urls, b.hosts
}

type targetBuilder struct {
	urls     []string
	hosts    []string
	seenURL  map[string]bool
	seenHost map[string]bool
}

func (b *targetBuilder) addURL(raw string) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return
	}
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return
	}
	b.addHostValue(u.Hostname(), true)
	if b.seenURL == nil {
		b.seenURL = map[string]bool{}
	}
	raw = strings.TrimRight(raw, ".,;:)]}")
	if raw == "" || b.seenURL[raw] {
		return
	}
	b.seenURL[raw] = true
	b.urls = append(b.urls, raw)
}

func (b *targetBuilder) addHostValue(h string, allowSingleLabel bool) {
	h = strings.TrimSpace(h)
	h = strings.TrimPrefix(h, "*.")
	h = normalizeHost(h)
	if h == "" {
		return
	}
	if net.ParseIP(h) == nil {
		if !reHostName.MatchString(h) && !(allowSingleLabel && reHostLabel.MatchString(h)) {
			return
		}
	}
	if b.seenHost == nil {
		b.seenHost = map[string]bool{}
	}
	if b.seenHost[h] {
		return
	}
	b.seenHost[h] = true
	b.hosts = append(b.hosts, h)
}

func (b *targetBuilder) fromCommand(command string) {
	for _, raw := range reSchemeURL.FindAllString(command, -1) {
		b.addURL(raw)
	}
	for _, segment := range reCmdSep.Split(command, -1) {
		curTool := false
		skipNext := false
		skipHeaderValue := false
		for _, tok := range reShellSep.Split(segment, -1) {
			tok = strings.Trim(tok, `"'`)
			if tok == "" {
				continue
			}
			if skipNext {
				skipNext = false
				// A value flag never takes another option as its value. curl -i
				// (include headers) followed by -c was swallowing the flag and
				// leaving the cookie-jar filename to be parsed as a target host.
				if !strings.HasPrefix(tok, "-") {
					// Header values are split on whitespace: -H 'Host: evil.test'
					// yields "Host:" and "evil.test". The host there is a header
					// value, not a connection target, so consume it as well.
					if skipHeaderValue && strings.HasSuffix(tok, ":") {
						skipNext = true
					}
					skipHeaderValue = false
					continue
				}
				skipHeaderValue = false
			}
			base := baseOf(tok)
			if isShellKeyword(base) {
				curTool = false
				continue
			}
			if hostTools[base] {
				curTool = true
				continue
			}
			if curTool {
				if strings.HasPrefix(tok, "-") {
					if valueFlags[tok] {
						skipNext = true
						if tok == "-H" || tok == "--header" {
							skipHeaderValue = true
						}
					}
					continue
				}
				if at := strings.LastIndex(tok, "@"); at >= 0 {
					tok = tok[at+1:] // ssh user@host
				}
				if ip := parseBareIP(tok); ip != "" {
					b.addHostValue(ip, false)
				} else if reHostName.MatchString(stripPortMaybe(tok)) {
					b.addHostValue(tok, false)
				}
				continue
			}
			// Outside a host tool's positional args only standalone IP literals are
			// unambiguous enough to count as targets.
			if ip := parseBareIP(tok); ip != "" {
				b.addHostValue(ip, false)
			}
		}
	}
}

func (b *targetBuilder) fromJSON(v any) {
	switch x := v.(type) {
	case map[string]any:
		for k, val := range x {
			if targetKeys[strings.ToLower(strings.TrimSpace(k))] {
				b.fromValue(val)
				continue
			}
			b.fromJSON(val)
		}
	case []any:
		for _, item := range x {
			b.fromJSON(item)
		}
	}
}

func (b *targetBuilder) fromValue(v any) {
	switch x := v.(type) {
	case string:
		b.addValue(x)
	case []any:
		for _, item := range x {
			b.fromValue(item)
		}
	case map[string]any:
		b.fromJSON(x)
	}
}

func (b *targetBuilder) addValue(s string) {
	s = strings.TrimSpace(s)
	if s == "" {
		return
	}
	if strings.Contains(s, "://") {
		b.addURL(s)
		return
	}
	// Accept "host/path", "user@host", "host:port" and bare host/IP.
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if at := strings.LastIndex(s, "@"); at >= 0 {
		s = s[at+1:]
	}
	b.addHostValue(s, false)
}

func isShellKeyword(tok string) bool {
	switch tok {
	case "sudo", "doas", "env", "time", "nice", "xargs":
		return true
	}
	return false
}

func baseOf(tok string) string {
	if j := strings.LastIndex(tok, "/"); j >= 0 {
		return tok[j+1:]
	}
	return tok
}

// parseBareIP returns the IP if tok is an IP literal or ip:port / [v6]:port.
func parseBareIP(tok string) string {
	if host, _, err := net.SplitHostPort(tok); err == nil {
		tok = host
	}
	tok = strings.Trim(tok, "[]")
	if net.ParseIP(tok) != nil {
		return tok
	}
	return ""
}

// stripPortMaybe drops a trailing :<numeric-port> from host:port (best effort).
func stripPortMaybe(tok string) string {
	if host, port, err := net.SplitHostPort(tok); err == nil {
		if _, err := strconv.Atoi(port); err == nil {
			return host
		}
	}
	return tok
}
