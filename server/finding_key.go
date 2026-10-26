package server

import (
	"net/url"
	"strings"
)

// findingDedupeKey is the canonical identity of a machine-produced finding:
// template + scheme + host:port + path. Query strings and fragments are dropped
// so the same issue found on different parameters or scans merges into one
// finding, while the original status/evidence history is preserved.
//
// It returns "" when the input cannot identify a target; callers then fall back
// to a non-deduped insert instead of merging unrelated findings.
func findingDedupeKey(templateID, rawURL string) string {
	templateID = strings.TrimSpace(templateID)
	rawURL = strings.TrimSpace(rawURL)
	if templateID == "" || rawURL == "" {
		return ""
	}
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return "v1|" + templateID + "|" + strings.ToLower(rawURL)
	}
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if (scheme == "http" && port == "80") || (scheme == "https" && port == "443") {
		port = ""
	}
	hostport := host
	if port != "" {
		hostport += ":" + port
	}
	path := strings.TrimRight(u.EscapedPath(), "/")
	if path == "" {
		path = "/"
	}
	return "v1|" + templateID + "|" + scheme + "://" + hostport + path
}
