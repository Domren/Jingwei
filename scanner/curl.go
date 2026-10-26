package scanner

import "strings"

// CurlRequest is the request nuclei described with its curl-command field.
type CurlRequest struct {
	Method  string
	URL     string
	Body    string
	Headers []string
	Cookie  string
}

// curlValueFlags are the curl options that consume the token after them.
var curlValueFlags = map[string]bool{
	"-x": true, "--request": true,
	"-d": true, "--data": true, "--data-raw": true, "--data-binary": true,
	"--data-urlencode": true,
	"-h":               true, "--header": true,
	"-b": true, "--cookie": true,
	"-a": true, "--user-agent": true,
	"-e": true, "--referer": true,
	"-o": true, "--output": true,
	"--url": true,
}

// ParseCurlRequest rebuilds a request from nuclei's curl-command.
//
// nuclei only prints the raw request for some hits, and the curl command is
// always there. Reading the method and body off it matters: a POC that injects
// through a POST form leaves the URL as a plain page otherwise, and sqlmap then
// reports a real injection point as absent.
func ParseCurlRequest(curl string) (CurlRequest, bool) {
	tokens := curlTokens(curl)
	if len(tokens) == 0 {
		return CurlRequest{}, false
	}
	req := CurlRequest{Method: "GET"}
	for i := 0; i < len(tokens); i++ {
		tok := tokens[i]
		if strings.HasPrefix(tok, "-") && len(tok) > 1 {
			flag := strings.ToLower(tok)
			var value string
			if eq := strings.Index(flag, "="); eq > 0 && flag != "--data-urlencode" {
				flag, value = flag[:eq], tok[eq+1:]
			} else if curlValueFlags[flag] && i+1 < len(tokens) {
				i++
				value = tokens[i]
			} else {
				continue
			}
			switch flag {
			case "-x", "--request", "--url":
				if flag == "--url" {
					req.URL = value
				} else {
					req.Method = strings.ToUpper(value)
				}
			case "-d", "--data", "--data-raw", "--data-binary", "--data-urlencode":
				req.Body = value
			case "-h", "--header":
				name, _, ok := strings.Cut(value, ":")
				name = strings.TrimSpace(name)
				switch {
				// The URL already carries the authority, so a second Host line
				// would make the packet ambiguous.
				case !ok || name == "" || strings.EqualFold(name, "host"):
				case strings.EqualFold(name, "cookie"):
					req.Cookie = strings.TrimSpace(value[strings.Index(value, ":")+1:])
				default:
					req.Headers = append(req.Headers, value)
				}
			case "-b", "--cookie":
				req.Cookie = value
			case "-a", "--user-agent":
				req.Headers = append(req.Headers, "User-Agent: "+value)
			case "-e", "--referer":
				req.Headers = append(req.Headers, "Referer: "+value)
			}
			continue
		}
		if (strings.HasPrefix(tok, "http://") || strings.HasPrefix(tok, "https://")) && req.URL == "" {
			req.URL = tok
		}
	}
	if req.URL == "" {
		return CurlRequest{}, false
	}
	return req, true
}

// curlTokens splits a command line into arguments, honouring single and double
// quotes and the '\” idiom curl output uses to embed a literal quote.
func curlTokens(curl string) []string {
	var (
		out   []string
		cur   []byte
		quote byte
		start bool
	)
	flush := func() {
		if start {
			out = append(out, string(cur))
			cur = cur[:0]
			start = false
		}
	}
	for i := 0; i < len(curl); i++ {
		c := curl[i]
		switch {
		case quote != 0:
			if c == quote {
				// curl writes an embedded single quote as '\'' : the closing
				// quote, an escaped quote, then a reopened quote. All three
				// characters are consumed so the string stays open.
				if quote == '\'' && i+3 < len(curl) && curl[i+1] == '\\' && curl[i+2] == '\'' && curl[i+3] == '\'' {
					cur = append(cur, '\'')
					i += 3
					continue
				}
				quote = 0
				continue
			}
			if quote == '"' && c == '\\' && i+1 < len(curl) {
				i++
			}
			cur = append(cur, c)
			start = true
		case c == '\'' || c == '"':
			quote, start = c, true
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			flush()
		case c == '\\' && i+1 < len(curl):
			i++
			cur = append(cur, curl[i])
			start = true
		default:
			cur = append(cur, c)
			start = true
		}
	}
	flush()
	if len(out) > 0 && (out[0] == "curl" || strings.HasSuffix(out[0], "/curl")) {
		out = out[1:]
	}
	return out
}
