package scanner

import "strings"

// CurlRequest is the request nuclei described with its curl-command field.
type CurlRequest struct {
	Method  string
	URL     string
	Body    string
	Headers []string
	Cookie  string
	Proxy   string
}

// curlValueFlags are the curl options that consume the token after them.
// Short options are case-sensitive in curl: -X is the HTTP method while -x is
// the proxy, and -H is a header while -h is help. Lowercasing the token (as
// this parser used to) turned a proxied replay into a request with method
// "HTTP://..." and dropped the real method.
var curlValueFlags = map[string]bool{
	"-X": true, "--request": true,
	"-x": true, "--proxy": true,
	"-d": true, "--data": true, "--data-raw": true, "--data-binary": true,
	"--data-urlencode": true,
	"-H":               true, "--header": true,
	"-b": true, "--cookie": true,
	"-A": true, "--user-agent": true,
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
			flag, value, attached := normalizeCurlFlag(tok)
			if !attached && curlValueFlags[flag] && i+1 < len(tokens) {
				i++
				value = tokens[i]
			} else if !attached && !curlValueFlags[flag] {
				continue
			}
			switch flag {
			case "-X", "--request":
				req.Method = strings.ToUpper(value)
			case "--url":
				req.URL = value
			case "-x", "--proxy":
				req.Proxy = value
			case "-d", "--data", "--data-raw", "--data-binary", "--data-urlencode":
				req.Body = value
			case "-H", "--header":
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
			case "-A", "--user-agent":
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

// normalizeCurlFlag splits one option token into the flag curl interprets and
// its value. Short options keep their case and may carry an attached value
// (-XPOST, -xhttp://proxy:8080); long options accept --flag=value. The
// --data-urlencode exception exists because its value legitimately contains '='.
func normalizeCurlFlag(tok string) (flag, value string, attached bool) {
	if strings.HasPrefix(tok, "--") {
		if eq := strings.Index(tok, "="); eq > 0 && !strings.EqualFold(tok[:eq], "--data-urlencode") {
			return strings.ToLower(tok[:eq]), tok[eq+1:], true
		}
		return strings.ToLower(tok), "", false
	}
	shape := tok
	if len(shape) > 2 {
		shape = shape[:2]
	}
	if len(shape) < 2 || !curlValueFlags[shape] {
		// Boolean short flag (-k, -s, -L): nothing to consume.
		return strings.ToLower(tok), "", false
	}
	if len(tok) > 2 {
		return shape, tok[2:], true
	}
	return shape, "", false
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
