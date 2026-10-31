package scanner

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	xproxy "golang.org/x/net/proxy"
)

// NormalizeProxyURL validates an operator-supplied proxy URL. Only schemes the
// whole pipeline can actually use are accepted: http/https (CONNECT) and
// socks5/socks5h. An empty value means "no proxy".
func NormalizeProxyURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("代理地址无效: %w", err)
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https", "socks5", "socks5h":
	default:
		return "", fmt.Errorf("代理协议不支持: %s（只支持 http/https/socks5/socks5h）", u.Scheme)
	}
	if u.Hostname() == "" {
		return "", fmt.Errorf("代理地址缺少主机: %s", raw)
	}
	if p := u.Port(); p != "" {
		if n, err := strconv.Atoi(p); err != nil || n < 1 || n > 65535 {
			return "", fmt.Errorf("代理端口无效: %s", p)
		}
	}
	return u.String(), nil
}

// ProxyDialFunc returns a dialer that sends every TCP connect through the
// proxy. It is what lets the port scanner and the HTTP prober reach hosts that
// only exist inside the target's network.
func ProxyDialFunc(raw string, timeout time.Duration) (func(ctx context.Context, network, addr string) (net.Conn, error), error) {
	raw, err := NormalizeProxyURL(raw)
	if err != nil || raw == "" {
		return nil, err
	}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	u, _ := url.Parse(raw)
	base := &net.Dialer{Timeout: timeout}
	switch strings.ToLower(u.Scheme) {
	case "socks5", "socks5h":
		var auth *xproxy.Auth
		if u.User != nil {
			auth = &xproxy.Auth{User: u.User.Username()}
			auth.Password, _ = u.User.Password()
		}
		d, err := xproxy.SOCKS5("tcp", u.Host, auth, base)
		if err != nil {
			return nil, fmt.Errorf("SOCKS5 代理初始化失败: %w", err)
		}
		return func(ctx context.Context, network, addr string) (net.Conn, error) {
			if cd, ok := d.(xproxy.ContextDialer); ok {
				return cd.DialContext(ctx, network, addr)
			}
			type dialResult struct {
				conn net.Conn
				err  error
			}
			ch := make(chan dialResult, 1)
			go func() {
				conn, err := d.Dial(network, addr)
				ch <- dialResult{conn, err}
			}()
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case r := <-ch:
				return r.conn, r.err
			}
		}, nil
	case "http", "https":
		return httpConnectDialFunc(u, base, timeout), nil
	}
	return nil, fmt.Errorf("代理协议不支持: %s", u.Scheme)
}

// httpConnectDialFunc tunnels each TCP connection with an HTTP CONNECT request.
// HTTPS proxies are wrapped in TLS first (target certificates are not validated
// anywhere else in the scanner, and an intercepting proxy is the normal case).
func httpConnectDialFunc(u *url.URL, base *net.Dialer, timeout time.Duration) func(ctx context.Context, network, addr string) (net.Conn, error) {
	proxyAddr := u.Host
	if u.Port() == "" {
		port := "80"
		if strings.EqualFold(u.Scheme, "https") {
			port = "443"
		}
		proxyAddr = net.JoinHostPort(u.Hostname(), port)
	}
	authHeader := ""
	if u.User != nil {
		password, _ := u.User.Password()
		token := base64.StdEncoding.EncodeToString([]byte(u.User.Username() + ":" + password))
		authHeader = "Proxy-Authorization: Basic " + token + "\r\n"
	}
	useTLS := strings.EqualFold(u.Scheme, "https")
	serverName := u.Hostname()
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, err := base.DialContext(ctx, "tcp", proxyAddr)
		if err != nil {
			return nil, err
		}
		if useTLS {
			tlsConn := tls.Client(conn, &tls.Config{ServerName: serverName, InsecureSkipVerify: true})
			if err := tlsConn.HandshakeContext(ctx); err != nil {
				_ = conn.Close()
				return nil, err
			}
			conn = tlsConn
		}
		_ = conn.SetDeadline(time.Now().Add(timeout))
		req := "CONNECT " + addr + " HTTP/1.1\r\nHost: " + addr + "\r\n" + authHeader + "\r\n"
		if _, err := io.WriteString(conn, req); err != nil {
			_ = conn.Close()
			return nil, err
		}
		br := bufio.NewReader(conn)
		resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
		if err != nil {
			_ = conn.Close()
			return nil, err
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			_ = conn.Close()
			return nil, fmt.Errorf("代理 CONNECT %s 失败: %s", addr, resp.Status)
		}
		_ = conn.SetDeadline(time.Time{})
		return conn, nil
	}
}
