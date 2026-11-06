package server

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/Autumn-27/jingwei/db"
)

// 客户授权清单（F4）。规则语法与范围匹配保持最小一致：
//   - CIDR（10.0.0.0/8）与裸 IP：按网络/地址匹配；
//   - 域名：精确匹配，或以点开头的后缀（.corp.com 只匹配子域）；
//   - 裸域名 corp.com 同时匹配自身与 *.corp.com——客户的授权清单通常就这么写。
//
// 排除项优先于包含项：命中任一条排除即视为该授权不覆盖这个目标。

func authorizationRuleMatches(pattern, host string) bool {
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	host = strings.ToLower(strings.TrimSpace(host))
	if pattern == "" || host == "" {
		return false
	}
	if _, _, err := net.ParseCIDR(pattern); err == nil {
		_, ipnet, _ := net.ParseCIDR(pattern)
		if ip := net.ParseIP(host); ip != nil {
			return ipnet.Contains(ip)
		}
		return false
	}
	if ip := net.ParseIP(pattern); ip != nil {
		return host == pattern
	}
	if strings.HasPrefix(pattern, ".") {
		return strings.HasSuffix(host, pattern)
	}
	return host == pattern || strings.HasSuffix(host, "."+pattern)
}

// authorizationAllows 报告 host 是否落在某条有效授权内（且不被其排除）。
func authorizationAllows(auths []*db.Authorization, host string) bool {
	for _, a := range auths {
		excluded := false
		for _, ex := range a.Exclusions {
			if authorizationRuleMatches(ex, host) {
				excluded = true
				break
			}
		}
		if excluded {
			continue
		}
		for _, target := range a.Targets {
			if authorizationRuleMatches(target, host) {
				return true
			}
		}
	}
	return false
}

// authorizationSummary 给拒绝原因用：列出有效授权的名字与时间窗。
func authorizationSummary(auths []*db.Authorization) string {
	parts := make([]string, 0, len(auths))
	for _, a := range auths {
		window := "长期"
		if a.EndsAt != nil {
			window = "至 " + a.EndsAt.Format("2006-01-02")
		}
		parts = append(parts, fmt.Sprintf("%s（%s）", a.Name, window))
	}
	if len(parts) > 6 {
		parts = append(parts[:6], "…")
	}
	return strings.Join(parts, "、")
}

// ---- HTTP ----------------------------------------------------------------

func (s *Server) listAuthorizations(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	list, err := pg.ListAuthorizations(atoiDefault(r.URL.Query().Get("limit"), 200))
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"authorizations": list})
}

func (s *Server) createAuthorization(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req struct {
		Name       string   `json:"name"`
		Targets    []string `json:"targets"`
		Exclusions []string `json:"exclusions"`
		StartsAt   string   `json:"starts_at"`
		EndsAt     string   `json:"ends_at"`
		Enabled    *bool    `json:"enabled"`
		Note       string   `json:"note"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "请求格式错误")
		return
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	in := db.AuthorizationInput{Name: req.Name, Targets: req.Targets, Exclusions: req.Exclusions,
		Enabled: enabled, Note: req.Note}
	parse := func(v string) (*time.Time, error) {
		v = strings.TrimSpace(v)
		if v == "" {
			return nil, nil
		}
		t, err := time.Parse("2006-01-02", v)
		if err != nil {
			return nil, errors.New("时间格式应为 YYYY-MM-DD：" + v)
		}
		return &t, nil
	}
	var err error
	if in.StartsAt, err = parse(req.StartsAt); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if in.EndsAt, err = parse(req.EndsAt); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	authz, err := pg.CreateAuthorization(in)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	s.invalidateGuardAuthorizations()
	writeJSON(w, 200, authz)
}

func (s *Server) deleteAuthorization(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, 400, "授权编号无效")
		return
	}
	okDel, err := pg.DeleteAuthorization(id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if !okDel {
		writeErr(w, 404, "授权不存在")
		return
	}
	s.invalidateGuardAuthorizations()
	writeJSON(w, 200, map[string]any{"deleted": true})
}
