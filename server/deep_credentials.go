package server

import (
	"net/http"

	pgdb "github.com/Autumn-27/jingwei/db"
)

// listGlobalCredentials returns all credential intelligence across every task.
// 凭据库：内网渗透时经常要拿一个密码打多个服务，需要全局视图而不是散在各任务里。
func (s *Server) listGlobalCredentials(w http.ResponseWriter, r *http.Request) {
	f := pgdb.IntelligenceFilter{
		Kind:   "credential",
		Limit:  200,
		Offset: 0,
	}
	// TaskID=0 + AssetID=0 → 不限任务，列出全部
	page, err := s.m.pg.ListIntelligence(r.Context(), f)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, page)
}
