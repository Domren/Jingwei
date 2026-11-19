package server

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Domren/jingwei/db"
)

// 命令历史审计导出的固定列顺序。who/when/where/what 四要素分别对应
// 操作者、时间、主机、命令；多带的会话名/类型/结果便于复核上下文。
var intranetEventExportColumns = []string{
	"时间", "操作者", "主机", "会话", "会话ID", "事件类型", "命令", "失败", "输出",
}

// intranetEventExportRow 把一条事件摊平成导出行。时间用 RFC3339，便于 CSV
// 里按字符串排序与跨系统对照。
func intranetEventExportRow(e *db.IntranetSessionEvent) []string {
	if e == nil {
		return nil
	}
	return []string{
		e.CreatedAt.UTC().Format(time.RFC3339),
		e.Operator,
		e.Host,
		e.SessionName,
		strconv.FormatInt(e.SessionID, 10),
		e.Kind,
		e.Command,
		strconv.FormatBool(e.IsError),
		strings.ReplaceAll(strings.ReplaceAll(e.Output, "\r\n", "\n"), "\n", " "),
	}
}

// renderIntranetEventsCSV 生成带 BOM 的 CSV：中文表头在 Excel 里不乱码，
// 输出中的换行被摊成空格，保证一行一条事件。
func renderIntranetEventsCSV(events []*db.IntranetSessionEvent) []byte {
	var buf bytes.Buffer
	buf.Write([]byte{0xef, 0xbb, 0xbf})
	w := csv.NewWriter(&buf)
	_ = w.Write(intranetEventExportColumns)
	for _, e := range events {
		_ = w.Write(intranetEventExportRow(e))
	}
	w.Flush()
	return buf.Bytes()
}

func renderIntranetEventsJSON(events []*db.IntranetSessionEvent) []byte {
	body, _ := json.MarshalIndent(map[string]any{"events": events, "total": len(events)}, "", "  ")
	return append(body, '\n')
}

// exportIntranetSessionEvents 导出命令审计。format=csv 给表格工具，默认 JSON。
// since 用 RFC3339；limit 上限 5000，避免一次请求拖垮库。
func (s *Server) exportIntranetSessionEvents(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	q := r.URL.Query()
	var since time.Time
	if raw := strings.TrimSpace(q.Get("since")); raw != "" {
		if t, err := time.Parse(time.RFC3339, raw); err == nil {
			since = t
		}
	}
	events, err := pg.ListIntranetSessionEventsForExport(since, atoiDefault(q.Get("limit"), 500))
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if strings.EqualFold(strings.TrimSpace(q.Get("format")), "csv") {
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="intranet-events.csv"`)
		_, _ = w.Write(renderIntranetEventsCSV(events))
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_, _ = w.Write(renderIntranetEventsJSON(events))
}
