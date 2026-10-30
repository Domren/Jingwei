// Command pocimport copies nuclei templates from the legacy Jingwei pocs table
// into the new poc_templates library. It is a one-off migration helper:
//
//	OLD_PG_DSN='postgres://postgres:123456@127.0.0.1:5433/jingwei?sslmode=disable' \
//	NEW_PG_DSN='postgres://jingwei:***@127.0.0.1:55432/jingwei?sslmode=disable' \
//	go run ./cmd/pocimport
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/Autumn-27/jingwei/pocparse"
	_ "github.com/jackc/pgx/v5/stdlib"
)

type legacyRow struct {
	ID          string
	Name        string
	Severity    string
	CVEID       string
	Description string
	Source      string
	SourceURL   string
	Content     string
	Active      int
}

func main() {
	oldDSN := strings.TrimSpace(os.Getenv("OLD_PG_DSN"))
	newDSN := strings.TrimSpace(os.Getenv("NEW_PG_DSN"))
	if oldDSN == "" || newDSN == "" {
		log.Fatal("请设置 OLD_PG_DSN 与 NEW_PG_DSN")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	oldDB, err := sql.Open("pgx", oldDSN)
	if err != nil {
		log.Fatalf("连接旧库失败: %v", err)
	}
	defer oldDB.Close()
	newDB, err := sql.Open("pgx", newDSN)
	if err != nil {
		log.Fatalf("连接新库失败: %v", err)
	}
	defer newDB.Close()
	if err := oldDB.PingContext(ctx); err != nil {
		log.Fatalf("旧库不可用: %v", err)
	}
	if err := newDB.PingContext(ctx); err != nil {
		log.Fatalf("新库不可用: %v", err)
	}

	rows, err := oldDB.QueryContext(ctx, `
SELECT id, name, COALESCE(severity,''), COALESCE(cve_id,''), COALESCE(description,''),
       COALESCE(source,''), COALESCE(source_url,''), content, COALESCE(is_active,1)
FROM pocs
ORDER BY id`)
	if err != nil {
		log.Fatalf("读取旧模板失败: %v", err)
	}
	defer rows.Close()

	tx, err := newDB.BeginTx(ctx, nil)
	if err != nil {
		log.Fatalf("开启事务失败: %v", err)
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, `
INSERT INTO poc_templates(template_id,name,severity,protocol,cve_id,cwe_id,cvss_score,tags,author,
                          description,refs,source,source_url,content,digest,enabled)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9,$10,$11::jsonb,$12,$13,$14,$15,$16)
ON CONFLICT (template_id) DO NOTHING`)
	if err != nil {
		log.Fatalf("准备写入语句失败: %v", err)
	}
	defer stmt.Close()

	var read, inserted, duplicate, parseFailed int
	for rows.Next() {
		var row legacyRow
		if err := rows.Scan(&row.ID, &row.Name, &row.Severity, &row.CVEID, &row.Description,
			&row.Source, &row.SourceURL, &row.Content, &row.Active); err != nil {
			log.Fatalf("扫描旧行失败: %v", err)
		}
		read++
		tpl, err := pocparse.Parse([]byte(row.Content), row.ID)
		if err != nil {
			parseFailed++
			if parseFailed <= 10 {
				log.Printf("跳过无法解析的模板 id=%s name=%q: %v", row.ID, row.Name, err)
			}
			continue
		}
		tags, _ := json.Marshal(tpl.Tags)
		refs, _ := json.Marshal(tpl.References)
		enabled := row.Active != 0
		res, err := stmt.ExecContext(ctx, tpl.TemplateID, tpl.Name, tpl.Severity, tpl.Protocol,
			tpl.CVEID, tpl.CWEID, tpl.CVSSScore, string(tags), tpl.Author, tpl.Description,
			string(refs), "jingwei-import", row.SourceURL, tpl.Content, tpl.Digest, enabled)
		if err != nil {
			log.Fatalf("写入模板 %s 失败: %v", tpl.TemplateID, err)
		}
		if n, _ := res.RowsAffected(); n == 0 {
			duplicate++
		} else {
			inserted++
		}
		if read%1000 == 0 {
			log.Printf("已读取 %d 条，写入 %d，重复跳过 %d，解析失败 %d", read, inserted, duplicate, parseFailed)
		}
	}
	if err := rows.Err(); err != nil {
		log.Fatalf("遍历旧模板失败: %v", err)
	}
	if err := tx.Commit(); err != nil {
		log.Fatalf("提交失败: %v", err)
	}
	fmt.Printf("完成：读取 %d，写入 %d，重复跳过 %d，解析失败 %d\n", read, inserted, duplicate, parseFailed)
}
