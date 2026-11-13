package server

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/Autumn-27/jingwei/db"
	_ "github.com/jackc/pgx/v5/stdlib"
)

// TestMain acquires a PostgreSQL advisory lock (7337741002) for the entire
// server test suite so cross-package DELETE cleanup races with db/agent
// packages are avoided when running `go test ./...`.
//
// db.Open (not a bare sql.Open+Ping) creates the database when it does not
// exist yet; skipping the lock while another package is still creating it would
// let two test binaries write the same tables and deadlock each other. The lock
// stays on one pinned connection because a session-level advisory lock returns
// to PostgreSQL with the session it was taken on.
//
// The isolated schema is only half of the isolation: more than half of this
// package builds its server through NewManager, which resolves the DSN from the
// environment and would otherwise land in `public`, sharing tables with the db
// and agent suites — including four `DELETE FROM authorizations` cleanups that
// would wipe rows another suite is asserting on. JINGWEI_PG_DSN is therefore
// re-exported pinned to the same schema, so both construction paths land on
// jingwei_test_server and the suite lock covers every write this package does.
func TestMain(m *testing.M) {
	dsn, _, err := db.DSN()
	if err != nil {
		os.Exit(m.Run())
	}
	pg, err := db.OpenTestSchema(dsn, "jingwei_test_server")
	if err != nil {
		// A DSN is configured, so these tests write real rows. Running without the
		// isolated schema and without the lock means sharing tables with db/agent —
		// the deadlock this lock exists to keep apart.
		fmt.Fprintf(os.Stderr, "server suite: 打不开隔离 schema，拒绝在共享表上跑：%v\n", err)
		os.Exit(1)
	}
	pinned, err := db.SchemaDSN(dsn, "jingwei_test_server")
	if err != nil {
		_ = pg.Close()
		fmt.Fprintf(os.Stderr, "server suite: 拼不出隔离 schema 的 DSN，拒绝让 NewManager 系用例写共享表：%v\n", err)
		os.Exit(1)
	}
	if err := os.Setenv("JINGWEI_PG_DSN", pinned); err != nil {
		_ = pg.Close()
		fmt.Fprintf(os.Stderr, "server suite: 无法把 DSN 指到隔离 schema：%v\n", err)
		os.Exit(1)
	}
	conn, err := pg.Conn(context.Background())
	if err != nil {
		fmt.Fprintf(os.Stderr, "server suite: 取固定连接失败，拒绝在无锁状态下跑：%v\n", err)
		_ = pg.Close()
		os.Exit(1)
	}
	if _, err := conn.ExecContext(context.Background(), `SELECT pg_advisory_lock(7337741002)`); err != nil {
		fmt.Fprintf(os.Stderr, "server suite: 拿不到套件锁，拒绝与别的包并发写共享表：%v\n", err)
		_ = conn.Close()
		_ = pg.Close()
		os.Exit(1)
	}
	watermark := toolUsageWatermark(pg)
	// 隔离 schema 跨轮次复用，上一轮失败留下的非终态任务会占满并发槽；而测试环境
	// 没有可用的 LLM，reconcileConcurrency 会把每个新任务都停进队列，于是依赖
	// 「任务能开跑」的用例（core 的 goal 播种、归档、深挖、备注）全变成红。
	// 每轮开跑前把残留任务置为暂停并释放队列占位——只动测试 schema，不改产品行为。
	if _, err := pg.Exec(`UPDATE tasks
   SET paused=true, queued=false, queued_at=NULL, queue_mode=''
 WHERE status NOT IN ('done','failed','timeout','budget')`); err != nil {
		fmt.Fprintf(os.Stderr, "server suite: reset leftover tasks: %v\n", err)
		_ = conn.Close()
		_ = pg.Close()
		os.Exit(1)
	}
	// 并发开关同样会被上一轮用例改脏（有测试 SetConcurrency(true,1) 后中途失败没还原）。
	// 测试环境没有可用 LLM，一旦并发开=true，reconcileConcurrency 会把每个新建任务
	// 停进队列（queued=true），归档/深挖/备注/goal 播种全部失败。这里统一复位为关；
	// 需要验证并发行为的用例（task_admission_test 等）自己会显式打开并在 defer 里还原。
	if err := pg.SetSetting(settingConcurrencyOn, "false"); err != nil {
		fmt.Fprintf(os.Stderr, "server suite: reset concurrency setting: %v\n", err)
		_ = conn.Close()
		_ = pg.Close()
		os.Exit(1)
	}
	code := m.Run()
	reapToolUsage(pg, watermark)
	// os.Exit skips deferred calls, so the lock and pool are released explicitly:
	// closing the pinned connection is what ends the session holding the lock.
	if _, err := conn.ExecContext(context.Background(), `SELECT pg_advisory_unlock(7337741002)`); err != nil {
		fmt.Fprintf(os.Stderr, "server suite: release advisory lock: %v\n", err)
	}
	_ = conn.Close()
	_ = pg.Close()
	os.Exit(code)
}

// toolUsageWatermark returns the highest tool_usage id when the suite starts.
func toolUsageWatermark(pg *db.DB) int64 {
	var id int64
	if err := pg.QueryRow(`SELECT COALESCE(max(id), 0) FROM tool_usage`).Scan(&id); err != nil {
		fmt.Fprintf(os.Stderr, "server suite: read tool usage watermark: %v\n", err)
		return -1
	}
	return id
}

// reapToolUsage deletes the metering rows the suite added. tool_usage carries no
// foreign key by design — statistics outlive their task — and the tools invoked
// here are attributed to no task at all, so the id watermark is the only handle
// on them and nothing else would ever remove them.
func reapToolUsage(pg *db.DB, since int64) {
	if since < 0 {
		return
	}
	if _, err := pg.Exec(`DELETE FROM tool_usage WHERE id > $1`, since); err != nil {
		fmt.Fprintf(os.Stderr, "server suite: reap tool usage: %v\n", err)
	}
}
