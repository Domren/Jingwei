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
func TestMain(m *testing.M) {
	dsn, _, err := db.DSN()
	if err != nil {
		os.Exit(m.Run())
	}
	pg, err := db.Open(dsn)
	if err != nil {
		os.Exit(m.Run())
	}
	conn, err := pg.Conn(context.Background())
	if err != nil {
		_ = pg.Close()
		os.Exit(m.Run())
	}
	if _, err := conn.ExecContext(context.Background(), `SELECT pg_advisory_lock(7337741002)`); err != nil {
		_ = conn.Close()
		_ = pg.Close()
		os.Exit(m.Run())
	}
	watermark := toolUsageWatermark(pg)
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
