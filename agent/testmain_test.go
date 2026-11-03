package agent

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/Autumn-27/jingwei/db"
	_ "github.com/jackc/pgx/v5/stdlib"
)

// TestMain acquires a PostgreSQL advisory lock (7337741002) for the entire
// agent test suite so cross-package DELETE cleanup races with db/server
// packages are avoided when running `go test ./...`.
//
// db.OpenTestSchema (not a bare sql.Open+Ping) creates the schema and applies the
// schema.sql DDL; if a DSN is configured but the suite cannot get its isolated
// schema or the lock, the run aborts instead of falling back to the shared tables
// the lock exists to keep apart. The lock stays on one pinned connection because a
// session-level advisory lock returns to PostgreSQL with the session it was taken on.
func TestMain(m *testing.M) {
	dsn, _, err := db.DSN()
	if err != nil {
		os.Exit(m.Run())
	}
	pg, err := db.OpenTestSchema(dsn, "jingwei_test_agent")
	if err != nil {
		// The DSN is configured, so these tests would write real rows. Running
		// without the isolated schema and without the lock means sharing tables
		// with the other packages — the deadlock this lock exists to prevent.
		fmt.Fprintf(os.Stderr, "agent suite: 打不开隔离 schema，拒绝在共享表上跑：%v\n", err)
		os.Exit(1)
	}
	conn, err := pg.Conn(context.Background())
	if err != nil {
		fmt.Fprintf(os.Stderr, "agent suite: 取固定连接失败，拒绝在无锁状态下跑：%v\n", err)
		_ = pg.Close()
		os.Exit(1)
	}
	if _, err := conn.ExecContext(context.Background(), `SELECT pg_advisory_lock(7337741002)`); err != nil {
		fmt.Fprintf(os.Stderr, "agent suite: 拿不到套件锁，拒绝与别的包并发写共享表：%v\n", err)
		_ = conn.Close()
		_ = pg.Close()
		os.Exit(1)
	}
	code := m.Run()
	// os.Exit skips deferred calls, so the lock and pool are released explicitly:
	// closing the pinned connection is what ends the session holding the lock.
	if _, err := conn.ExecContext(context.Background(), `SELECT pg_advisory_unlock(7337741002)`); err != nil {
		fmt.Fprintf(os.Stderr, "agent suite: release advisory lock: %v\n", err)
	}
	_ = conn.Close()
	_ = pg.Close()
	os.Exit(code)
}
