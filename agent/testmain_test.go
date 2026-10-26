package agent

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/Autumn-27/artex/db"
	_ "github.com/jackc/pgx/v5/stdlib"
)

// TestMain acquires a PostgreSQL advisory lock (7337741002) for the entire
// agent test suite so cross-package DELETE cleanup races with db/server
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
