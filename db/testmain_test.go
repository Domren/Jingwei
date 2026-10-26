package db

import (
	"context"
	"fmt"
	"os"
	"testing"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// TestMain acquires a PostgreSQL advisory lock (7337741002) for the entire
// db test suite. Packages agent, evidence and server hold the same lock, so
// parallel `go test ./...` runs serialize across packages on the shared dev DB
// and avoid cross-package cleanup races (e.g. DELETE FROM assets WHERE id > X
// from one package deleting assets created by another).
//
// Open (not a bare sql.Open+Ping) is deliberate: it creates the database when
// it does not exist yet. Skipping the lock because the target DB is still being
// created by another package would let two test binaries write the same tables
// and deadlock each other. The lock is held on one pinned connection, since a
// session-level advisory lock handed back to the pool can be dropped with the
// session.
func TestMain(m *testing.M) {
	dsn, _, err := DSN()
	if err != nil {
		// No DB configured — tests that need PG will skip themselves.
		os.Exit(m.Run())
	}
	pg, err := Open(dsn)
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
		fmt.Fprintf(os.Stderr, "db suite: release advisory lock: %v\n", err)
	}
	_ = conn.Close()
	_ = pg.Close()
	os.Exit(code)
}
