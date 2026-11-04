package server

import (
	"database/sql"
	"testing"

	"github.com/Autumn-27/jingwei/db"
	"github.com/Autumn-27/jingwei/guard"
)

func TestGuardTargetPolicyFailsClosedWithoutDatabase(t *testing.T) {
	policy := newGuardTargetPolicy(nil)
	verdict, reason := policy.Check(1, []string{"http://example.test"}, []string{"example.test"})
	if verdict != guard.ScopeOut || reason == "" {
		t.Fatalf("missing policy database: %v, %q", verdict, reason)
	}
}

func TestGuardTargetPolicyFailsClosedOnDatabaseErrors(t *testing.T) {
	pool, err := sql.Open("pgx", "postgres://127.0.0.1:1/unavailable?sslmode=disable&connect_timeout=1")
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	policy := newGuardTargetPolicy(&db.DB{DB: pool})
	verdict, reason := policy.Check(1, nil, []string{"example.test"})
	if verdict != guard.ScopeOut || reason == "" {
		t.Fatalf("unreadable policy database: %v, %q", verdict, reason)
	}
}
