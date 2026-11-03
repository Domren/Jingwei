package db

import (
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	_ "github.com/jackc/pgx/v5/stdlib" // pgx database/sql driver ("pgx")
)

// testSchemaName allows the identifiers OpenTestSchema may interpolate. Schema
// names cannot be parameterised in DDL, so this is the check that keeps a test
// helper from becoming a way to run arbitrary SQL.
var testSchemaName = regexp.MustCompile(`^[a-z][a-z0-9_]{2,62}$`)

// withSearchPath pins the connection's search_path to schema, in whichever DSN
// dialect the caller used. libpq DSNs take a trailing " options=..." parameter;
// a URI's parameters live in the query string, where a space-separated suffix
// would be read as one more sslmode value — appending " options=..." to
// "postgres://…?sslmode=disable" produced "failed to configure TLS (sslmode is
// invalid)" for every test in the isolated packages, which is how this function
// exists. Merging rather than replacing any existing options keeps a caller's own
// -c settings alive.
func withSearchPath(baseDSN, schema string) (string, error) {
	if u, err := url.Parse(baseDSN); err == nil && (u.Scheme == "postgres" || u.Scheme == "postgresql") {
		q := u.Query()
		opts := strings.Fields(q.Get("options"))
		q.Set("options", strings.Join(append(opts, "-csearch_path="+schema), " "))
		u.RawQuery = q.Encode()
		return u.String(), nil
	}
	if strings.Contains(baseDSN, "options=") {
		return "", fmt.Errorf("DSN 已带 options 参数，无法安全追加 search_path：%q", baseDSN)
	}
	return baseDSN + " options=-csearch_path=" + schema, nil
}

// OpenTestSchema opens the test database with every table inside its own schema.
// Packages under `go test ./...` run in parallel against one database, and sharing
// tables meant one package's cleanup deleted rows another was asserting on. The
// connection pins search_path, so the unqualified DDL in schema.sql lands in that
// schema and each package gets an isolated, fully seeded copy.
func OpenTestSchema(baseDSN, schema string) (*DB, error) {
	if baseDSN == "" {
		return nil, errors.New("需要测试库 DSN")
	}
	if !testSchemaName.MatchString(schema) {
		return nil, fmt.Errorf("非法的测试 schema 名 %q", schema)
	}
	pinned, err := withSearchPath(baseDSN, schema)
	if err != nil {
		return nil, err
	}
	raw, err := sql.Open("pgx", baseDSN)
	if err != nil {
		return nil, err
	}
	if _, err := raw.Exec(`CREATE SCHEMA IF NOT EXISTS ` + schema); err != nil {
		_ = raw.Close()
		return nil, err
	}
	if err := raw.Close(); err != nil {
		return nil, err
	}
	return Open(pinned)
}
