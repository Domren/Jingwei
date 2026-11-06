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
// exists. Other -c settings the caller carried are kept; an existing search_path
// is replaced rather than refused, because a suite that pins once in TestMain and
// hands the pinned DSN back to a per-test helper is doing nothing wrong.
func withSearchPath(baseDSN, schema string) (string, error) {
	pin := "-csearch_path=" + schema
	if u, err := url.Parse(baseDSN); err == nil && (u.Scheme == "postgres" || u.Scheme == "postgresql") {
		q := u.Query()
		var carried []string
		for _, v := range q["options"] {
			carried = append(carried, strings.Fields(v)...)
		}
		q.Del("options")
		q.Set("options", strings.Join(append(dropSearchPath(carried), pin), " "))
		u.RawQuery = q.Encode()
		return u.String(), nil
	}
	// libpq keyword DSN: whitespace-separated key=value. A quoted options value
	// would need a real parser to rewrite, and no caller builds one.
	fields := strings.Fields(baseDSN)
	var carried []string
	kept := make([]string, 0, len(fields))
	for _, f := range fields {
		if strings.HasPrefix(f, "options=") {
			v := strings.TrimPrefix(f, "options=")
			if strings.ContainsAny(v, `"'\\`) {
				return "", fmt.Errorf("DSN 的 options 参数带引号或转义，改写出 search_path：%q", baseDSN)
			}
			carried = append(carried, strings.Fields(v)...)
			continue
		}
		kept = append(kept, f)
	}
	return strings.Join(append(kept, "options="+strings.Join(append(dropSearchPath(carried), pin), " ")), " "), nil
}

// dropSearchPath removes any search_path setting from a list of -c options:
// "-csearch_path=x" and the two-token "-c search_path=x" spellings.
func dropSearchPath(opts []string) []string {
	out := make([]string, 0, len(opts))
	for i := 0; i < len(opts); i++ {
		tok := opts[i]
		if tok == "-c" && i+1 < len(opts) && strings.HasPrefix(opts[i+1], "search_path=") {
			i++
			continue
		}
		if strings.HasPrefix(tok, "-csearch_path=") || tok == "search_path" || strings.HasPrefix(tok, "search_path=") {
			continue
		}
		out = append(out, tok)
	}
	return out
}

// SchemaDSN pins baseDSN's search_path to schema and hands the result back, for
// the callers that cannot use OpenTestSchema because something else opens the
// connection — a production constructor that resolves the DSN from the
// environment. Test binaries use it to keep such constructors on the same
// isolated schema as the rest of the package.
func SchemaDSN(baseDSN, schema string) (string, error) {
	if !testSchemaName.MatchString(schema) {
		return "", fmt.Errorf("非法的测试 schema 名 %q", schema)
	}
	return withSearchPath(baseDSN, schema)
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
