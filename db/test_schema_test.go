package db

import (
	"net/url"
	"strings"
	"testing"
)

// TestWithSearchPathKeepsBothDSNDialectsParsable guards the shape of the DSN
// OpenTestSchema hands to the driver. A URI DSN already carries its parameters in
// the query string, so the naive " …?sslmode=disable options=…" concatenation is
// read as a second sslmode value and every test in the isolated package dies with
// "failed to configure TLS (sslmode is invalid)" — and because TestMain treats an
// unusable handle as "no database", the package then ran unprotected against the
// shared tables and deadlocked the db suite.
func TestWithSearchPathKeepsBothDSNDialectsParsable(t *testing.T) {
	const schema = "jingwei_test_server"

	uriDSN, err := withSearchPath("postgres://u:p@127.0.0.1:55433/jingwei_gotest?sslmode=disable", schema)
	if err != nil {
		t.Fatalf("URI DSN: %v", err)
	}
	u, err := url.Parse(uriDSN)
	if err != nil {
		t.Fatalf("URI DSN 解析不了 %q: %v", uriDSN, err)
	}
	if got := u.Query().Get("options"); got != "-csearch_path="+schema {
		t.Fatalf("URI DSN 的 options = %q，期望 -csearch_path=%s", got, schema)
	}
	if got := u.Query().Get("sslmode"); got != "disable" {
		t.Fatalf("URI DSN 丢了 sslmode：%q", uriDSN)
	}
	if strings.Contains(uriDSN, " ") {
		t.Fatalf("URI DSN 里还有裸空格，会被当成多写一个参数：%q", uriDSN)
	}

	libpqDSN, err := withSearchPath("host=127.0.0.1 port=55433 user=u password=p dbname=jingwei_gotest sslmode=disable", schema)
	if err != nil {
		t.Fatalf("libpq DSN: %v", err)
	}
	if !strings.HasSuffix(libpqDSN, " options=-csearch_path="+schema) {
		t.Fatalf("libpq DSN 末尾不对：%q", libpqDSN)
	}

	// An existing options value must survive and must not be doubled up.
	merged, err := withSearchPath("postgres://u:p@h/db?options=-cstatement_timeout%3D3000", schema)
	if err != nil {
		t.Fatalf("带 options 的 URI DSN: %v", err)
	}
	u, err = url.Parse(merged)
	if err != nil {
		t.Fatalf("带 options 的 URI DSN 解析不了 %q: %v", merged, err)
	}
	if got := u.Query().Get("options"); got != "-cstatement_timeout=3000 -csearch_path="+schema {
		t.Fatalf("合并后的 options = %q", got)
	}

	libpqMerged, err := withSearchPath("host=h options=-cfoo=1", schema)
	if err != nil {
		t.Fatalf("libpq DSN 已有 options 时应当合并，不该拒绝: %v", err)
	}
	if libpqMerged != "host=h options=-cfoo=1 -csearch_path="+schema {
		t.Fatalf("libpq DSN 合并结果 = %q", libpqMerged)
	}
	if n := strings.Count(libpqMerged, "options="); n != 1 {
		t.Fatalf("libpq DSN 出现了 %d 个 options 参数：%q", n, libpqMerged)
	}

	// Re-pinning is the shape a suite hits when TestMain pins JINGWEI_PG_DSN and a
	// per-test helper pins the same DSN again: the old search_path must be dropped,
	// not appended after, or the last one silently wins for some spellings and the
	// helper reads a schema nobody created.
	for _, dsn := range []string{
		"host=h options=-csearch_path=other_schema",
		"host=h options='-c quoted'", // 带引号的值改不动，必须拒绝而不是拼坏
	} {
		got, err := withSearchPath(dsn, schema)
		if strings.Contains(dsn, "'") {
			if err == nil {
				t.Fatalf("带引号的 options 值应当拒绝改写，得到 %q", got)
			}
			continue
		}
		if err != nil {
			t.Fatalf("重写 search_path: %v", err)
		}
		if got != "host=h options=-csearch_path="+schema {
			t.Fatalf("重写后的 DSN 还留着旧 schema：%q", got)
		}
	}
}
