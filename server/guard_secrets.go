package server

import (
	"os"
	"strings"

	pgdb "github.com/Autumn-27/artex/db"
)

// refreshGuardSecrets (re)registers platform secret fingerprints on the
// process-wide egress guard. Only SHA-256 digests are stored; plaintext is
// never copied out of this function and never logged. Safe to call on every
// config change (adds are idempotent; dynamic kinds are replaced wholesale).
func (s *Server) refreshGuardSecrets() {
	if s == nil || s.m == nil || s.m.egress == nil {
		return
	}
	eg := s.m.egress

	if len(s.jwtKey) > 0 {
		eg.AddFingerprint("platform-jwt-key", string(s.jwtKey))
	}
	if dsn, _, err := pgdb.DSN(); err == nil {
		eg.AddFingerprint("pg-dsn", dsn)
		for _, pw := range dsnSecrets(dsn) {
			eg.AddFingerprint("pg-password", pw)
		}
	}

	// LLM keys: every stored profile (not just the active one) plus env-injected
	// credentials. Rebuild from scratch so removed/rotated keys disappear.
	eg.RemoveKind("llm-api-key")
	if s.m.pg != nil {
		if keys, err := s.m.pg.ProfileAPIKeys(); err == nil {
			for _, k := range keys {
				if k = strings.TrimSpace(k); k != "" {
					eg.AddFingerprint("llm-api-key", k)
				}
			}
		}
	}
	for _, env := range []string{"ANTHROPIC_API_KEY", "OPENAI_API_KEY"} {
		if v := strings.TrimSpace(os.Getenv(env)); v != "" {
			eg.AddFingerprint("llm-api-key", v)
		}
	}

	eg.RemoveKind("web-search-key")
	_, _, brave, tavily, _ := s.m.WebSearch()
	for _, k := range []string{brave, tavily} {
		if k = strings.TrimSpace(k); k != "" {
			eg.AddFingerprint("web-search-key", k)
		}
	}

	eg.RemoveKind("java-chains")
	for _, env := range []string{"JAVA_CHAINS_MCP_TOKEN", "JAVA_CHAINS_PASS"} {
		if v := strings.TrimSpace(os.Getenv(env)); v != "" {
			eg.AddFingerprint("java-chains", v)
		}
	}
}
