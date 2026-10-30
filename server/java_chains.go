package server

import (
	"context"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/Autumn-27/jingwei/db"
	"github.com/Autumn-27/jingwei/scanner"
)

// seedJavaChainsMCP registers the optional java-chains gateway as a Streamable
// HTTP MCP server. The token is minted by the sidecar (deploy/java-chains-setup.sh)
// and passed in through the environment; without it the server is not registered
// and the skill falls back to driving the Web UI.
func seedJavaChainsMCP(pg *db.DB) {
	token := strings.TrimSpace(os.Getenv("JAVA_CHAINS_MCP_TOKEN"))
	if token == "" {
		return
	}
	base := strings.TrimSpace(os.Getenv("JAVA_CHAINS_URL"))
	if base == "" {
		base = "http://java-chains:8011"
	}
	endpoint := strings.TrimRight(base, "/") + "/api/mcp"
	if err := pg.UpsertJavaChainsMCP(endpoint, token); err != nil {
		log.Printf("[mcp] java-chains 注册失败: %v", err)
		return
	}
	log.Printf("[mcp] java-chains 已注册: %s", endpoint)
}

// javaChainsStatus reports whether the optional sidecar is configured and
// currently reachable. It never exposes the API token.
func (s *Server) javaChainsStatus(w http.ResponseWriter, r *http.Request) {
	cfg := scanner.JavaChainsConfigFromEnv()
	out := map[string]any{
		"configured":    cfg.Configured(),
		"url":           cfg.BaseURL,
		"callback_host": cfg.CallbackHost,
		"bind_host":     cfg.BindHost,
		"online":        false,
	}
	if !cfg.Configured() {
		out["error"] = "JAVA_CHAINS_MCP_TOKEN 未配置"
		writeJSON(w, 200, out)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 4*time.Second)
	defer cancel()
	client := scanner.NewJavaChainsClient(cfg, 4*time.Second)
	if err := client.JavaChainsStatus(ctx); err != nil {
		out["error"] = err.Error()
	} else {
		out["online"] = true
	}
	writeJSON(w, 200, out)
}
