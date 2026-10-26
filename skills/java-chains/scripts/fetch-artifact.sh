#!/usr/bin/env bash
# 下载 java-chains MCP 生成的 artifact（payload 字节）。
# 用法：fetch-artifact.sh <artifactId> [输出路径]
# 依赖容器环境变量 JAVA_CHAINS_URL、JAVA_CHAINS_MCP_TOKEN。
set -euo pipefail

id="${1:?用法: fetch-artifact.sh <artifactId> [输出路径]}"
out="${2:-/tmp/java-chains-${id}.bin}"
base="${JAVA_CHAINS_URL:-http://java-chains:8011}"
token="${JAVA_CHAINS_MCP_TOKEN:?JAVA_CHAINS_MCP_TOKEN 未配置}"

case "$id" in
  art_*) ;;
  *) echo "artifactId 应以 art_ 开头: $id" >&2; exit 1 ;;
esac

umask 077
curl -fsS --max-time 60 -H "X-Api-Token: $token" \
  "${base%/}/api/mcp/artifacts/${id}" -o "$out"
printf '%s\n' "$out"
