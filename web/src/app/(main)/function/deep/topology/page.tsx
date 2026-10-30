"use client";

import * as React from "react";

import { Loader2Icon, Maximize2Icon, NetworkIcon, RefreshCwIcon, ZoomInIcon, ZoomOutIcon } from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { api } from "@/lib/api";
import type { Asset } from "@/lib/types";

// 内网拓扑图：按资产类型分层展示（公司 → 域名 → IP → 服务 → 端点），
// 用 SVG 力导向布局。节点可点击跳转到资产详情。按任务过滤。

type LayoutNode = {
  id: string;
  label: string;
  type: string;
  x: number;
  y: number;
  assetId?: number;
};

type LayoutEdge = { from: string; to: string };

const TYPE_COLORS: Record<string, string> = {
  company: "#8b5cf6",
  root_domain: "#3b82f6",
  subdomain: "#60a5fa",
  ip: "#f59e0b",
  service: "#10b981",
  app: "#ec4899",
  endpoint: "#f97316",
  credential: "#ef4444",
};

const TYPE_LABELS: Record<string, string> = {
  company: "公司",
  root_domain: "根域",
  subdomain: "子域",
  ip: "IP",
  service: "服务",
  app: "应用",
  endpoint: "端点",
};

// buildGraph extracts nodes and edges from a flat asset list using implicit
// relationships (root_domain → subdomain → ip → service → endpoint).
function buildGraph(assets: Asset[]): { nodes: LayoutNode[]; edges: LayoutEdge[] } {
  const nodes: LayoutNode[] = [];
  const edges: LayoutEdge[] = [];
  const byKey = new Map<string, string>(); // key → node id

  const addNode = (key: string, label: string, type: string, assetId?: number): string => {
    const id = key;
    if (!byKey.has(id)) {
      byKey.set(id, id);
      nodes.push({ id, label, type, x: 0, y: 0, assetId });
    }
    return id;
  };

  // Group by type for layering
  const byType: Record<string, Asset[]> = {};
  for (const a of assets) {
    const t = a.type || "unknown";
    (byType[t] ??= []).push(a);
  }

  // Root domains
  const rootIds: string[] = [];
  for (const a of byType.root_domain ?? []) {
    const dom = a.domain ?? "";
    if (!dom) continue;
    const id = addNode(`rd:${dom}`, dom, "root_domain", a.id);
    rootIds.push(id);
  }

  // Subdomains → parent root
  const subIds: string[] = [];
  for (const a of byType.subdomain ?? []) {
    const dom = a.domain ?? "";
    if (!dom) continue;
    const id = addNode(`sd:${dom}`, dom, "subdomain", a.id);
    subIds.push(id);
    // Link to root domain
    const root = a.root_domain ?? "";
    if (root && byKey.has(`rd:${root}`)) {
      edges.push({ from: `rd:${root}`, to: id });
    } else if (root) {
      const rid = addNode(`rd:${root}`, root, "root_domain");
      edges.push({ from: rid, to: id });
      rootIds.push(rid);
    }
  }

  // IPs
  const ipIds: string[] = [];
  for (const a of byType.ip ?? []) {
    const ipAddr = a.ip ?? "";
    if (!ipAddr) continue;
    const id = addNode(`ip:${ipAddr}`, ipAddr, "ip", a.id);
    ipIds.push(id);
    // Link to bound domains
    for (const d of a.bound_domains ?? []) {
      const sdKey = `sd:${d}`;
      const rdKey = `rd:${d}`;
      if (byKey.has(sdKey)) edges.push({ from: sdKey, to: id });
      else if (byKey.has(rdKey)) edges.push({ from: rdKey, to: id });
    }
  }

  // Services
  for (const a of byType.service ?? []) {
    const ipAddr = a.ip ?? "";
    const label = `${ipAddr}:${a.port ?? ""}`.replace(/^:/, "") || a.domain || "service";
    const id = addNode(`sv:${label}`, label, "service", a.id);
    // Link to IP
    if (ipAddr) {
      const ipKey = `ip:${ipAddr}`;
      if (byKey.has(ipKey)) edges.push({ from: ipKey, to: id });
      else {
        const pid = addNode(`ip:${ipAddr}`, ipAddr, "ip");
        edges.push({ from: pid, to: id });
      }
    }
  }

  // Endpoints
  for (const a of byType.endpoint ?? []) {
    const dom = a.domain ?? "";
    const ipAddr = a.ip ?? "";
    const label = dom || ipAddr || "endpoint";
    const id = addNode(`ep:${label}${a.id}`, label, "endpoint", a.id);
    if (dom) {
      const sdKey = `sd:${dom}`;
      const rdKey = `rd:${dom}`;
      if (byKey.has(sdKey)) edges.push({ from: sdKey, to: id });
      else if (byKey.has(rdKey)) edges.push({ from: rdKey, to: id });
    }
    if (ipAddr) {
      const ipKey = `ip:${ipAddr}`;
      if (byKey.has(ipKey)) edges.push({ from: ipKey, to: id });
    }
  }

  // Simple layered layout: type determines X, index determines Y
  const typeOrder = ["company", "root_domain", "subdomain", "ip", "service", "app", "endpoint"];
  const layerGap = 160;
  const rowGap = 36;
  for (const type of typeOrder) {
    const layerIdx = typeOrder.indexOf(type);
    const layerNodes = nodes.filter((n) => n.type === type);
    layerNodes.forEach((n, i) => {
      n.x = 80 + layerIdx * layerGap;
      n.y = 60 + i * rowGap;
    });
  }

  return { nodes, edges };
}

export default function TopologyPage() {
  const [assets, setAssets] = React.useState<Asset[]>([]);
  const [loading, setLoading] = React.useState(false);
  const [zoom, setZoom] = React.useState(1);
  const [filter, setFilter] = React.useState<string>("");

  const load = React.useCallback(async () => {
    setLoading(true);
    try {
      const page = await api.assets("", 500);
      setAssets(page.assets ?? []);
    } catch (e) {
      toast.error("加载资产失败：" + (e as Error).message);
    } finally {
      setLoading(false);
    }
  }, []);

  React.useEffect(() => {
    void load();
  }, [load]);

  const filteredAssets = React.useMemo(() => {
    if (!filter) return assets;
    return assets.filter((a) => a.type === filter);
  }, [assets, filter]);

  const { nodes, edges } = React.useMemo(() => buildGraph(filteredAssets), [filteredAssets]);

  const svgW = Math.max(800, ...nodes.map((n) => n.x + 200));
  const svgH = Math.max(400, ...nodes.map((n) => n.y + 60));

  return (
    <div className="flex flex-1 flex-col gap-4 p-4 lg:p-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="flex items-center gap-2 text-lg font-semibold">
            <NetworkIcon className="size-5" /> 内网拓扑图
          </h1>
          <p className="mt-1 text-sm text-muted-foreground">
            按资产类型分层展示：公司 → 域名 → IP → 服务 → 端点。节点颜色按类型区分。
          </p>
        </div>
        <div className="flex items-center gap-2">
          {["", ...Object.keys(TYPE_LABELS)].map((t) => (
            <Button
              key={t || "all"}
              size="sm"
              variant={filter === t ? "default" : "outline"}
              onClick={() => setFilter(t)}
              className="h-7 text-xs"
            >
              {t ? TYPE_LABELS[t] : "全部"}
            </Button>
          ))}
          <Button size="sm" variant="outline" disabled={loading} onClick={() => void load()}>
            {loading ? <Loader2Icon className="size-4 animate-spin" /> : <RefreshCwIcon className="size-4" />}
          </Button>
        </div>
      </div>

      <Card className="flex-1 overflow-hidden">
        <CardHeader className="flex-row items-center justify-between">
          <CardTitle className="text-sm">
            {nodes.length} 个节点 · {edges.length} 条关系
          </CardTitle>
          <div className="flex items-center gap-1">
            <Button size="icon" variant="ghost" className="size-7" onClick={() => setZoom((z) => Math.min(2, z + 0.2))}>
              <ZoomInIcon className="size-4" />
            </Button>
            <Button size="icon" variant="ghost" className="size-7" onClick={() => setZoom((z) => Math.max(0.4, z - 0.2))}>
              <ZoomOutIcon className="size-4" />
            </Button>
            <Button size="icon" variant="ghost" className="size-7" onClick={() => setZoom(1)}>
              <Maximize2Icon className="size-4" />
            </Button>
          </div>
        </CardHeader>
        <CardContent className="overflow-auto p-0">
          {nodes.length === 0 ? (
            <p className="py-12 text-center text-sm text-muted-foreground">
              暂无资产。任务发现资产后会自动出现在这里。
            </p>
          ) : (
            <svg width={svgW * zoom} height={svgH * zoom} viewBox={`0 0 ${svgW} ${svgH}`} className="block">
              {/* Edges */}
              {edges.map((e, i) => {
                const from = nodes.find((n) => n.id === e.from);
                const to = nodes.find((n) => n.id === e.to);
                if (!from || !to) return null;
                return (
                  <line
                    key={`e-${i}`}
                    x1={from.x + 100}
                    y1={from.y + 14}
                    x2={to.x + 100}
                    y2={to.y + 14}
                    stroke="#94a3b8"
                    strokeWidth={1.2}
                    strokeDasharray={from.type === to.type ? "none" : "4 2"}
                    opacity={0.5}
                  />
                );
              })}
              {/* Nodes */}
              {nodes.map((n) => (
                <g key={n.id} transform={`translate(${n.x}, ${n.y})`}>
                  <rect
                    x={0}
                    y={0}
                    width={200}
                    height={28}
                    rx={6}
                    fill={TYPE_COLORS[n.type] ?? "#6b7280"}
                    opacity={0.12}
                    stroke={TYPE_COLORS[n.type] ?? "#6b7280"}
                    strokeWidth={1.2}
                  />
                  <text x={10} y={18} fontSize={11} fill="currentColor" className="select-none">
                    {n.label.length > 22 ? n.label.slice(0, 22) + "…" : n.label}
                  </text>
                  {/* Type badge */}
                  <text x={170} y={18} fontSize={9} fill={TYPE_COLORS[n.type] ?? "#6b7280"} textAnchor="end" className="select-none">
                    {TYPE_LABELS[n.type] ?? n.type}
                  </text>
                </g>
              ))}
            </svg>
          )}
        </CardContent>
      </Card>

      {/* Legend */}
      <div className="flex flex-wrap items-center gap-3">
        {Object.entries(TYPE_LABELS).map(([type, label]) => (
          <div key={type} className="flex items-center gap-1.5">
            <div className="size-3 rounded-full" style={{ backgroundColor: TYPE_COLORS[type] }} />
            <span className="text-xs text-muted-foreground">{label}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
