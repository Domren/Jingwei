"use client";

import * as React from "react";

import { Loader2Icon, NetworkIcon, RefreshCwIcon, ServerCogIcon, ShieldCheckIcon } from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { api } from "@/lib/api";
import type { ManagedResource, PortAuditResult, PortListener } from "@/lib/types";

import { fmtTime } from "../_components/deep-ui";

const KIND_LABEL: Record<string, string> = {
  callback: "回调端口",
  webshell: "Webshell",
  tunnel: "隧道",
  listener: "监听器",
};

const KIND_CLASS: Record<string, string> = {
  callback: "border-violet-500/30 bg-violet-500/10 text-violet-600 dark:text-violet-400",
  webshell: "border-sky-500/30 bg-sky-500/10 text-sky-600 dark:text-sky-400",
  tunnel: "border-emerald-500/30 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400",
  listener: "border-slate-500/30 bg-slate-500/10 text-slate-600 dark:text-slate-400",
};

function statusMeta(status: string) {
  switch (status) {
    case "active":
      return { label: "占用中", className: "border-emerald-500/30 bg-emerald-500/10 text-emerald-600" };
    case "released":
      return { label: "已释放", className: "border-slate-500/30 bg-slate-500/10 text-slate-600 dark:text-slate-400" };
    case "expired":
      return { label: "已过期", className: "border-amber-500/30 bg-amber-500/10 text-amber-600 dark:text-amber-400" };
    default:
      return { label: status || "—", className: "" };
  }
}

function ttlText(resource: ManagedResource) {
  if (!resource.expires_at) return "常驻";
  const remaining = new Date(resource.expires_at).getTime() - Date.now();
  if (remaining <= 0) return "已到期";
  const minutes = Math.ceil(remaining / 60000);
  if (minutes < 60) return `${minutes} 分钟后到期`;
  const hours = Math.ceil(minutes / 60);
  if (hours < 48) return `${hours} 小时后到期`;
  return `${Math.ceil(hours / 24)} 天后到期`;
}

function scopeBadge(scope: string) {
  switch (scope) {
    case "wildcard":
      return {
        label: "全部网卡",
        className: "border-orange-500/30 bg-orange-500/10 text-orange-600 dark:text-orange-400",
      };
    case "interface":
      return { label: "指定网卡", className: "border-sky-500/30 bg-sky-500/10 text-sky-600 dark:text-sky-400" };
    default:
      return { label: "仅本机", className: "border-slate-500/30 bg-slate-500/10 text-slate-600 dark:text-slate-400" };
  }
}

function ownership(listener: PortListener) {
  if (listener.platform) {
    return { label: "平台自身", className: "border-sky-500/30 bg-sky-500/10 text-sky-600 dark:text-sky-400" };
  }
  if (listener.managed) {
    return {
      label: KIND_LABEL[listener.managed_kind ?? ""] ?? "受管资源",
      className: "border-emerald-500/30 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400",
    };
  }
  return { label: "未登记", className: "border-red-500/30 bg-red-500/10 text-red-600 dark:text-red-400" };
}

function StatCard({ label, value, tone }: { label: string; value: number; tone?: string }) {
  return (
    <div className="rounded-md border px-3 py-2">
      <div className="text-muted-foreground text-xs">{label}</div>
      <div className={`mt-0.5 font-semibold text-lg ${tone ?? ""}`}>{value}</div>
    </div>
  );
}

export default function DeepResourcesPage() {
  const [resources, setResources] = React.useState<ManagedResource[]>([]);
  const [total, setTotal] = React.useState(0);
  const [audit, setAudit] = React.useState<PortAuditResult | null>(null);
  const [loading, setLoading] = React.useState(false);
  const [auditing, setAuditing] = React.useState(false);
  const [statusFilter, setStatusFilter] = React.useState("active");
  const [refreshKey, setRefreshKey] = React.useState(0);
  const [busyId, setBusyId] = React.useState<number | null>(null);

  // biome-ignore lint/correctness/useExhaustiveDependencies: refreshKey is an explicit manual-reload trigger.
  React.useEffect(() => {
    let alive = true;
    async function load() {
      try {
        const r = await api.managedResources({ status: statusFilter === "all" ? undefined : statusFilter, limit: 200 });
        if (!alive) return;
        setResources(r.resources ?? []);
        setTotal(r.total ?? 0);
      } catch (e) {
        if (alive) toast.error((e as Error).message);
      } finally {
        if (alive) setLoading(false);
      }
    }
    setLoading(true);
    void load();
    const timer = setInterval(load, 5000);
    return () => {
      alive = false;
      clearInterval(timer);
    };
  }, [statusFilter, refreshKey]);

  const runAudit = React.useCallback(async (silent = false) => {
    if (!silent) setAuditing(true);
    try {
      const r = await api.auditLocalPorts();
      setAudit(r);
    } catch (e) {
      if (!silent) toast.error((e as Error).message);
    } finally {
      if (!silent) setAuditing(false);
    }
  }, []);

  React.useEffect(() => {
    void runAudit(true);
    const timer = setInterval(() => void runAudit(true), 15000);
    return () => clearInterval(timer);
  }, [runAudit]);

  async function release(resource: ManagedResource) {
    const hint =
      resource.kind === "callback"
        ? "释放后对应回调/JNDI 端口会立即下线；若已无其它回调，java-chains 也会停止。"
        : resource.kind === "webshell"
          ? "仅解除台账占用，不会删除 webshell 记录本身。"
          : "释放后平台不再为该资源保留监听。";
    if (!window.confirm(`释放「${resource.name || resource.endpoint}」？\n${hint}`)) return;
    setBusyId(resource.id);
    try {
      await api.releaseManagedResource(resource.id);
      toast.success("已释放");
      setRefreshKey((k) => k + 1);
      void runAudit(true);
    } catch (e) {
      toast.error((e as Error).message);
    } finally {
      setBusyId(null);
    }
  }

  const active = resources.filter((r) => r.status === "active");
  const activeByKind = (kind: string) => active.filter((r) => r.kind === kind).length;
  const unmanaged = audit?.unmanaged ?? [];
  const showLoading = loading && resources.length === 0;

  return (
    <div className="flex min-h-0 flex-1 flex-col gap-4">
      <div className="flex items-center justify-between gap-4">
        <div className="flex items-center gap-2">
          <ServerCogIcon className="h-5 w-5 text-muted-foreground" />
          <h1 className="font-semibold text-xl tracking-tight">受管资源</h1>
          <Badge variant="secondary">{total}</Badge>
        </div>
        <div className="flex items-center gap-2">
          <Select value={statusFilter} onValueChange={setStatusFilter}>
            <SelectTrigger className="w-32">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="active">占用中</SelectItem>
              <SelectItem value="released">已释放</SelectItem>
              <SelectItem value="expired">已过期</SelectItem>
              <SelectItem value="all">全部状态</SelectItem>
            </SelectContent>
          </Select>
          <Button variant="outline" size="sm" onClick={() => setRefreshKey((k) => k + 1)}>
            <RefreshCwIcon className="size-4" />
            刷新
          </Button>
          <Button size="sm" disabled={auditing} onClick={() => void runAudit()}>
            {auditing ? <Loader2Icon className="size-4 animate-spin" /> : <ShieldCheckIcon className="size-4" />}
            端口审计
          </Button>
        </div>
      </div>

      <p className="text-muted-foreground text-sm">
        回调端口、webshell、隧道等由平台开启的资源统一登记在这里，到期自动回收；端口审计对比本机监听与台账，暴露未登记的监听。
      </p>

      <div className="grid grid-cols-2 gap-2 sm:grid-cols-5">
        <StatCard label="占用中" value={active.length} />
        <StatCard label="回调端口" value={activeByKind("callback")} />
        <StatCard label="隧道" value={activeByKind("tunnel")} />
        <StatCard label="Webshell" value={activeByKind("webshell")} />
        <StatCard
          label="未登记监听"
          value={unmanaged.length}
          tone={unmanaged.length > 0 ? "text-red-600 dark:text-red-400" : ""}
        />
      </div>

      <Tabs defaultValue="ledger" className="flex min-h-0 flex-1 flex-col gap-3">
        <TabsList className="w-fit">
          <TabsTrigger value="ledger">资源台账</TabsTrigger>
          <TabsTrigger value="audit">端口审计{unmanaged.length > 0 ? ` (${unmanaged.length})` : ""}</TabsTrigger>
        </TabsList>

        <TabsContent value="ledger" className="flex min-h-0 flex-1 flex-col gap-3">
          {showLoading ? (
            <div className="flex items-center justify-center py-16 text-muted-foreground text-sm">
              <Loader2Icon className="mr-2 size-4 animate-spin" />
              加载中…
            </div>
          ) : null}
          {!showLoading && resources.length === 0 ? (
            <div className="rounded-md border border-dashed py-12 text-center text-muted-foreground text-sm">
              暂无受管资源。执行 webshell 注入、java-chains 反序列化或隧道任务后会自动登记。
            </div>
          ) : null}
          {resources.length > 0 ? (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-28">类型</TableHead>
                  <TableHead>资源</TableHead>
                  <TableHead>目标</TableHead>
                  <TableHead className="w-32">归属</TableHead>
                  <TableHead className="w-24">状态</TableHead>
                  <TableHead className="w-32">到期</TableHead>
                  <TableHead className="w-20 text-right">操作</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {resources.map((r) => {
                  const status = statusMeta(r.status);
                  return (
                    <TableRow key={r.id}>
                      <TableCell>
                        <Badge variant="outline" className={KIND_CLASS[r.kind] ?? ""}>
                          {KIND_LABEL[r.kind] ?? r.kind}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <div className="max-w-64 truncate font-medium text-sm" title={r.name}>
                          {r.name || r.endpoint || "—"}
                        </div>
                        <div className="max-w-72 truncate font-mono text-xs text-muted-foreground" title={r.endpoint}>
                          {r.endpoint}
                        </div>
                      </TableCell>
                      <TableCell className="max-w-56 truncate font-mono text-xs" title={r.target}>
                        {r.target || "—"}
                      </TableCell>
                      <TableCell className="text-xs">
                        <div>{r.owner || "—"}</div>
                        {r.task_id ? <div className="text-muted-foreground">任务 #{r.task_id}</div> : null}
                      </TableCell>
                      <TableCell>
                        <Badge variant="outline" className={status.className}>
                          {status.label}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-xs text-muted-foreground" title={r.expires_at}>
                        {r.status === "active" ? ttlText(r) : fmtTime(r.released_at ?? r.expires_at)}
                      </TableCell>
                      <TableCell className="text-right">
                        {r.status === "active" ? (
                          <Button variant="ghost" size="sm" disabled={busyId === r.id} onClick={() => release(r)}>
                            释放
                          </Button>
                        ) : (
                          <span className="text-muted-foreground text-xs">—</span>
                        )}
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          ) : null}
        </TabsContent>

        <TabsContent value="audit" className="flex min-h-0 flex-1 flex-col gap-3">
          <div className="flex items-center justify-between gap-3">
            <div className="flex items-center gap-2 text-muted-foreground text-sm">
              <NetworkIcon className="size-4" />
              本机监听 {audit?.listeners.length ?? 0} 个，未登记 {unmanaged.length} 个
              <span className="text-xs">· 白名单端口 {audit?.allow_ports.join(", ") || "—"}</span>
            </div>
            <span className="text-muted-foreground text-xs">审计时间 {fmtTime(audit?.checked_at)}</span>
          </div>
          {!audit ? (
            <div className="flex items-center justify-center py-16 text-muted-foreground text-sm">
              <Loader2Icon className="mr-2 size-4 animate-spin" />
              正在读取本机监听…
            </div>
          ) : audit.listeners.length === 0 ? (
            <div className="rounded-md border border-dashed py-12 text-center text-muted-foreground text-sm">
              未发现监听端口。
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-16">协议</TableHead>
                  <TableHead>监听地址</TableHead>
                  <TableHead className="w-20">端口</TableHead>
                  <TableHead>进程</TableHead>
                  <TableHead className="w-24">范围</TableHead>
                  <TableHead className="w-28">归属</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {audit.listeners.map((l) => {
                  const scope = scopeBadge(l.scope);
                  const owner = ownership(l);
                  return (
                    <TableRow key={`${l.proto}-${l.address}-${l.port}`}>
                      <TableCell className="font-mono text-xs uppercase">{l.proto}</TableCell>
                      <TableCell className="font-mono text-xs">{l.address}</TableCell>
                      <TableCell className="font-mono text-xs">{l.port}</TableCell>
                      <TableCell className="max-w-56 truncate text-xs">
                        {l.process || "未知进程"}
                        {l.pid ? <span className="text-muted-foreground"> · pid {l.pid}</span> : null}
                      </TableCell>
                      <TableCell>
                        <Badge variant="outline" className={scope.className}>
                          {scope.label}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <Badge variant="outline" className={owner.className}>
                          {owner.label}
                        </Badge>
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          )}
        </TabsContent>
      </Tabs>
    </div>
  );
}
