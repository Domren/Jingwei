"use client";

import * as React from "react";

import { CopyIcon, Loader2Icon, Trash2Icon } from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { api } from "@/lib/api";
import type { DeepTask, ExploitRecord, JavaChainsStatus, POCTemplate, WAFBypassResult } from "@/lib/types";
import { cn } from "@/lib/utils";

export const DEEP_KIND_LABEL: Record<string, string> = {
  verify: "漏洞验证",
  exploit: "漏洞利用",
  sqli_probe: "SQL 注入专项验证",
  xss_probe: "XSS 专项验证",
  waf_bypass: "WAF 绕过",
  webshell_inject: "Webshell 注入",
};

export function fmtTime(ts?: string) {
  if (!ts) return "—";
  return new Date(ts).toLocaleString("zh-CN", {
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function severityClass(sev: string) {
  switch (sev) {
    case "critical":
      return "border-red-500/30 bg-red-500/10 text-red-600 dark:text-red-400";
    case "high":
      return "border-orange-500/30 bg-orange-500/10 text-orange-600 dark:text-orange-400";
    case "medium":
      return "border-amber-500/30 bg-amber-500/10 text-amber-600 dark:text-amber-400";
    case "low":
      return "border-sky-500/30 bg-sky-500/10 text-sky-600 dark:text-sky-400";
    default:
      return "border-slate-500/30 bg-slate-500/10 text-slate-600 dark:text-slate-400";
  }
}

export function statusMeta(task: DeepTask): { label: string; className: string } {
  switch (task.status) {
    case "queued":
      return { label: "排队中", className: "border-slate-500/30 bg-slate-500/10" };
    case "running":
      return { label: stageLabel(task.stage), className: "border-sky-500/30 bg-sky-500/10 text-sky-600" };
    case "done":
      return { label: "已完成", className: "border-emerald-500/30 bg-emerald-500/10 text-emerald-600" };
    case "failed":
      return { label: "失败", className: "border-red-500/30 bg-red-500/10 text-red-600" };
    default:
      return { label: "已停止", className: "border-amber-500/30 bg-amber-500/10 text-amber-600" };
  }
}

function stageLabel(stage: string) {
  switch (stage) {
    case "discover":
      return "目标探测";
    case "match":
      return "匹配 POC";
    case "verify":
      return "漏洞验证";
    case "exploit":
      return "漏洞利用";
    case "sqlmap":
      return "SQL 注入检测";
    case "dalfox":
      return "XSS 检测";
    case "probe":
      return "注入点收集";
    case "waf":
      return "WAF 探测";
    case "inject":
      return "Webshell 注入";
    case "done":
      return "已完成";
    default:
      return "执行中";
  }
}

export function verdictMeta(verdict: string): { label: string; className: string } {
  switch (verdict) {
    case "confirmed":
      return { label: "已确认", className: "border-red-500/30 bg-red-500/10 text-red-600 dark:text-red-400" };
    case "needs_review":
      return { label: "待复核", className: "border-amber-500/30 bg-amber-500/10 text-amber-600 dark:text-amber-400" };
    case "not_reproduced":
      return { label: "未复现", className: "border-slate-500/30 bg-slate-500/10 text-slate-600 dark:text-slate-400" };
    case "tool_uncovered":
      return { label: "超出工具检测范围", className: "border-slate-500/30 bg-slate-500/10 text-slate-600 dark:text-slate-400" };
    case "session_needed":
      return { label: "需要登录会话", className: "border-amber-500/30 bg-amber-500/10 text-amber-600 dark:text-amber-400" };
    case "tool_unavailable":
      return { label: "工具未安装", className: "border-amber-500/30 bg-amber-500/10 text-amber-600" };
    case "error":
      return { label: "工具执行失败", className: "border-red-500/30 bg-red-500/10 text-red-600" };
    case "executed":
      return { label: "已执行", className: "border-emerald-500/30 bg-emerald-500/10 text-emerald-600" };
    case "attempted":
      return { label: "已投递待回连", className: "border-amber-500/30 bg-amber-500/10 text-amber-600" };
    case "payload_generated":
      return { label: "已生成 payload", className: "border-sky-500/30 bg-sky-500/10 text-sky-600" };
    case "server_error":
      return { label: "服务端错误", className: "border-amber-500/30 bg-amber-500/10 text-amber-600" };
    default:
      return { label: verdict || "—", className: "" };
  }
}

export function wafVerdictMeta(verdict: string): { label: string; className: string } {
  switch (verdict) {
    case "bypassed":
      return { label: "可绕过", className: "border-emerald-500/30 bg-emerald-500/10 text-emerald-600" };
    case "blocked":
      return { label: "被拦截", className: "border-red-500/30 bg-red-500/10 text-red-600 dark:text-red-400" };
    case "passed":
      return { label: "无拦截", className: "border-sky-500/30 bg-sky-500/10 text-sky-600" };
    default:
      return { label: "错误", className: "border-amber-500/30 bg-amber-500/10 text-amber-600" };
  }
}

/** JavaChainsHint shows whether the optional java-chains sidecar can be used. */
export function JavaChainsHint() {
  const [status, setStatus] = React.useState<JavaChainsStatus | null>(null);

  React.useEffect(() => {
    let alive = true;
    api
      .javaChainsStatus()
      .then((s) => alive && setStatus(s))
      .catch(() => undefined);
    return () => {
      alive = false;
    };
  }, []);

  if (!status) return null;
  if (!status.configured) {
    return <span className="text-xs text-muted-foreground">java-chains 未配置，自动反序列化利用不可用</span>;
  }
  if (!status.online) {
    return (
      <span className="text-xs text-amber-600 dark:text-amber-400" title={status.error ?? "sidecar 未启动"}>
        java-chains 未启动（docker compose --profile java-chains up -d java-chains）
      </span>
    );
  }
  return (
    <span
      className="text-xs text-emerald-600 dark:text-emerald-400"
      title={`${status.url} · 回调 ${status.callback_host}`}
    >
      java-chains 在线 · 反序列化 POC 将自动选链与投递
    </span>
  );
}

/** useDeepTasks polls the deep-task list of one kind. */
export function useDeepTasks(kind: string) {
  const [tasks, setTasks] = React.useState<DeepTask[]>([]);
  const [total, setTotal] = React.useState(0);
  const [loading, setLoading] = React.useState(false);
  const [refreshKey, setRefreshKey] = React.useState(0);

  // biome-ignore lint/correctness/useExhaustiveDependencies: refreshKey is an explicit manual-reload trigger.
  React.useEffect(() => {
    let alive = true;
    async function load() {
      try {
        const r = await api.deepTasks({ kind, limit: 100 });
        if (!alive) return;
        setTasks(r.tasks ?? []);
        setTotal(r.total ?? 0);
      } catch (e) {
        if (alive) toast.error((e as Error).message);
      } finally {
        if (alive) setLoading(false);
      }
    }
    setLoading(true);
    void load();
    const timer = setInterval(load, 4000);
    return () => {
      alive = false;
      clearInterval(timer);
    };
  }, [kind, refreshKey]);

  return { tasks, total, loading, refresh: () => setRefreshKey((k) => k + 1) };
}

/** DeepTaskTable renders the task list shared by every deep-exploitation page. */
export function DeepTaskTable({
  tasks,
  onOpen,
  onChanged,
  emptyHint,
}: {
  tasks: DeepTask[];
  onOpen: (id: number) => void;
  onChanged: () => void;
  emptyHint: string;
}) {
  const [busyId, setBusyId] = React.useState<number | null>(null);

  async function stop(task: DeepTask) {
    setBusyId(task.id);
    try {
      await api.cancelDeepTask(task.id);
      toast.success("已请求停止");
      onChanged();
    } catch (e) {
      toast.error((e as Error).message);
    } finally {
      setBusyId(null);
    }
  }

  async function remove(task: DeepTask) {
    if (!window.confirm(`删除深度利用任务「${task.name}」及其证据？`)) return;
    setBusyId(task.id);
    try {
      await api.deleteDeepTask(task.id);
      toast.success("已删除");
      onChanged();
    } catch (e) {
      toast.error((e as Error).message);
    } finally {
      setBusyId(null);
    }
  }

  if (tasks.length === 0) {
    return (
      <div className="rounded-md border border-dashed py-12 text-center text-sm text-muted-foreground">{emptyHint}</div>
    );
  }

  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead className="w-16">ID</TableHead>
          <TableHead>名称</TableHead>
          <TableHead>目标</TableHead>
          <TableHead className="w-24">状态</TableHead>
          <TableHead className="w-36">创建时间</TableHead>
          <TableHead className="w-32 text-right">操作</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {tasks.map((t) => {
          const meta = statusMeta(t);
          const running = t.status === "running" || t.status === "queued";
          return (
            <TableRow key={t.id}>
              <TableCell className="font-mono text-xs text-muted-foreground">#{t.id}</TableCell>
              <TableCell className="max-w-56 truncate font-medium" title={t.name}>
                {t.name}
              </TableCell>
              <TableCell className="max-w-72 truncate font-mono text-xs" title={t.target}>
                {t.target}
              </TableCell>
              <TableCell>
                <Badge variant="outline" className={meta.className}>
                  {meta.label}
                </Badge>
              </TableCell>
              <TableCell className="text-xs text-muted-foreground">{fmtTime(t.created_at)}</TableCell>
              <TableCell className="text-right">
                <div className="flex items-center justify-end gap-1">
                  <Button variant="ghost" size="sm" onClick={() => onOpen(t.id)}>
                    详情
                  </Button>
                  {running && (
                    <Button variant="ghost" size="sm" disabled={busyId === t.id} onClick={() => stop(t)}>
                      停止
                    </Button>
                  )}
                  {!running && (
                    <Button variant="ghost" size="sm" disabled={busyId === t.id} onClick={() => remove(t)}>
                      <Trash2Icon className="size-3.5" />
                    </Button>
                  )}
                </div>
              </TableCell>
            </TableRow>
          );
        })}
      </TableBody>
    </Table>
  );
}

/** DeepDetailDialog shows the log, summary and evidence of one deep task. */
export function DeepDetailDialog({
  taskId,
  open,
  onOpenChange,
  onChanged,
}: {
  taskId: number | null;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onChanged: () => void;
}) {
  const [task, setTask] = React.useState<DeepTask | null>(null);
  const [records, setRecords] = React.useState<ExploitRecord[]>([]);
  const [wafResults, setWafResults] = React.useState<WAFBypassResult[]>([]);
  const [tab, setTab] = React.useState("records");

  React.useEffect(() => {
    if (!open || !taskId) return;
    const id = taskId;
    let alive = true;

    async function load() {
      try {
        const r = await api.deepTask(id);
        if (!alive) return;
        setTask(r.task);
        setRecords(r.records ?? []);
        setWafResults(r.waf_results ?? []);
      } catch (e) {
        if (alive) toast.error((e as Error).message);
      }
    }

    void load();
    const timer = setInterval(load, 2500);
    return () => {
      alive = false;
      clearInterval(timer);
    };
  }, [open, taskId]);

  React.useEffect(() => {
    if (!open) return;
    const running = task?.status === "running" || task?.status === "queued";
    if (running) onChanged();
  }, [open, task?.status, onChanged]);

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[88vh] overflow-hidden sm:max-w-4xl">
        <DialogHeader>
          <DialogTitle>深度利用任务 #{taskId}</DialogTitle>
          <DialogDescription>{task ? task.name : "加载中…"}</DialogDescription>
        </DialogHeader>

        <div className="flex min-h-0 flex-1 flex-col gap-3 overflow-hidden">
          {task && (
            <div className="grid grid-cols-2 gap-2 text-xs sm:grid-cols-4">
              <div className="rounded-md border p-2">
                <div className="text-muted-foreground">类型</div>
                <div className="mt-0.5 font-medium">{DEEP_KIND_LABEL[task.kind] ?? task.kind}</div>
              </div>
              <div className="rounded-md border p-2">
                <div className="text-muted-foreground">状态</div>
                <div className="mt-0.5 font-medium">{statusMeta(task).label}</div>
              </div>
              <div className="rounded-md border p-2">
                <div className="text-muted-foreground">目标</div>
                <div className="mt-0.5 truncate font-mono">{task.target}</div>
              </div>
              <div className="rounded-md border p-2">
                <div className="text-muted-foreground">结果</div>
                <div className="mt-0.5 font-medium">{summaryText(task.summary)}</div>
              </div>
            </div>
          )}

          {task?.error && (
            <div className="rounded-md border border-red-500/40 bg-red-500/5 px-3 py-2 text-xs text-red-600 dark:text-red-400">
              {task.error}
            </div>
          )}

          <div className="flex min-h-0 flex-1 flex-col gap-2">
            <div className="flex gap-2 border-b">
              {wafResults.length > 0 && (
                <button
                  type="button"
                  className={cn(
                    "border-b-2 px-3 py-1.5 text-sm transition-colors",
                    tab === "waf"
                      ? "border-primary text-foreground"
                      : "border-transparent text-muted-foreground hover:text-foreground",
                  )}
                  onClick={() => setTab("waf")}
                >
                  WAF 结果 ({wafResults.length})
                </button>
              )}
              <button
                type="button"
                className={cn(
                  "border-b-2 px-3 py-1.5 text-sm transition-colors",
                  tab === "records"
                    ? "border-primary text-foreground"
                    : "border-transparent text-muted-foreground hover:text-foreground",
                )}
                onClick={() => setTab("records")}
              >
                证据 ({records.length})
              </button>
              <button
                type="button"
                className={cn(
                  "border-b-2 px-3 py-1.5 text-sm transition-colors",
                  tab === "log"
                    ? "border-primary text-foreground"
                    : "border-transparent text-muted-foreground hover:text-foreground",
                )}
                onClick={() => setTab("log")}
              >
                日志
              </button>
            </div>

            <ScrollArea className="min-h-0 flex-1">
              <div className="pr-3">
                {tab === "records" && <ExploitRecordList records={records} />}
                {tab === "waf" && <WAFResultList results={wafResults} />}
                {tab === "log" && (
                  <pre className="whitespace-pre-wrap break-all rounded-md bg-muted/50 p-3 font-mono text-xs">
                    {task?.log?.trim() || "（暂无日志）"}
                  </pre>
                )}
              </div>
            </ScrollArea>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}

function summaryText(summary: Record<string, unknown>) {
  const parts: string[] = [];
  for (const [k, v] of Object.entries(summary)) {
    if (typeof v === "number" || typeof v === "boolean" || typeof v === "string") {
      parts.push(`${k}=${v}`);
    }
  }
  return parts.length > 0 ? parts.join(" · ") : "—";
}

/** ExploitRecordList renders the verification / exploitation evidence. */
export function ExploitRecordList({ records }: { records: ExploitRecord[] }) {
  if (records.length === 0) {
    return <p className="py-8 text-center text-sm text-muted-foreground">暂无证据记录</p>;
  }
  return (
    <div className="flex flex-col gap-2">
      {records.map((rec) => (
        <ExploitRecordCard key={rec.id} record={rec} />
      ))}
    </div>
  );
}

function ExploitRecordCard({ record }: { record: ExploitRecord }) {
  const [expanded, setExpanded] = React.useState(false);
  const verdict = verdictMeta(record.verdict);
  return (
    <div className="rounded-md border">
      <div className="flex items-center gap-2 px-3 py-2">
        <Badge variant="outline" className={severityClass(record.severity)}>
          {record.severity || "unknown"}
        </Badge>
        <Badge variant="outline" className={verdict.className}>
          {verdict.label}
        </Badge>
        {record.mode === "java_chains" && (
          <Badge
            variant="outline"
            className="border-violet-500/30 bg-violet-500/10 text-violet-600 dark:text-violet-400"
          >
            java-chains
          </Badge>
        )}
        <span className="min-w-0 flex-1 truncate text-sm font-medium">{record.name}</span>
        {record.status_code ? (
          <span className="font-mono text-xs text-muted-foreground">HTTP {record.status_code}</span>
        ) : null}
        <Button variant="ghost" size="sm" onClick={() => setExpanded((v) => !v)}>
          {expanded ? "收起" : "展开"}
        </Button>
      </div>
      <div className="border-t px-3 py-1.5 text-xs text-muted-foreground">
        <span className="font-mono">{record.template_id}</span>
        {record.target ? <span className="ml-3">{record.target}</span> : null}
        {record.extracted.length ? <span className="ml-3">提取: {record.extracted.join(", ")}</span> : null}
      </div>
      {expanded && (
        <div className="flex flex-col gap-2 border-t p-3">
          {record.curl_command && (
            <div>
              <div className="mb-1 flex items-center justify-between">
                <span className="text-xs font-medium text-muted-foreground">curl</span>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => {
                    void navigator.clipboard.writeText(record.curl_command ?? "");
                    toast.success("已复制 curl");
                  }}
                >
                  <CopyIcon className="size-3.5" />
                </Button>
              </div>
              <pre className="overflow-x-auto rounded bg-muted/50 p-2 font-mono text-xs">{record.curl_command}</pre>
            </div>
          )}
          {record.request && (
            <div>
              <div className="mb-1 text-xs font-medium text-muted-foreground">请求</div>
              <pre className="overflow-x-auto whitespace-pre-wrap break-all rounded bg-muted/50 p-2 font-mono text-xs">
                {record.request}
              </pre>
            </div>
          )}
          {record.response && (
            <div>
              <div className="mb-1 text-xs font-medium text-muted-foreground">响应</div>
              <pre className="overflow-x-auto whitespace-pre-wrap break-all rounded bg-muted/50 p-2 font-mono text-xs">
                {record.response}
              </pre>
            </div>
          )}
          {record.evidence && (
            <div>
              <div className="mb-1 text-xs font-medium text-muted-foreground">说明</div>
              <pre className="whitespace-pre-wrap break-all rounded bg-muted/50 p-2 font-mono text-xs">
                {record.evidence}
              </pre>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

/** WAFResultList renders the WAF bypass attempts. */
export function WAFResultList({ results }: { results: WAFBypassResult[] }) {
  if (results.length === 0) {
    return <p className="py-8 text-center text-sm text-muted-foreground">暂无绕过结果</p>;
  }
  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>变形</TableHead>
          <TableHead>方法</TableHead>
          <TableHead>路径</TableHead>
          <TableHead className="w-20">状态码</TableHead>
          <TableHead className="w-24">结论</TableHead>
          <TableHead className="w-20">长度</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {results.map((r) => {
          const meta = wafVerdictMeta(r.verdict);
          return (
            <TableRow key={r.id}>
              <TableCell>
                <div className="font-medium">{r.variant_desc || r.variant}</div>
                <div className="font-mono text-xs text-muted-foreground">{r.variant}</div>
              </TableCell>
              <TableCell className="font-mono text-xs">{r.method}</TableCell>
              <TableCell className="max-w-64 truncate font-mono text-xs" title={r.path}>
                {r.path}
              </TableCell>
              <TableCell className="font-mono text-xs">{r.status_code ?? "—"}</TableCell>
              <TableCell>
                <Badge variant="outline" className={meta.className}>
                  {meta.label}
                </Badge>
              </TableCell>
              <TableCell className="font-mono text-xs text-muted-foreground">{r.resp_length}</TableCell>
            </TableRow>
          );
        })}
      </TableBody>
    </Table>
  );
}

/** PickerFields renders a target/POC picker shared by the task creation forms. */
export function PocPicker({ selected, onChange }: { selected: Set<number>; onChange: (next: Set<number>) => void }) {
  const [query, setQuery] = React.useState("");
  const [debounced, setDebounced] = React.useState("");
  const [page, setPage] = React.useState(0);
  const [pocs, setPocs] = React.useState<POCTemplate[]>([]);
  const [total, setTotal] = React.useState(0);
  const [loading, setLoading] = React.useState(false);
  const PAGE_SIZE = 10;

  React.useEffect(() => {
    const t = setTimeout(() => {
      setDebounced(query.trim());
      setPage(0);
    }, 300);
    return () => clearTimeout(t);
  }, [query]);

  React.useEffect(() => {
    let alive = true;
    setLoading(true);
    api
      .pocs({ q: debounced || undefined, enabled: "true", page, size: PAGE_SIZE })
      .then((r) => {
        if (!alive) return;
        setPocs(r.pocs ?? []);
        setTotal(r.total ?? 0);
      })
      .catch((e: Error) => alive && toast.error(e.message))
      .finally(() => alive && setLoading(false));
    return () => {
      alive = false;
    };
  }, [debounced, page]);

  const pages = Math.max(1, Math.ceil(total / PAGE_SIZE));

  return (
    <div className="flex flex-col gap-2">
      <Input
        value={query}
        onChange={(e) => setQuery(e.target.value)}
        placeholder="搜索 POC 模板（留空则按目标指纹自动匹配）"
      />
      <div className="max-h-56 overflow-y-auto rounded-md border">
        {loading && <p className="p-3 text-center text-xs text-muted-foreground">加载中…</p>}
        {!loading && pocs.length === 0 && (
          <p className="p-3 text-center text-xs text-muted-foreground">没有匹配的 POC</p>
        )}
        <Table>
          <TableBody>
            {pocs.map((p) => (
              <TableRow key={p.id}>
                <TableCell className="w-10">
                  <Checkbox
                    checked={selected.has(p.id)}
                    onCheckedChange={(checked) => {
                      const next = new Set(selected);
                      if (checked) next.add(p.id);
                      else next.delete(p.id);
                      onChange(next);
                    }}
                    aria-label={`选择 ${p.name}`}
                  />
                </TableCell>
                <TableCell>
                  <div className="max-w-72 truncate text-xs font-medium">{p.name}</div>
                  <div className="max-w-72 truncate font-mono text-[11px] text-muted-foreground">{p.template_id}</div>
                </TableCell>
                <TableCell className="w-20 text-right">
                  <Badge variant="outline" className={severityClass(p.severity)}>
                    {p.severity}
                  </Badge>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>
      <div className="flex items-center justify-between text-xs text-muted-foreground">
        <span>
          已选 {selected.size} 个 / 共 {total} 个
        </span>
        <div className="flex items-center gap-1">
          <Button variant="outline" size="sm" disabled={page === 0} onClick={() => setPage((p) => p - 1)}>
            上一页
          </Button>
          <span>
            {page + 1}/{pages}
          </span>
          <Button variant="outline" size="sm" disabled={page + 1 >= pages} onClick={() => setPage((p) => p + 1)}>
            下一页
          </Button>
        </div>
      </div>
    </div>
  );
}

/** TaskFormShell wraps the shared fields of every creation form. */
export function TaskFormShell({
  children,
  onSubmit,
  submitting,
  submitLabel,
}: {
  children: React.ReactNode;
  onSubmit: () => void;
  submitting: boolean;
  submitLabel: string;
}) {
  return (
    <form
      className="flex flex-col gap-4"
      onSubmit={(e) => {
        e.preventDefault();
        onSubmit();
      }}
    >
      {children}
      <Button type="submit" disabled={submitting}>
        {submitting ? <Loader2Icon className="size-4 animate-spin" /> : null}
        {submitLabel}
      </Button>
    </form>
  );
}

/** FieldRow is a labelled form row. */
export function FieldRow({ label, hint, children }: { label: string; hint?: string; children: React.ReactNode }) {
  return (
    <div className="flex flex-col gap-1.5">
      <Label>{label}</Label>
      {children}
      {hint ? <p className="text-xs text-muted-foreground">{hint}</p> : null}
    </div>
  );
}
