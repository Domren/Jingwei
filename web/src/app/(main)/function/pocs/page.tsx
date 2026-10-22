"use client";

import * as React from "react";
import { toast } from "sonner";
import {
  ChevronLeftIcon,
  ChevronRightIcon,
  CopyIcon,
  FlaskConicalIcon,
  Loader2Icon,
  PlayIcon,
  SearchIcon,
  Trash2Icon,
  UploadIcon,
} from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import { Switch } from "@/components/ui/switch";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Textarea } from "@/components/ui/textarea";
import { api } from "@/lib/api";
import type { POCRunResponse, POCStats, POCTemplate } from "@/lib/types";
import { cn } from "@/lib/utils";

const PAGE_SIZES = [25, 50, 100, 200];
const SEVERITIES = ["critical", "high", "medium", "low", "info", "unknown"];

function fmtTime(ts: string) {
  return new Date(ts).toLocaleString("zh-CN", {
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function fmtBytes(n: number) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

function severityClass(sev: string) {
  switch (sev) {
    case "critical":
      return "border-red-500/30 bg-red-500/10 text-red-600 dark:text-red-400";
    case "high":
      return "border-orange-500/30 bg-orange-500/10 text-orange-600 dark:text-orange-400";
    case "medium":
      return "border-amber-500/30 bg-amber-500/10 text-amber-600 dark:text-amber-400";
    case "low":
      return "border-sky-500/30 bg-sky-500/10 text-sky-600 dark:text-sky-400";
    case "info":
      return "border-slate-500/30 bg-slate-500/10 text-slate-600 dark:text-slate-400";
    default:
      return "";
  }
}

function splitTargets(raw: string): string[] {
  return Array.from(
    new Set(
      raw
        .split(/[\s,;]+/)
        .map((s) => s.trim())
        .filter(Boolean),
    ),
  );
}

export default function POCsPage() {
  const [items, setItems] = React.useState<POCTemplate[]>([]);
  const [total, setTotal] = React.useState(0);
  const [stats, setStats] = React.useState<POCStats | null>(null);
  const [loading, setLoading] = React.useState(false);

  const [query, setQuery] = React.useState("");
  const [queryQ, setQueryQ] = React.useState("");
  const [severity, setSeverity] = React.useState("all");
  const [source, setSource] = React.useState("all");
  const [enabled, setEnabled] = React.useState("all");
  const [page, setPage] = React.useState(0);
  const [size, setSize] = React.useState(50);
  const [refreshKey, setRefreshKey] = React.useState(0);
  const [selectedIds, setSelectedIds] = React.useState<Set<number>>(new Set());

  const [detail, setDetail] = React.useState<POCTemplate | null>(null);
  const [detailOpen, setDetailOpen] = React.useState(false);
  const [detailLoading, setDetailLoading] = React.useState(false);

  const [uploadOpen, setUploadOpen] = React.useState(false);
  const [uploadText, setUploadText] = React.useState("");
  const [uploadName, setUploadName] = React.useState("");
  const [uploading, setUploading] = React.useState(false);

  const [runOpen, setRunOpen] = React.useState(false);
  const [runTargets, setRunTargets] = React.useState("");
  const [runTimeout, setRunTimeout] = React.useState("180");
  const [running, setRunning] = React.useState(false);
  const [runResp, setRunResp] = React.useState<POCRunResponse | null>(null);

  const fileRef = React.useRef<HTMLInputElement>(null);

  React.useEffect(() => {
    const t = setTimeout(() => setQueryQ(query.trim()), 300);
    return () => clearTimeout(t);
  }, [query]);

  // biome-ignore lint/correctness/useExhaustiveDependencies: filters intentionally reset pagination.
  React.useEffect(() => {
    setPage(0);
    setSelectedIds(new Set());
  }, [queryQ, severity, source, enabled, size]);

  const loadStats = React.useCallback(() => {
    api
      .pocStats()
      .then(setStats)
      .catch(() => setStats(null));
  }, []);

  React.useEffect(() => {
    loadStats();
  }, [loadStats]);

  React.useEffect(() => {
    let alive = true;
    setLoading(true);
    api
      .pocs({
        q: queryQ || undefined,
        severity: severity === "all" ? undefined : severity,
        source: source === "all" ? undefined : source,
        enabled: enabled === "all" ? undefined : enabled,
        page,
        size,
      })
      .then((r) => {
        if (!alive) return;
        setItems(r.pocs ?? []);
        setTotal(r.total ?? 0);
      })
      .catch((e: Error) => {
        if (!alive) return;
        setItems([]);
        setTotal(0);
        toast.error(e.message);
      })
      .finally(() => alive && setLoading(false));
    return () => {
      alive = false;
    };
  }, [page, size, queryQ, severity, source, enabled, refreshKey]);

  const totalPages = Math.max(1, Math.ceil(total / size));
  const rangeStart = total === 0 ? 0 : page * size + 1;
  const rangeEnd = page * size + items.length;
  const selectedOnPage = items.filter((p) => selectedIds.has(p.id)).length;
  const allOnPageSelected = items.length > 0 && selectedOnPage === items.length;

  function toggleAllOnPage(checked: boolean) {
    const next = new Set(selectedIds);
    for (const p of items) {
      if (checked) next.add(p.id);
      else next.delete(p.id);
    }
    setSelectedIds(next);
  }

  function toggleOne(id: number, checked: boolean) {
    const next = new Set(selectedIds);
    if (checked) next.add(id);
    else next.delete(id);
    setSelectedIds(next);
  }

  async function openDetail(row: POCTemplate) {
    setDetailOpen(true);
    setDetail(null);
    setDetailLoading(true);
    try {
      setDetail(await api.poc(row.id));
    } catch (e) {
      toast.error((e as Error).message);
      setDetailOpen(false);
    } finally {
      setDetailLoading(false);
    }
  }

  async function toggleEnabled(row: POCTemplate, value: boolean) {
    try {
      await api.updatePoc(row.id, { enabled: value });
      setItems((prev) => prev.map((p) => (p.id === row.id ? { ...p, enabled: value } : p)));
      loadStats();
      toast.success(value ? "已启用" : "已禁用");
    } catch (e) {
      toast.error((e as Error).message);
    }
  }

  async function removePOC(row: POCTemplate) {
    if (!window.confirm(`删除 POC「${row.name}」？此操作不可撤销。`)) return;
    try {
      await api.deletePoc(row.id);
      toast.success("已删除");
      setSelectedIds((prev) => {
        const next = new Set(prev);
        next.delete(row.id);
        return next;
      });
      loadStats();
      setPage((p) => (items.length === 1 && p > 0 ? p - 1 : p));
      setRefreshKey((k) => k + 1);
    } catch (e) {
      toast.error((e as Error).message);
    }
  }

  function pickFile(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;
    if (file.size > 2 * 1024 * 1024) {
      toast.error("文件超过 2MB");
      return;
    }
    const reader = new FileReader();
    reader.onload = () => {
      setUploadText(String(reader.result ?? ""));
      setUploadName(file.name);
    };
    reader.readAsText(file);
  }

  async function submitUpload() {
    if (!uploadText.trim()) {
      toast.error("请粘贴 YAML 或选择文件");
      return;
    }
    setUploading(true);
    try {
      const p = await api.createPoc({ content: uploadText, source: "manual" });
      toast.success(`已导入：${p.name}`);
      setUploadOpen(false);
      setUploadText("");
      setUploadName("");
      loadStats();
      setPage(0);
      setRefreshKey((k) => k + 1);
    } catch (e) {
      toast.error((e as Error).message);
    } finally {
      setUploading(false);
    }
  }

  async function submitRun() {
    const targets = splitTargets(runTargets);
    if (selectedIds.size === 0) {
      toast.error("请先选择 POC");
      return;
    }
    if (targets.length === 0) {
      toast.error("请填写目标");
      return;
    }
    setRunning(true);
    setRunResp(null);
    try {
      const resp = await api.runPocs({
        ids: Array.from(selectedIds),
        targets,
        timeout_seconds: Number(runTimeout) || 180,
      });
      setRunResp(resp);
      if (resp.ok) toast.success(`扫描完成，命中 ${resp.result_count} 条`);
      else toast.error(resp.error || "执行失败");
    } catch (e) {
      toast.error((e as Error).message);
    } finally {
      setRunning(false);
    }
  }

  function openRun() {
    setRunResp(null);
    setRunOpen(true);
  }

  async function copyContent() {
    if (!detail?.content) return;
    try {
      await navigator.clipboard.writeText(detail.content);
      toast.success("YAML 已复制");
    } catch {
      toast.error("复制失败");
    }
  }

  const runNames = items.filter((p) => selectedIds.has(p.id)).map((p) => p.name);
  const critical = stats?.by_severity?.critical ?? 0;
  const high = stats?.by_severity?.high ?? 0;

  return (
    <div className="flex min-h-0 flex-1 flex-col gap-4">
      <div className="flex items-center justify-between gap-4">
        <div className="flex items-center gap-2">
          <FlaskConicalIcon className="h-5 w-5 text-muted-foreground" />
          <h1 className="text-xl font-semibold tracking-tight">POC 库</h1>
          <Badge variant="secondary">{total}</Badge>
          {stats && (
            <span className="hidden items-center gap-2 text-xs text-muted-foreground md:flex">
              <span>可用 {stats.enabled}</span>
              <span className="text-red-500">严重 {critical}</span>
              <span className="text-orange-500">高危 {high}</span>
            </span>
          )}
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm" onClick={() => setUploadOpen(true)}>
            <UploadIcon className="size-4" />
            上传 POC
          </Button>
          <Button size="sm" onClick={openRun} disabled={selectedIds.size === 0}>
            <PlayIcon className="size-4" />
            执行已选 {selectedIds.size > 0 ? `(${selectedIds.size})` : ""}
          </Button>
        </div>
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <div className="relative max-w-sm flex-1">
          <SearchIcon className="absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            placeholder="搜索名称 / ID / CVE / 描述..."
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            className="h-8 pl-8"
          />
        </div>
        <Select value={severity} onValueChange={setSeverity}>
          <SelectTrigger size="sm" className="w-28">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">全部等级</SelectItem>
            {SEVERITIES.map((s) => (
              <SelectItem key={s} value={s}>
                {s}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Select value={source} onValueChange={setSource}>
          <SelectTrigger size="sm" className="w-36">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">全部来源</SelectItem>
            {(stats?.sources ?? []).map((s) => (
              <SelectItem key={s} value={s}>
                {s}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Select value={enabled} onValueChange={setEnabled}>
          <SelectTrigger size="sm" className="w-28">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">全部状态</SelectItem>
            <SelectItem value="true">已启用</SelectItem>
            <SelectItem value="false">已禁用</SelectItem>
          </SelectContent>
        </Select>
        <Select value={String(size)} onValueChange={(v) => setSize(Number(v))}>
          <SelectTrigger size="sm" className="w-28">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {PAGE_SIZES.map((n) => (
              <SelectItem key={n} value={String(n)}>
                {n} / 页
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <div className="ml-auto flex items-center gap-2 text-xs text-muted-foreground">
          <span className="tabular-nums">
            {rangeStart}–{rangeEnd} / {total}
          </span>
          <Button
            variant="outline"
            size="icon"
            className="size-8"
            disabled={page <= 0 || loading}
            onClick={() => setPage((p) => Math.max(0, p - 1))}
          >
            <ChevronLeftIcon className="size-4" />
          </Button>
          <span className="tabular-nums">
            {page + 1}/{totalPages}
          </span>
          <Button
            variant="outline"
            size="icon"
            className="size-8"
            disabled={page + 1 >= totalPages || loading}
            onClick={() => setPage((p) => p + 1)}
          >
            <ChevronRightIcon className="size-4" />
          </Button>
        </div>
      </div>

      <div className="min-h-0 flex-1 overflow-auto rounded-md border">
        <Table>
          <TableHeader className="sticky top-0 z-10 bg-background">
            <TableRow>
              <TableHead className="w-10">
                <Checkbox
                  checked={allOnPageSelected ? true : selectedOnPage > 0 ? "indeterminate" : false}
                  onCheckedChange={(v) => toggleAllOnPage(v === true)}
                  aria-label="选择当前页"
                />
              </TableHead>
              <TableHead>模板</TableHead>
              <TableHead className="w-24">等级</TableHead>
              <TableHead className="w-20">协议</TableHead>
              <TableHead className="w-40">CVE / CWE</TableHead>
              <TableHead>标签</TableHead>
              <TableHead className="w-28">更新时间</TableHead>
              <TableHead className="w-32">启用</TableHead>
              <TableHead className="w-24">操作</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {loading && items.length === 0 ? (
              <TableRow>
                <TableCell colSpan={9} className="h-32 text-center text-muted-foreground">
                  <Loader2Icon className="mx-auto size-5 animate-spin" />
                </TableCell>
              </TableRow>
            ) : items.length === 0 ? (
              <TableRow>
                <TableCell colSpan={9} className="h-32 text-center text-muted-foreground">
                  暂无 POC 模板，点击右上角「上传 POC」导入 nuclei YAML。
                </TableCell>
              </TableRow>
            ) : (
              items.map((row) => (
                <TableRow key={row.id}>
                  <TableCell>
                    <Checkbox
                      checked={selectedIds.has(row.id)}
                      onCheckedChange={(v) => toggleOne(row.id, v === true)}
                      aria-label={`选择 ${row.name}`}
                    />
                  </TableCell>
                  <TableCell>
                    <button
                      type="button"
                      className="max-w-md truncate text-left font-medium hover:underline"
                      onClick={() => openDetail(row)}
                    >
                      {row.name}
                    </button>
                    <div className="max-w-md truncate font-mono text-xs text-muted-foreground">{row.template_id}</div>
                  </TableCell>
                  <TableCell>
                    <Badge variant="outline" className={cn("uppercase", severityClass(row.severity))}>
                      {row.severity}
                    </Badge>
                  </TableCell>
                  <TableCell className="text-xs uppercase text-muted-foreground">{row.protocol || "—"}</TableCell>
                  <TableCell className="text-xs">
                    <div className="max-w-40 truncate font-mono">{row.cve_id || row.cwe_id || "—"}</div>
                  </TableCell>
                  <TableCell>
                    <div className="flex max-w-56 flex-wrap gap-1">
                      {row.tags.slice(0, 3).map((t) => (
                        <Badge key={t} variant="secondary" className="text-[10px]">
                          {t}
                        </Badge>
                      ))}
                      {row.tags.length > 3 && (
                        <span className="text-xs text-muted-foreground">+{row.tags.length - 3}</span>
                      )}
                    </div>
                  </TableCell>
                  <TableCell className="text-xs text-muted-foreground">{fmtTime(row.updated_at)}</TableCell>
                  <TableCell>
                    <Switch checked={row.enabled} onCheckedChange={(v) => toggleEnabled(row, v)} />
                  </TableCell>
                  <TableCell>
                    <div className="flex items-center gap-1">
                      <Button variant="ghost" size="icon" className="size-8" onClick={() => openDetail(row)}>
                        <SearchIcon className="size-4" />
                      </Button>
                      <Button
                        variant="ghost"
                        size="icon"
                        className="size-8 text-destructive"
                        onClick={() => removePOC(row)}
                      >
                        <Trash2Icon className="size-4" />
                      </Button>
                    </div>
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </div>

      {/* Detail */}
      <Sheet open={detailOpen} onOpenChange={setDetailOpen}>
        <SheetContent className="flex w-full flex-col gap-0 sm:max-w-2xl">
          <SheetHeader>
            <SheetTitle className="pr-8">{detail?.name ?? "加载中..."}</SheetTitle>
            <SheetDescription className="font-mono text-xs">
              {detail ? `${detail.template_id} · ${fmtBytes(detail.size_bytes)}` : ""}
            </SheetDescription>
          </SheetHeader>
          {detailLoading || !detail ? (
            <div className="flex flex-1 items-center justify-center">
              <Loader2Icon className="size-5 animate-spin text-muted-foreground" />
            </div>
          ) : (
            <div className="flex min-h-0 flex-1 flex-col gap-3 overflow-y-auto px-4 pb-4">
              <div className="flex flex-wrap items-center gap-2">
                <Badge variant="outline" className={cn("uppercase", severityClass(detail.severity))}>
                  {detail.severity}
                </Badge>
                {detail.protocol && <Badge variant="secondary">{detail.protocol}</Badge>}
                {detail.cvss_score != null && <Badge variant="secondary">CVSS {detail.cvss_score}</Badge>}
                {detail.cve_id && <Badge variant="secondary">{detail.cve_id}</Badge>}
                {detail.cwe_id && <Badge variant="secondary">{detail.cwe_id}</Badge>}
              </div>
              <div className="grid grid-cols-2 gap-2 text-xs text-muted-foreground">
                <div>作者：{detail.author || "—"}</div>
                <div>来源：{detail.source}</div>
                <div>导入：{fmtTime(detail.created_at)}</div>
                <div>更新：{fmtTime(detail.updated_at)}</div>
              </div>
              {detail.description && <p className="text-sm leading-relaxed">{detail.description}</p>}
              {detail.references.length > 0 && (
                <div className="flex flex-wrap gap-2 text-xs">
                  {detail.references.map((r) => (
                    <a key={r} href={r} target="_blank" rel="noreferrer" className="text-primary hover:underline">
                      {r}
                    </a>
                  ))}
                </div>
              )}
              <div className="flex items-center justify-between pt-2">
                <span className="text-xs font-medium text-muted-foreground">nuclei YAML</span>
                <Button variant="outline" size="sm" className="h-7" onClick={copyContent}>
                  <CopyIcon className="size-3.5" />
                  复制
                </Button>
              </div>
              <pre className="max-h-[52vh] overflow-auto rounded-md border bg-muted/40 p-3 font-mono text-xs leading-relaxed">
                {detail.content}
              </pre>
            </div>
          )}
        </SheetContent>
      </Sheet>

      {/* Upload */}
      <Dialog open={uploadOpen} onOpenChange={setUploadOpen}>
        <DialogContent className="sm:max-w-xl">
          <DialogHeader>
            <DialogTitle>上传 nuclei POC</DialogTitle>
            <DialogDescription>
              支持单个 nuclei YAML（.yaml/.yml）。模板 ID 唯一，重复上传会提示冲突。
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-3">
            <div className="flex items-center gap-2">
              <Button variant="outline" size="sm" onClick={() => fileRef.current?.click()}>
                <UploadIcon className="size-4" />
                选择文件
              </Button>
              <span className="truncate text-xs text-muted-foreground">{uploadName || "未选择文件"}</span>
              <input ref={fileRef} type="file" accept=".yaml,.yml" className="hidden" onChange={pickFile} />
            </div>
            <Textarea
              value={uploadText}
              onChange={(e) => setUploadText(e.target.value)}
              placeholder={"id: CVE-2024-xxxx\ninfo:\n  name: Example\n  author: you\n  severity: high\n  tags: demo\nhttp:\n  - method: GET\n    path:\n      - \"{{BaseURL}}/\""}
              className="min-h-64 font-mono text-xs"
            />
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setUploadOpen(false)}>
              取消
            </Button>
            <Button onClick={submitUpload} disabled={uploading}>
              {uploading && <Loader2Icon className="size-4 animate-spin" />}
              导入
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Run */}
      <Dialog open={runOpen} onOpenChange={setRunOpen}>
        <DialogContent className="sm:max-w-3xl">
          <DialogHeader>
            <DialogTitle>执行 POC</DialogTitle>
            <DialogDescription>
              已选 {selectedIds.size} 个模板。将在应用容器内调用 nuclei 直接请求目标，请确认已获得授权。
            </DialogDescription>
          </DialogHeader>
          <div className="grid gap-3 sm:grid-cols-[1fr_120px]">
            <div className="space-y-1.5">
              <Label htmlFor="poc-targets">目标（每行一个，或用空格/逗号分隔）</Label>
              <Textarea
                id="poc-targets"
                value={runTargets}
                onChange={(e) => setRunTargets(e.target.value)}
                placeholder={"https://example.com\n192.168.1.10:8080"}
                className="min-h-28 font-mono text-xs"
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="poc-timeout">超时（秒）</Label>
              <Input
                id="poc-timeout"
                value={runTimeout}
                onChange={(e) => setRunTimeout(e.target.value.replace(/\D/g, ""))}
                className="font-mono"
              />
              <p className="text-xs text-muted-foreground">10–600</p>
            </div>
          </div>
          {runNames.length > 0 && (
            <p className="max-h-16 overflow-y-auto text-xs text-muted-foreground">
              模板：{runNames.slice(0, 8).join("、")}
              {runNames.length > 8 ? ` 等 ${runNames.length} 个` : ""}
            </p>
          )}
          {runResp && (
            <div className="space-y-2 rounded-md border p-3">
              <div className="flex flex-wrap items-center gap-3 text-xs">
                <span className={runResp.ok ? "text-emerald-600" : "text-destructive"}>
                  {runResp.ok ? "执行完成" : "执行异常"}
                </span>
                <span>命中 {runResp.result_count}</span>
                <span>
                  模板 {runResp.template_count} · 目标 {runResp.target_count}
                </span>
                <span>{(runResp.elapsed_ms / 1000).toFixed(1)}s</span>
                {runResp.timed_out && <span className="text-destructive">已超时</span>}
              </div>
              {runResp.error && <p className="text-xs text-destructive">{runResp.error}</p>}
              {runResp.results.length > 0 ? (
                <div className="max-h-64 overflow-auto rounded border">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>模板</TableHead>
                        <TableHead className="w-20">等级</TableHead>
                        <TableHead>命中位置</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {runResp.results.map((r, i) => (
                        <TableRow key={`${r.template_id}-${r.matched_at}-${i}`}>
                          <TableCell className="max-w-64 truncate text-xs">{r.name || r.template_id}</TableCell>
                          <TableCell className="text-xs uppercase">{r.severity}</TableCell>
                          <TableCell className="max-w-80 truncate font-mono text-xs">{r.matched_at || r.host}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </div>
              ) : (
                <p className="text-xs text-muted-foreground">没有命中结果。</p>
              )}
              {(runResp.stderr || (!runResp.ok && runResp.stdout)) && (
                <pre className="max-h-24 overflow-auto whitespace-pre-wrap rounded bg-muted/40 p-2 font-mono text-[11px] text-muted-foreground">
                  {runResp.stderr || runResp.stdout}
                </pre>
              )}
            </div>
          )}
          <DialogFooter>
            <Button variant="outline" onClick={() => setRunOpen(false)}>
              关闭
            </Button>
            <Button onClick={submitRun} disabled={running}>
              {running ? <Loader2Icon className="size-4 animate-spin" /> : <PlayIcon className="size-4" />}
              开始执行
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
