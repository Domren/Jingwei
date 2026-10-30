"use client";

import * as React from "react";

import {
  ChevronLeftIcon,
  ChevronRightIcon,
  CopyIcon,
  DownloadIcon,
  Loader2Icon,
  PlayIcon,
  RadarIcon,
  RotateCcwIcon,
  SearchIcon,
  SquareIcon,
  Trash2Icon,
} from "lucide-react";
import { toast } from "sonner";

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
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Switch } from "@/components/ui/switch";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
import { api } from "@/lib/api";
import type { POCTemplate, ScanAsset, ScanAutoResult, ScanMode, ScanResult, ScanTask } from "@/lib/types";
import { cn } from "@/lib/utils";

import {
  DEEP_KIND_LABEL,
  DeepDetailDialog,
  statusMeta as deepStatusMeta,
  ExploitRecordList,
  WAFResultList,
} from "../deep/_components/deep-ui";

const MODES: { value: ScanMode; label: string; desc: string }[] = [
  { value: "auto", label: "指纹自动匹配", desc: "识别 Web 指纹，自动选择相关 POC" },
  { value: "selected", label: "专项扫描", desc: "手动选择 POC 模板执行" },
  { value: "full", label: "全量扫描", desc: "执行全部已启用的 POC（耗时较长）" },
];

const SEVERITIES = ["low", "medium", "high", "critical"];

function fmtTime(ts?: string) {
  if (!ts) return "—";
  return new Date(ts).toLocaleString("zh-CN", {
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
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

function statusMeta(task: ScanTask): { label: string; className: string } {
  if (task.status === "queued") return { label: "排队中", className: "border-slate-500/30 bg-slate-500/10" };
  if (task.status === "running") {
    const stages: Record<string, string> = {
      discover: "资产发现",
      app: "应用层发现",
      weakpass: "弱口令检测",
      fingerprint: "指纹识别",
      match: "匹配 POC",
      scan: "漏洞扫描",
      baseline: "注入基线",
      auto: "自动利用",
      finalize: "结果入库",
    };
    return { label: stages[task.stage] ?? "执行中", className: "border-sky-500/30 bg-sky-500/10 text-sky-600" };
  }
  if (task.status === "done")
    return { label: "已完成", className: "border-emerald-500/30 bg-emerald-500/10 text-emerald-600" };
  if (task.status === "failed") return { label: "失败", className: "border-red-500/30 bg-red-500/10 text-red-600" };
  return { label: "已停止", className: "border-amber-500/30 bg-amber-500/10 text-amber-600" };
}

function modeLabel(mode: string) {
  return MODES.find((m) => m.value === mode)?.label ?? mode;
}

function assetTypeLabel(type: string) {
  switch (type) {
    case "app":
      return "应用系统";
    case "service":
      return "服务";
    case "ip":
      return "IP";
    default:
      return type;
  }
}

function portsLabel(ports: string) {
  switch (ports) {
    case "web":
      return "Web 常用端口";
    case "top100":
      return "Top100";
    case "top1000":
      return "Top1000 + 常见服务";
    case "full":
      return "全端口";
    default:
      return ports;
  }
}

function num(v: unknown) {
  return typeof v === "number" ? v : 0;
}

function deepSummaryText(summary: Record<string, unknown>): string {
  const parts: string[] = [];
  const push = (label: string, key: string) => {
    const v = summary[key];
    if (typeof v === "number" || typeof v === "string" || typeof v === "boolean") parts.push(`${label} ${v}`);
  };
  push("模板", "templates");
  push("尝试", "attempted");
  push("确认", "confirmed");
  push("命中", "hits");
  push("变形", "variants");
  push("可绕过", "bypassed");
  if (summary.waf_detected === true) {
    const vendor = typeof summary.waf_vendor === "string" && summary.waf_vendor ? summary.waf_vendor : "未知";
    parts.push(`WAF ${vendor}`);
  }
  if (summary.skipped === true) parts.push("未检测到 WAF，已跳过");
  if (summary.upload_status !== undefined) parts.push(`上传 HTTP ${summary.upload_status}`);
  if (summary.webshell_id !== undefined) parts.push(`Webshell #${summary.webshell_id}`);
  return parts.length > 0 ? parts.join(" · ") : "—";
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

export default function ScansPage() {
  const [scans, setScans] = React.useState<ScanTask[]>([]);
  const [total, setTotal] = React.useState(0);
  const [loading, setLoading] = React.useState(false);
  const [refreshKey, setRefreshKey] = React.useState(0);
  const [busyId, setBusyId] = React.useState<number | null>(null);
  const [exportingId, setExportingId] = React.useState<number | null>(null);

  const [createOpen, setCreateOpen] = React.useState(false);
  const [submitting, setSubmitting] = React.useState(false);
  const [name, setName] = React.useState("");
  const [targets, setTargets] = React.useState("");
  const [mode, setMode] = React.useState<ScanMode>("auto");
  const [portsPreset, setPortsPreset] = React.useState("top1000");
  const [customPorts, setCustomPorts] = React.useState("80,443,8080,8443");
  const [minSeverity, setMinSeverity] = React.useState("none");
  const [fingerprint, setFingerprint] = React.useState(true);
  const [createFindings, setCreateFindings] = React.useState(true);
  const [rateLimit, setRateLimit] = React.useState("50");
  const [concurrency, setConcurrency] = React.useState("25");
  const [timeoutSeconds, setTimeoutSeconds] = React.useState("600");
  const [selectedPocs, setSelectedPocs] = React.useState<Set<number>>(new Set());
  const [webshellInject, setWebshellInject] = React.useState(false);
  const [shellUploadPath, setShellUploadPath] = React.useState("");
  const [shellLandPath, setShellLandPath] = React.useState("");
  const [shellType, setShellType] = React.useState("php");
  const [shellPassword, setShellPassword] = React.useState("");
  const [shellField, setShellField] = React.useState("file");

  const [pocQuery, setPocQuery] = React.useState("");
  const [pocQueryQ, setPocQueryQ] = React.useState("");
  const [pocPage, setPocPage] = React.useState(0);
  const [pocs, setPocs] = React.useState<POCTemplate[]>([]);
  const [pocTotal, setPocTotal] = React.useState(0);
  const [pocLoading, setPocLoading] = React.useState(false);
  const POC_PAGE_SIZE = 20;

  const [detailId, setDetailId] = React.useState<number | null>(null);
  const [detailTask, setDetailTask] = React.useState<ScanTask | null>(null);
  const [detailAssets, setDetailAssets] = React.useState<ScanAsset[]>([]);
  const [detailResults, setDetailResults] = React.useState<ScanResult[]>([]);
  const [detailAuto, setDetailAuto] = React.useState<ScanAutoResult | null>(null);
  const [deepDetailId, setDeepDetailId] = React.useState<number | null>(null);
  const [detailLoading, setDetailLoading] = React.useState(false);
  const [detailTab, setDetailTab] = React.useState("assets");

  // biome-ignore lint/correctness/useExhaustiveDependencies: refreshKey is an explicit manual-reload trigger.
  React.useEffect(() => {
    let alive = true;
    async function load() {
      try {
        const r = await api.scans({ limit: 100 });
        if (!alive) return;
        setScans(r.scans ?? []);
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
  }, [refreshKey]);

  React.useEffect(() => {
    const t = setTimeout(() => {
      setPocQueryQ(pocQuery.trim());
      setPocPage(0);
    }, 300);
    return () => clearTimeout(t);
  }, [pocQuery]);

  React.useEffect(() => {
    if (!createOpen || mode !== "selected") return;
    let alive = true;
    setPocLoading(true);
    api
      .pocs({ q: pocQueryQ || undefined, enabled: "true", page: pocPage, size: POC_PAGE_SIZE })
      .then((r) => {
        if (!alive) return;
        setPocs(r.pocs ?? []);
        setPocTotal(r.total ?? 0);
      })
      .catch((e: Error) => alive && toast.error(e.message))
      .finally(() => alive && setPocLoading(false));
    return () => {
      alive = false;
    };
  }, [createOpen, mode, pocPage, pocQueryQ]);

  React.useEffect(() => {
    if (!detailId) return;
    let alive = true;
    let lastStatus = "";

    async function loadOutputs(id: number) {
      try {
        const [a, r] = await Promise.all([api.scanAssets(id), api.scanResults(id)]);
        if (!alive) return;
        setDetailAssets(a.assets ?? []);
        setDetailResults(r.results ?? []);
      } catch (e) {
        if (alive) toast.error((e as Error).message);
      }
    }

    async function loadAuto(id: number) {
      try {
        const auto = await api.scanAuto(id);
        if (!alive) return;
        setDetailAuto(auto);
      } catch {
        // the automatic stage is populated after the scan ends; transient errors are retried
      }
    }

    async function loadAll(id: number) {
      try {
        const t = await api.scan(id);
        if (!alive) return;
        lastStatus = t.status;
        setDetailTask(t);
        await Promise.all([loadOutputs(id), loadAuto(id)]);
      } catch (e) {
        if (alive) toast.error((e as Error).message);
      } finally {
        if (alive) setDetailLoading(false);
      }
    }

    async function poll(id: number) {
      try {
        const t = await api.scan(id);
        if (!alive) return;
        setDetailTask(t);
        const terminal = t.status === "done" || t.status === "failed" || t.status === "canceled";
        if (terminal && lastStatus !== t.status) {
          lastStatus = t.status;
          setRefreshKey((k) => k + 1);
          await loadOutputs(id);
        }
        // Auto exploitation and WAF tasks are queued after the scan finishes,
        // so their results keep changing even when the scan itself is terminal.
        await loadAuto(id);
      } catch {
        // polling errors are transient; the next tick retries
      }
    }

    setDetailLoading(true);
    setDetailTask(null);
    setDetailAssets([]);
    setDetailResults([]);
    setDetailAuto(null);
    setDeepDetailId(null);
    setDetailTab("assets");
    void loadAll(detailId);
    const timer = setInterval(() => poll(detailId), 2500);
    return () => {
      alive = false;
      clearInterval(timer);
    };
  }, [detailId]);

  function resetForm() {
    setName("");
    setTargets("");
    setMode("auto");
    setPortsPreset("top1000");
    setCustomPorts("80,443,8080,8443");
    setMinSeverity("none");
    setFingerprint(true);
    setCreateFindings(true);
    setRateLimit("50");
    setConcurrency("25");
    setTimeoutSeconds("600");
    setSelectedPocs(new Set());
    setWebshellInject(false);
    setShellUploadPath("");
    setShellLandPath("");
    setShellType("php");
    setShellPassword("");
    setShellField("file");
    setPocQuery("");
    setPocPage(0);
  }

  function openCreate() {
    resetForm();
    setCreateOpen(true);
  }

  async function submitCreate() {
    const parsed = splitTargets(targets);
    if (parsed.length === 0) {
      toast.error("请填写至少一个目标（IP / 域名 / CIDR / URL）");
      return;
    }
    if (mode === "selected" && selectedPocs.size === 0) {
      toast.error("专项扫描请至少选择一个 POC");
      return;
    }
    const ports = portsPreset === "custom" ? customPorts.trim() : portsPreset;
    if (!ports) {
      toast.error("请填写端口范围");
      return;
    }
    const uploadPath = shellUploadPath.trim();
    if (webshellInject && !uploadPath.startsWith("/")) {
      toast.error("启用 Webshell 注入时，上传路径必填且必须以 / 开头");
      return;
    }
    if (webshellInject && shellLandPath.trim() && !shellLandPath.trim().startsWith("/")) {
      toast.error("落地路径必须为空或以 / 开头");
      return;
    }
    setSubmitting(true);
    try {
      const task = await api.createScan({
        name: name.trim() || undefined,
        targets: parsed,
        mode,
        poc_ids: mode === "selected" ? Array.from(selectedPocs) : undefined,
        ports,
        min_severity: minSeverity === "none" ? "" : minSeverity,
        fingerprint,
        create_findings: createFindings,
        webshell_inject: webshellInject,
        webshell_params: webshellInject
          ? {
              upload_path: uploadPath,
              land_path: shellLandPath.trim(),
              shell_type: shellType,
              password: shellPassword.trim(),
              field_name: shellField.trim() || "file",
            }
          : undefined,
        rate_limit: Number(rateLimit) || 50,
        concurrency: Number(concurrency) || 25,
        timeout_seconds: Number(timeoutSeconds) || 600,
      });
      toast.success(`已创建扫描任务 #${task.id}`);
      setCreateOpen(false);
      setRefreshKey((k) => k + 1);
    } catch (e) {
      toast.error((e as Error).message);
    } finally {
      setSubmitting(false);
    }
  }

  async function stopTask(task: ScanTask) {
    setBusyId(task.id);
    try {
      await api.cancelScan(task.id);
      toast.success("已请求停止");
      setRefreshKey((k) => k + 1);
    } catch (e) {
      toast.error((e as Error).message);
    } finally {
      setBusyId(null);
    }
  }

  async function rerunTask(task: ScanTask) {
    setBusyId(task.id);
    try {
      await api.rerunScan(task.id);
      toast.success("已重新加入队列");
      setRefreshKey((k) => k + 1);
    } catch (e) {
      toast.error((e as Error).message);
    } finally {
      setBusyId(null);
    }
  }

  async function removeTask(task: ScanTask) {
    if (!window.confirm(`删除扫描任务「${task.name}」及其结果？发现的漏洞会保留。`)) return;
    setBusyId(task.id);
    try {
      await api.deleteScan(task.id);
      toast.success("已删除");
      if (detailId === task.id) setDetailId(null);
      setRefreshKey((k) => k + 1);
    } catch (e) {
      toast.error((e as Error).message);
    } finally {
      setBusyId(null);
    }
  }

  // 导出本漏扫任务命中的全部漏洞(去重后),DOCX 同时落一份到工作区 reports/。
  async function exportReport(task: ScanTask) {
    setExportingId(task.id);
    try {
      const result = await api.exportFindings({
        format: "docx",
        scope: "filtered",
        filters: { scanTaskId: String(task.id) },
      });
      toast.success(`报告已导出：${result.workspacePath || result.filename}`);
    } catch (e) {
      toast.error(`导出失败：${(e as Error).message}`);
    } finally {
      setExportingId(null);
    }
  }

  function togglePoc(id: number, checked: boolean) {
    setSelectedPocs((prev) => {
      const next = new Set(prev);
      if (checked) next.add(id);
      else next.delete(id);
      return next;
    });
  }

  const pocPages = Math.max(1, Math.ceil(pocTotal / POC_PAGE_SIZE));
  const running = scans.some((s) => s.status === "running" || s.status === "queued");
  const detailRunning = detailTask?.status === "running" || detailTask?.status === "queued";

  return (
    <div className="flex min-h-0 flex-1 flex-col gap-4">
      <div className="flex items-center justify-between gap-4">
        <div className="flex items-center gap-2">
          <RadarIcon className="h-5 w-5 text-muted-foreground" />
          <h1 className="text-xl font-semibold tracking-tight">自动化漏扫</h1>
          <Badge variant="secondary">{total}</Badge>
          {running && (
            <span className="flex items-center gap-1 text-xs text-muted-foreground">
              <Loader2Icon className="size-3 animate-spin" />
              扫描中
            </span>
          )}
        </div>
        <Button size="sm" onClick={openCreate}>
          <PlayIcon className="size-4" />
          新建扫描
        </Button>
      </div>

      <p className="text-xs text-muted-foreground">
        无需 LLM：自动探测 IP / CIDR 的开放端口与 Web 指纹并匹配 POC。命中 medium
        及以上的模板会自动复现验证、尝试利用并探测 WAF 绕过（反序列化漏洞自动联动 java-chains），Webshell
        注入可在创建任务时按需开启。结果同步为资产和发现。
      </p>

      <div className="min-h-0 flex-1 overflow-auto rounded-md border">
        <Table>
          <TableHeader className="sticky top-0 z-10 bg-background">
            <TableRow>
              <TableHead>任务</TableHead>
              <TableHead className="w-32">模式</TableHead>
              <TableHead>目标</TableHead>
              <TableHead className="w-32">状态</TableHead>
              <TableHead className="w-56">进度</TableHead>
              <TableHead className="w-28">创建时间</TableHead>
              <TableHead className="w-40">操作</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {loading && scans.length === 0 ? (
              <TableRow>
                <TableCell colSpan={7} className="h-32 text-center text-muted-foreground">
                  <Loader2Icon className="mx-auto size-5 animate-spin" />
                </TableCell>
              </TableRow>
            ) : scans.length === 0 ? (
              <TableRow>
                <TableCell colSpan={7} className="h-32 text-center text-muted-foreground">
                  暂无扫描任务，点击「新建扫描」开始。
                </TableCell>
              </TableRow>
            ) : (
              scans.map((task) => {
                const meta = statusMeta(task);
                const active = task.status === "running" || task.status === "queued";
                return (
                  <TableRow key={task.id}>
                    <TableCell>
                      <button
                        type="button"
                        className="max-w-64 truncate text-left font-medium hover:underline"
                        onClick={() => setDetailId(task.id)}
                      >
                        {task.name}
                      </button>
                      <div className="font-mono text-xs text-muted-foreground">
                        #{task.id} · {portsLabel(task.ports)}
                      </div>
                    </TableCell>
                    <TableCell>
                      <Badge variant="outline">{modeLabel(task.mode)}</Badge>
                    </TableCell>
                    <TableCell>
                      <div className="max-w-56 truncate font-mono text-xs">
                        {task.targets.slice(0, 2).join(", ")}
                        {task.targets.length > 2 ? ` +${task.targets.length - 2}` : ""}
                      </div>
                    </TableCell>
                    <TableCell>
                      <Badge variant="outline" className={cn("gap-1", meta.className)}>
                        {active && <Loader2Icon className="size-3 animate-spin" />}
                        {meta.label}
                      </Badge>
                      {task.error && (
                        <div className="mt-1 max-w-32 truncate text-[11px] text-destructive">{task.error}</div>
                      )}
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground">
                      <span>资产 {num(task.progress.assets ?? task.summary.assets)}</span>
                      <span className="mx-1">·</span>
                      <span>POC {num(task.progress.templates ?? task.summary.templates)}</span>
                      <span className="mx-1">·</span>
                      <span className="text-foreground">结果 {num(task.progress.results ?? task.summary.results)}</span>
                      {num(task.summary.findings) > 0 && (
                        <span className="ml-1 text-orange-600">发现 {num(task.summary.findings)}</span>
                      )}
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground">{fmtTime(task.created_at)}</TableCell>
                    <TableCell>
                      <div className="flex items-center gap-1">
                        <Button variant="ghost" size="sm" className="h-7 px-2" onClick={() => setDetailId(task.id)}>
                          详情
                        </Button>
                        {active ? (
                          <Button
                            variant="ghost"
                            size="icon"
                            className="size-7"
                            disabled={busyId === task.id}
                            onClick={() => stopTask(task)}
                            title="停止"
                          >
                            <SquareIcon className="size-3.5" />
                          </Button>
                        ) : (
                          <Button
                            variant="ghost"
                            size="icon"
                            className="size-7"
                            disabled={busyId === task.id}
                            onClick={() => rerunTask(task)}
                            title="重跑"
                          >
                            <RotateCcwIcon className="size-3.5" />
                          </Button>
                        )}
                        <Button
                          variant="ghost"
                          size="icon"
                          className="size-7 text-destructive"
                          disabled={busyId === task.id || active}
                          onClick={() => removeTask(task)}
                          title="删除"
                        >
                          <Trash2Icon className="size-3.5" />
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                );
              })
            )}
          </TableBody>
        </Table>
      </div>

      {/* Create */}
      <Dialog open={createOpen} onOpenChange={setCreateOpen}>
        <DialogContent className="flex max-h-[92vh] flex-col sm:max-w-3xl">
          <DialogHeader>
            <DialogTitle>新建自动化扫描</DialogTitle>
            <DialogDescription>
              扫描在应用容器内执行，请确认目标已获得授权；命中资产拦截规则的目标会被拒绝。
            </DialogDescription>
          </DialogHeader>
          <div className="min-h-0 flex-1 space-y-4 overflow-y-auto pr-1">
            <div className="grid gap-3 sm:grid-cols-2">
              <div className="space-y-1.5">
                <Label htmlFor="scan-name">任务名称</Label>
                <Input
                  id="scan-name"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="留空自动生成"
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="scan-ports">端口策略</Label>
                <div className="flex gap-2">
                  <Select value={portsPreset} onValueChange={setPortsPreset}>
                    <SelectTrigger id="scan-ports" className="flex-1">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="top1000">Top1000 + 常见服务（推荐）</SelectItem>
                      <SelectItem value="web">Web 常用端口</SelectItem>
                      <SelectItem value="top100">Top 100</SelectItem>
                      <SelectItem value="full">全端口（1-65535）</SelectItem>
                      <SelectItem value="custom">自定义</SelectItem>
                    </SelectContent>
                  </Select>
                  {portsPreset === "custom" && (
                    <Input
                      value={customPorts}
                      onChange={(e) => setCustomPorts(e.target.value)}
                      className="w-40 font-mono"
                      placeholder="80,443,8000-8100"
                    />
                  )}
                </div>
              </div>
            </div>

            <div className="space-y-1.5">
              <Label htmlFor="scan-targets">目标（每行一个，或空格/逗号分隔）</Label>
              <Textarea
                id="scan-targets"
                value={targets}
                onChange={(e) => setTargets(e.target.value)}
                placeholder={"192.168.1.0/24\nhttps://example.com\nexample.org"}
                className="min-h-24 font-mono text-xs"
              />
              <p className="text-xs text-muted-foreground">
                支持 IPv4、CIDR（最大 /24）、域名和 http/https URL；单任务最多 256 个 IP。
              </p>
            </div>

            <div className="space-y-1.5">
              <Label>扫描模式</Label>
              <div className="grid gap-2 sm:grid-cols-3">
                {MODES.map((m) => (
                  <button
                    key={m.value}
                    type="button"
                    onClick={() => setMode(m.value)}
                    className={cn(
                      "rounded-md border p-3 text-left transition-colors",
                      mode === m.value ? "border-primary bg-primary/5" : "hover:bg-muted/50",
                    )}
                  >
                    <div className="text-sm font-medium">{m.label}</div>
                    <div className="mt-1 text-[11px] leading-relaxed text-muted-foreground">{m.desc}</div>
                  </button>
                ))}
              </div>
            </div>

            {mode === "auto" && (
              <div className="flex items-center justify-between rounded-md border p-3">
                <div>
                  <div className="text-sm">Web 指纹匹配</div>
                  <div className="text-[11px] text-muted-foreground">
                    根据探测到的技术指纹自动筛选 POC（自动模式始终开启）
                  </div>
                </div>
                <Switch checked={fingerprint} onCheckedChange={setFingerprint} disabled />
              </div>
            )}

            {mode === "selected" && (
              <div className="space-y-2 rounded-md border p-3">
                <div className="flex items-center justify-between gap-2">
                  <Label>选择 POC</Label>
                  <span className="text-xs text-muted-foreground">已选 {selectedPocs.size} 个</span>
                </div>
                <div className="relative">
                  <SearchIcon className="absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-muted-foreground" />
                  <Input
                    value={pocQuery}
                    onChange={(e) => setPocQuery(e.target.value)}
                    placeholder="搜索 POC 名称 / ID / CVE / 标签..."
                    className="h-8 pl-8"
                  />
                </div>
                <div className="max-h-56 overflow-y-auto rounded border">
                  <Table>
                    <TableBody>
                      {pocLoading ? (
                        <TableRow>
                          <TableCell className="h-16 text-center">
                            <Loader2Icon className="mx-auto size-4 animate-spin" />
                          </TableCell>
                        </TableRow>
                      ) : pocs.length === 0 ? (
                        <TableRow>
                          <TableCell className="h-16 text-center text-xs text-muted-foreground">
                            没有匹配的已启用 POC
                          </TableCell>
                        </TableRow>
                      ) : (
                        pocs.map((p) => (
                          <TableRow key={p.id}>
                            <TableCell className="w-10">
                              <Checkbox
                                checked={selectedPocs.has(p.id)}
                                onCheckedChange={(v) => togglePoc(p.id, v === true)}
                                aria-label={`选择 ${p.name}`}
                              />
                            </TableCell>
                            <TableCell>
                              <div className="max-w-96 truncate text-xs font-medium">{p.name}</div>
                              <div className="max-w-96 truncate font-mono text-[11px] text-muted-foreground">
                                {p.template_id}
                              </div>
                            </TableCell>
                            <TableCell className="w-20">
                              <Badge
                                variant="outline"
                                className={cn("text-[10px] uppercase", severityClass(p.severity))}
                              >
                                {p.severity}
                              </Badge>
                            </TableCell>
                          </TableRow>
                        ))
                      )}
                    </TableBody>
                  </Table>
                </div>
                <div className="flex items-center justify-end gap-2 text-xs text-muted-foreground">
                  <span>
                    {pocTotal} 个 · {pocPage + 1}/{pocPages}
                  </span>
                  <Button
                    variant="outline"
                    size="icon"
                    className="size-7"
                    disabled={pocPage <= 0 || pocLoading}
                    onClick={() => setPocPage((p) => Math.max(0, p - 1))}
                  >
                    <ChevronLeftIcon className="size-3.5" />
                  </Button>
                  <Button
                    variant="outline"
                    size="icon"
                    className="size-7"
                    disabled={pocPage + 1 >= pocPages || pocLoading}
                    onClick={() => setPocPage((p) => p + 1)}
                  >
                    <ChevronRightIcon className="size-3.5" />
                  </Button>
                </div>
              </div>
            )}

            <div className="grid gap-3 sm:grid-cols-3">
              <div className="space-y-1.5">
                <Label>最低危险等级</Label>
                <Select value={minSeverity} onValueChange={setMinSeverity}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="none">不限</SelectItem>
                    {SEVERITIES.map((s) => (
                      <SelectItem key={s} value={s}>
                        {s}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-1.5">
                <Label>限速（请求/秒）</Label>
                <Input
                  value={rateLimit}
                  onChange={(e) => setRateLimit(e.target.value.replace(/\D/g, ""))}
                  className="font-mono"
                />
              </div>
              <div className="space-y-1.5">
                <Label>并发</Label>
                <Input
                  value={concurrency}
                  onChange={(e) => setConcurrency(e.target.value.replace(/\D/g, ""))}
                  className="font-mono"
                />
              </div>
            </div>

            <div className="grid gap-3 sm:grid-cols-2">
              <div className="space-y-1.5">
                <Label>总超时（秒）</Label>
                <Input
                  value={timeoutSeconds}
                  onChange={(e) => setTimeoutSeconds(e.target.value.replace(/\D/g, ""))}
                  className="font-mono"
                />
                <p className="text-[11px] text-muted-foreground">30–7200 秒</p>
              </div>
              <div className="flex items-center justify-between rounded-md border p-3">
                <div>
                  <div className="text-sm">结果写入「发现」</div>
                  <div className="text-[11px] text-muted-foreground">low 及以上等级自动生成漏洞发现</div>
                </div>
                <Switch checked={createFindings} onCheckedChange={setCreateFindings} />
              </div>
            </div>

            <div className="rounded-md border">
              <div className="flex items-center justify-between gap-3 p-3">
                <div>
                  <div className="text-sm">尝试 Webshell 注入</div>
                  <div className="text-[11px] text-muted-foreground">
                    仅对 high 及以上命中自动尝试；需填写已知的上传接口，密码留空则自动生成
                  </div>
                </div>
                <Switch checked={webshellInject} onCheckedChange={setWebshellInject} />
              </div>
              {webshellInject && (
                <div className="grid gap-3 border-t p-3 sm:grid-cols-2">
                  <div className="space-y-1.5">
                    <Label htmlFor="shell-upload">上传接口路径 *</Label>
                    <Input
                      id="shell-upload"
                      value={shellUploadPath}
                      onChange={(e) => setShellUploadPath(e.target.value)}
                      placeholder="/uploads/shell.php"
                      className="font-mono"
                    />
                  </div>
                  <div className="space-y-1.5">
                    <Label htmlFor="shell-land">落地访问路径（可选）</Label>
                    <Input
                      id="shell-land"
                      value={shellLandPath}
                      onChange={(e) => setShellLandPath(e.target.value)}
                      placeholder="/upload/shell.php"
                      className="font-mono"
                    />
                  </div>
                  <div className="space-y-1.5">
                    <Label>脚本类型</Label>
                    <Select value={shellType} onValueChange={setShellType}>
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="php">PHP</SelectItem>
                        <SelectItem value="jsp">JSP</SelectItem>
                        <SelectItem value="aspx">ASPX</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="space-y-1.5">
                    <Label htmlFor="shell-password">连接密码</Label>
                    <Input
                      id="shell-password"
                      value={shellPassword}
                      onChange={(e) => setShellPassword(e.target.value)}
                      placeholder="留空自动生成"
                      className="font-mono"
                    />
                  </div>
                  <div className="space-y-1.5">
                    <Label htmlFor="shell-field">上传字段名</Label>
                    <Input
                      id="shell-field"
                      value={shellField}
                      onChange={(e) => setShellField(e.target.value)}
                      placeholder="file"
                      className="font-mono"
                    />
                  </div>
                </div>
              )}
            </div>
          </div>
          <DialogFooter className="pt-2">
            <Button variant="outline" onClick={() => setCreateOpen(false)}>
              取消
            </Button>
            <Button onClick={submitCreate} disabled={submitting}>
              {submitting ? <Loader2Icon className="size-4 animate-spin" /> : <PlayIcon className="size-4" />}
              创建并开始
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Detail */}
      <Sheet open={detailId !== null} onOpenChange={(open) => !open && setDetailId(null)}>
        <SheetContent className="flex w-full! flex-col gap-0 sm:max-w-5xl!">
          <SheetHeader>
            <SheetTitle className="pr-8">{detailTask?.name ?? `扫描任务 #${detailId ?? ""}`}</SheetTitle>
            <SheetDescription className="font-mono text-xs">
              {detailTask
                ? `${detailTask.targets.join(", ")} · ${modeLabel(detailTask.mode)} · ${fmtTime(detailTask.created_at)}`
                : ""}
            </SheetDescription>
          </SheetHeader>
          {detailLoading || !detailTask ? (
            <div className="flex flex-1 items-center justify-center">
              <Loader2Icon className="size-5 animate-spin text-muted-foreground" />
            </div>
          ) : (
            <div className="flex min-h-0 flex-1 flex-col gap-3 overflow-y-auto px-4 pb-4">
              <div className="flex flex-wrap items-center gap-2">
                <Badge variant="outline" className={cn("gap-1", statusMeta(detailTask).className)}>
                  {detailRunning && <Loader2Icon className="size-3 animate-spin" />}
                  {statusMeta(detailTask).label}
                </Badge>
                <Badge variant="secondary">资产 {num(detailTask.summary.assets)}</Badge>
                <Badge variant="secondary">端口 {num(detailTask.summary.open_ports)}</Badge>
                <Badge variant="secondary">Web {num(detailTask.summary.services)}</Badge>
                {num(detailTask.summary.app_systems) > 0 && (
                  <Badge variant="secondary">应用层系统 {num(detailTask.summary.app_systems)}</Badge>
                )}
                {num(detailTask.summary.weak_pass_targets) > 0 && (
                  <Badge variant="secondary">弱口令页面 {num(detailTask.summary.weak_pass_targets)}</Badge>
                )}
                <Badge variant="secondary">POC {num(detailTask.summary.templates)}</Badge>
                <Badge variant="secondary">结果 {num(detailTask.summary.results)}</Badge>
                <Badge variant="outline" className={num(detailTask.summary.findings) > 0 ? severityClass("high") : ""}>
                  发现 {num(detailTask.summary.findings)}
                </Badge>
                <div className="ml-auto flex items-center gap-2">
                  <Button
                    variant="outline"
                    size="sm"
                    className="h-7"
                    disabled={exportingId === detailTask.id || num(detailTask.summary.findings) === 0}
                    onClick={() => void exportReport(detailTask)}
                  >
                    {exportingId === detailTask.id ? (
                      <Loader2Icon className="size-3.5 animate-spin" />
                    ) : (
                      <DownloadIcon className="size-3.5" />
                    )}
                    导出报告
                  </Button>
                  {detailRunning ? (
                    <Button variant="outline" size="sm" className="h-7" onClick={() => stopTask(detailTask)}>
                      <SquareIcon className="size-3.5" />
                      停止
                    </Button>
                  ) : (
                    <Button variant="outline" size="sm" className="h-7" onClick={() => rerunTask(detailTask)}>
                      <RotateCcwIcon className="size-3.5" />
                      重跑
                    </Button>
                  )}
                </div>
              </div>
              {detailTask.error && <p className="text-xs text-destructive">{detailTask.error}</p>}

              <Tabs value={detailTab} onValueChange={setDetailTab} className="flex min-h-0 flex-1 flex-col">
                <TabsList>
                  <TabsTrigger value="assets">资产 ({detailAssets.length})</TabsTrigger>
                  <TabsTrigger value="results">结果 ({detailResults.length})</TabsTrigger>
                  <TabsTrigger value="auto">自动利用 ({detailAuto?.tasks.length ?? 0})</TabsTrigger>
                  <TabsTrigger value="log">日志</TabsTrigger>
                </TabsList>
                <TabsContent value="assets" className="min-h-0 flex-1 overflow-auto rounded-md border">
                  <Table>
                    <TableHeader className="sticky top-0 z-10 bg-background">
                      <TableRow>
                        <TableHead className="w-20">类型</TableHead>
                        <TableHead>主机 / URL</TableHead>
                        <TableHead className="w-16">状态</TableHead>
                        <TableHead>标题</TableHead>
                        <TableHead>指纹 / 备注</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {detailAssets.length === 0 ? (
                        <TableRow>
                          <TableCell colSpan={5} className="h-24 text-center text-xs text-muted-foreground">
                            {detailRunning ? "资产发现中..." : "没有资产记录"}
                          </TableCell>
                        </TableRow>
                      ) : (
                        detailAssets.map((a) => (
                          <TableRow key={`${a.asset_type}-${a.asset_id}`}>
                            <TableCell className="text-xs uppercase text-muted-foreground">
                              {assetTypeLabel(a.asset_type)}
                            </TableCell>
                            <TableCell className="max-w-80 truncate font-mono text-xs">{a.url || a.host}</TableCell>
                            <TableCell className="text-xs">{a.status_code ?? "—"}</TableCell>
                            <TableCell className="max-w-56 truncate text-xs">{a.page_title || "—"}</TableCell>
                            <TableCell>
                              <div className="flex max-w-64 flex-wrap gap-1">
                                {a.technologies.slice(0, 5).map((t) => (
                                  <Badge key={t} variant="secondary" className="text-[10px]">
                                    {t}
                                  </Badge>
                                ))}
                                {a.note && <span className="truncate text-[11px] text-muted-foreground">{a.note}</span>}
                              </div>
                            </TableCell>
                          </TableRow>
                        ))
                      )}
                    </TableBody>
                  </Table>
                </TabsContent>
                <TabsContent value="results" className="min-h-0 flex-1 overflow-auto rounded-md border">
                  <Table>
                    <TableHeader className="sticky top-0 z-10 bg-background">
                      <TableRow>
                        <TableHead className="w-24">等级</TableHead>
                        <TableHead>模板</TableHead>
                        <TableHead>命中位置</TableHead>
                        <TableHead className="w-28">发现</TableHead>
                        <TableHead className="w-10" />
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {detailResults.length === 0 ? (
                        <TableRow>
                          <TableCell colSpan={5} className="h-24 text-center text-xs text-muted-foreground">
                            {detailRunning ? "扫描中..." : "没有命中结果"}
                          </TableCell>
                        </TableRow>
                      ) : (
                        detailResults.map((r) => (
                          <TableRow key={r.id}>
                            <TableCell>
                              <Badge
                                variant="outline"
                                className={cn("text-[10px] uppercase", severityClass(r.severity))}
                              >
                                {r.severity || "unknown"}
                              </Badge>
                            </TableCell>
                            <TableCell>
                              <div className="max-w-72 truncate text-xs font-medium">{r.name || r.template_id}</div>
                              <div className="max-w-72 truncate font-mono text-[11px] text-muted-foreground">
                                {r.template_id}
                              </div>
                            </TableCell>
                            <TableCell className="max-w-72 truncate font-mono text-xs">
                              {r.matched_at || r.host}
                            </TableCell>
                            <TableCell className="text-xs text-muted-foreground">
                              {r.finding_id
                                ? `#${r.finding_id}${r.finding_status ? ` · ${r.finding_status}` : ""}`
                                : "—"}
                            </TableCell>
                            <TableCell>
                              {r.curl_command && (
                                <Button
                                  variant="ghost"
                                  size="icon"
                                  className="size-7"
                                  title="复制复现命令"
                                  onClick={async () => {
                                    try {
                                      await navigator.clipboard.writeText(r.curl_command ?? "");
                                      toast.success("复现命令已复制");
                                    } catch {
                                      toast.error("复制失败");
                                    }
                                  }}
                                >
                                  <CopyIcon className="size-3.5" />
                                </Button>
                              )}
                            </TableCell>
                          </TableRow>
                        ))
                      )}
                    </TableBody>
                  </Table>
                </TabsContent>
                <TabsContent value="auto" className="min-h-0 flex-1 overflow-auto rounded-md border">
                  <div className="flex flex-col gap-3 p-3">
                    <div className="flex flex-wrap items-center gap-2">
                      <Badge variant="secondary">自动主机 {num(detailTask.summary.auto_hosts)}</Badge>
                      <Badge variant="secondary">模板 {num(detailTask.summary.auto_templates)}</Badge>
                      <Badge variant="secondary">基线注入点 {num(detailTask.summary.baseline_points)}</Badge>
                      <Badge variant="secondary">基线任务 {num(detailTask.summary.baseline_tasks)}</Badge>
                      <Badge
                        variant="outline"
                        className={num(detailTask.summary.weak_pass_found) > 0 ? severityClass("high") : undefined}
                      >
                        弱口令命中 {num(detailTask.summary.weak_pass_found)}
                      </Badge>
                      <Badge
                        variant="outline"
                        className={num(detailTask.summary.auto_webshell) > 0 ? severityClass("high") : undefined}
                      >
                        Webshell 尝试 {num(detailTask.summary.auto_webshell)}
                      </Badge>
                      <Badge variant="secondary">跳过 low/info {num(detailTask.summary.auto_skipped)}</Badge>
                      <span className="text-xs text-muted-foreground">
                        证据 {detailAuto?.records.length ?? 0} · WAF 结果 {detailAuto?.waf_results.length ?? 0}
                      </span>
                    </div>

                    {(detailAuto?.tasks.length ?? 0) === 0 ? (
                      <div className="rounded-md border border-dashed py-8 text-center text-xs text-muted-foreground">
                        {detailRunning
                          ? "扫描完成后将自动验证 / 利用命中结果"
                          : "没有自动任务：可能没有 medium 及以上命中、页面未枚举出参数位置，或任务未正常完成"}
                      </div>
                    ) : (
                      <div className="flex flex-col gap-2">
                        {(detailAuto?.tasks ?? []).map((t) => {
                          const meta = deepStatusMeta(t);
                          return (
                            <div key={t.id} className="rounded-md border px-3 py-2">
                              <div className="flex flex-wrap items-center gap-2">
                                <span className="font-mono text-xs text-muted-foreground">#{t.id}</span>
                                <Badge variant="outline">{DEEP_KIND_LABEL[t.kind] ?? t.kind}</Badge>
                                <Badge variant="outline" className={cn("gap-1", meta.className)}>
                                  {(t.status === "running" || t.status === "queued") && (
                                    <Loader2Icon className="size-3 animate-spin" />
                                  )}
                                  {meta.label}
                                </Badge>
                                <Button
                                  variant="ghost"
                                  size="sm"
                                  className="ml-auto h-7 px-2"
                                  onClick={() => setDeepDetailId(t.id)}
                                >
                                  详情
                                </Button>
                              </div>
                              <div className="mt-1 truncate font-mono text-xs text-muted-foreground" title={t.target}>
                                {t.target}
                              </div>
                              <div className="mt-0.5 text-xs text-muted-foreground">
                                {t.error ? (
                                  <span className="text-destructive">{t.error}</span>
                                ) : (
                                  deepSummaryText(t.summary)
                                )}
                              </div>
                            </div>
                          );
                        })}
                      </div>
                    )}

                    <div className="grid gap-4 xl:grid-cols-2">
                      <div className="flex flex-col gap-2">
                        <div className="text-sm font-medium">验证 / 利用证据</div>
                        <ExploitRecordList records={detailAuto?.records ?? []} />
                      </div>
                      <div className="flex flex-col gap-2">
                        <div className="text-sm font-medium">WAF 探测与绕过</div>
                        <div className="overflow-x-auto rounded-md border">
                          <WAFResultList results={detailAuto?.waf_results ?? []} />
                        </div>
                      </div>
                    </div>
                  </div>
                </TabsContent>
                <TabsContent value="log" className="min-h-0 flex-1 overflow-auto rounded-md border">
                  <pre className="whitespace-pre-wrap p-3 font-mono text-[11px] leading-relaxed text-muted-foreground">
                    {detailTask.log || "暂无日志"}
                  </pre>
                </TabsContent>
              </Tabs>
            </div>
          )}
        </SheetContent>
      </Sheet>

      <DeepDetailDialog
        taskId={deepDetailId}
        open={deepDetailId !== null}
        onOpenChange={(open) => !open && setDeepDetailId(null)}
        onChanged={() => setRefreshKey((k) => k + 1)}
      />
    </div>
  );
}
