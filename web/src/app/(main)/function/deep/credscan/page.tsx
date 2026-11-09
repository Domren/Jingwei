"use client";

import * as React from "react";

import {
  CopyIcon,
  KeyRoundIcon,
  Loader2Icon,
  LockKeyholeIcon,
  PlayIcon,
  RefreshCwIcon,
  SquareIcon,
  Trash2Icon,
} from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
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
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Textarea } from "@/components/ui/textarea";
import { api } from "@/lib/api";
import type { CredBuiltinDictInfo, CredDict, CredProtocolInfo, CredResult, CredTask } from "@/lib/types";
import { cn } from "@/lib/utils";

import { fmtTime } from "../_components/deep-ui";

// 弱口令检测：只测出并记下「某资产的某协议存在某组可用凭据」这条事实。
// 页面刻意不提供任何「一键登录 / 自动复用」入口——用不用这组凭据由人决定。

const OUTCOME_META: Record<string, { label: string; className: string }> = {
  hit: { label: "命中", className: "border-red-500/30 bg-red-500/10 text-red-600 dark:text-red-400" },
  deny: { label: "拒绝", className: "border-emerald-500/30 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400" },
  unreachable: { label: "连不上", className: "border-slate-500/30 bg-slate-500/10 text-slate-600 dark:text-slate-400" },
  locked: { label: "账号锁定", className: "border-amber-500/30 bg-amber-500/10 text-amber-600 dark:text-amber-400" },
  inconclusive: { label: "不可判定", className: "border-sky-500/30 bg-sky-500/10 text-sky-600 dark:text-sky-400" },
  unsupported: {
    label: "暂不支持",
    className: "border-violet-500/30 bg-violet-500/10 text-violet-600 dark:text-violet-400",
  },
};

const OUTCOME_ORDER = ["hit", "deny", "unreachable", "locked", "inconclusive", "unsupported"];

const BUDGETS = [
  { value: "300", label: "5 分钟" },
  { value: "600", label: "10 分钟（默认）" },
  { value: "1800", label: "30 分钟" },
  { value: "3600", label: "1 小时" },
];

function statusMeta(task: CredTask): { label: string; className: string } {
  if (task.status === "queued") return { label: "排队中", className: "border-slate-500/30 bg-slate-500/10" };
  if (task.status === "running") {
    const stages: Record<string, string> = { planning: "规划端点", testing: "认证测试" };
    return {
      label: stages[task.stage] ?? "运行中",
      className: "border-sky-500/30 bg-sky-500/10 text-sky-600 dark:text-sky-400",
    };
  }
  if (task.status === "done")
    return {
      label: "已完成",
      className: "border-emerald-500/30 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400",
    };
  if (task.status === "canceled")
    return { label: "已取消", className: "border-amber-500/30 bg-amber-500/10 text-amber-600 dark:text-amber-400" };
  return { label: "失败", className: "border-destructive/40 bg-destructive/10 text-destructive" };
}

function elapsedText(task: CredTask): string {
  if (!task.started_at) return "—";
  const end = task.finished_at ? new Date(task.finished_at).getTime() : Date.now();
  const secs = Math.max(0, Math.round((end - new Date(task.started_at).getTime()) / 1000));
  if (secs < 60) return `${secs} 秒`;
  return `${Math.floor(secs / 60)} 分 ${secs % 60} 秒`;
}

function hintCount(task: CredTask, key: string): number {
  const v = task.summary[key] ?? task.progress[key];
  return typeof v === "number" ? v : 0;
}

export default function CredscanPage() {
  const [tasks, setTasks] = React.useState<CredTask[]>([]);
  const [loading, setLoading] = React.useState(true);
  const [protocols, setProtocols] = React.useState<CredProtocolInfo[]>([]);
  const [dictionaries, setDictionaries] = React.useState<string[]>(["builtin"]);
  const [dicts, setDicts] = React.useState<CredDict[]>([]);
  // 内置字典的版本与分档：让界面能回答「这一版到底试了哪些、覆盖到哪」。
  const [builtinDict, setBuiltinDict] = React.useState<CredBuiltinDictInfo | null>(null);
  const [dictOpen, setDictOpen] = React.useState(false);
  const [dictName, setDictName] = React.useState("");
  const [dictContent, setDictContent] = React.useState("");
  const [dictBusy, setDictBusy] = React.useState(false);

  const [createOpen, setCreateOpen] = React.useState(false);
  const [name, setName] = React.useState("");
  const [targets, setTargets] = React.useState("");
  const [picked, setPicked] = React.useState<Set<string>>(new Set());
  const [dictProfile, setDictProfile] = React.useState("builtin");
  const [concurrency, setConcurrency] = React.useState("16");
  const [rateLimit, setRateLimit] = React.useState("20");
  const [budget, setBudget] = React.useState("600");
  const [submitting, setSubmitting] = React.useState(false);

  const [detailId, setDetailId] = React.useState<number | null>(null);
  const [detail, setDetail] = React.useState<{ task: CredTask; counts: Record<string, number> } | null>(null);
  const [results, setResults] = React.useState<CredResult[]>([]);
  const [resultTotal, setResultTotal] = React.useState(0);
  const [outcome, setOutcome] = React.useState("all");
  const [evidence, setEvidence] = React.useState<CredResult | null>(null);

  const loadTasks = React.useCallback(async () => {
    try {
      const r = await api.credTasks();
      setTasks(r.tasks ?? []);
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "读取任务失败");
    } finally {
      setLoading(false);
    }
  }, []);

  const loadProtocols = React.useCallback(async () => {
    try {
      const r = await api.credProtocols();
      setProtocols(r.protocols ?? []);
      setDicts(r.dicts ?? []);
      setBuiltinDict(r.builtin_dict ?? null);
      if (r.dictionaries?.length) {
        setDictionaries(r.dictionaries);
        setDictProfile((prev) => (r.dictionaries.includes(prev) ? prev : r.dictionaries[0]));
      }
    } catch {
      toast.error("读取协议清单失败");
    }
  }, []);

  React.useEffect(() => {
    void loadTasks();
    void loadProtocols();
  }, [loadTasks, loadProtocols]);

  const anyActive = tasks.some((t) => t.status === "running" || t.status === "queued");
  React.useEffect(() => {
    if (!anyActive) return;
    const timer = window.setInterval(() => void loadTasks(), 2500);
    return () => window.clearInterval(timer);
  }, [anyActive, loadTasks]);

  const loadDetail = React.useCallback(async (id: number, oc: string) => {
    try {
      const d = await api.credTask(id);
      setDetail(d);
      const page = await api.credTaskResults(id, { outcome: oc === "all" ? "" : oc, limit: 500 });
      setResults(page.results ?? []);
      setResultTotal(page.total ?? 0);
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "读取详情失败");
    }
  }, []);

  const detailActive = detail?.task.status === "running" || detail?.task.status === "queued";
  React.useEffect(() => {
    if (detailId == null) return;
    void loadDetail(detailId, outcome);
    if (!detailActive) return;
    const timer = window.setInterval(() => void loadDetail(detailId, outcome), 2000);
    return () => window.clearInterval(timer);
  }, [detailId, outcome, detailActive, loadDetail]);

  const supported = protocols.filter((p) => p.supported);
  const unsupported = protocols.filter((p) => !p.supported);

  function openCreate() {
    setName("");
    setTargets("");
    setPicked(new Set(supported.slice(0, 3).map((p) => p.name)));
    setDictProfile(dictionaries[0] ?? "builtin");
    setBudget("600");
    setCreateOpen(true);
  }

  function toggleProtocol(name: string) {
    setPicked((prev) => {
      const next = new Set(prev);
      if (next.has(name)) next.delete(name);
      else next.add(name);
      return next;
    });
  }

  async function importDict() {
    if (!dictName.trim() || !dictContent.trim()) {
      toast.error("字典名与内容都要填");
      return;
    }
    setDictBusy(true);
    try {
      const d = await api.saveCredDict(dictName.trim(), dictContent);
      toast.success(`字典 ${d.name} 已导入（${d.entry_count} 组）`);
      setDictName("");
      setDictContent("");
      setDictProfile(d.name);
      await loadProtocols();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "导入失败");
    } finally {
      setDictBusy(false);
    }
  }

  async function removeDict(name: string) {
    try {
      await api.deleteCredDict(name);
      toast.success(`字典 ${name} 已删除`);
      await loadProtocols();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "删除失败");
    }
  }

  async function submitCreate() {
    const list = targets
      .split(/[\s,，]+/)
      .map((s) => s.trim())
      .filter(Boolean);
    if (list.length === 0) {
      toast.error("至少填写一个目标");
      return;
    }
    if (picked.size === 0) {
      toast.error("至少勾选一个协议");
      return;
    }
    setSubmitting(true);
    try {
      const task = await api.createCredTask({
        name: name.trim(),
        targets: list,
        protocols: Array.from(picked),
        dict_profile: dictProfile,
        options: {
          concurrency: Number(concurrency) || 0,
          rate_limit: Number(rateLimit) || 0,
          budget_seconds: Number(budget) || 600,
        },
      });
      toast.success(`任务 #${task.id} 已进入队列`);
      setCreateOpen(false);
      await loadTasks();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "创建任务失败");
    } finally {
      setSubmitting(false);
    }
  }

  async function downloadReport(id: number, internal: boolean) {
    try {
      const name = await api.downloadCredReport(id, internal);
      toast.success(`已下载 ${name}`);
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "下载报告失败");
    }
  }

  async function cancelTask(id: number) {
    try {
      await api.cancelCredTask(id);
      toast.success("已请求停止");
      await loadTasks();
      if (detailId === id) await loadDetail(id, outcome);
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "取消失败");
    }
  }

  async function removeTask(id: number) {
    try {
      await api.deleteCredTask(id);
      toast.success("已删除");
      if (detailId === id) setDetailId(null);
      await loadTasks();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "删除失败");
    }
  }

  return (
    <div className="flex min-h-0 flex-1 flex-col gap-4">
      <div className="flex items-center justify-between gap-4">
        <div className="flex items-center gap-2">
          <LockKeyholeIcon className="h-5 w-5 text-muted-foreground" />
          <h1 className="font-semibold text-xl tracking-tight">弱口令检测</h1>
          <Badge variant="secondary">{tasks.length}</Badge>
          {anyActive && (
            <span className="flex items-center gap-1 text-muted-foreground text-xs">
              <Loader2Icon className="size-3 animate-spin" />
              检测中
            </span>
          )}
        </div>
        <div className="flex items-center gap-2">
          <Button size="sm" variant="outline" onClick={() => setDictOpen(true)}>
            字典
          </Button>
          <Button size="sm" variant="outline" onClick={() => void loadTasks()}>
            <RefreshCwIcon className="size-4" />
            刷新
          </Button>
          <Button size="sm" onClick={openCreate}>
            <PlayIcon className="size-4" />
            新建检测
          </Button>
        </div>
      </div>

      <p className="text-muted-foreground text-xs">
        按协议逐组验证口令，结果分六态：命中 / 明确拒绝 / 连不上 / 账号锁定 / 不可判定 / 暂不支持。
        「拒绝」是已验证该口令不可用，「不可判定」是没测出来——两者在报告里不能混。默认端口表只决定测哪个端口，
        协议必须先经握手确认；账号一旦被提示锁定立即停手。本页只产出事实，不自动登录、不自动复用凭据。
      </p>

      <div className="min-h-0 flex-1 overflow-auto rounded-md border">
        <Table>
          <TableHeader className="sticky top-0 z-10 bg-background">
            <TableRow>
              <TableHead>任务</TableHead>
              <TableHead className="w-40">协议</TableHead>
              <TableHead className="w-28">状态</TableHead>
              <TableHead className="w-56">进度</TableHead>
              <TableHead className="w-20">命中</TableHead>
              <TableHead className="w-24">用时</TableHead>
              <TableHead className="w-32">创建时间</TableHead>
              <TableHead className="w-44">操作</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {loading && tasks.length === 0 ? (
              <TableRow>
                <TableCell colSpan={8} className="h-32 text-center text-muted-foreground">
                  <Loader2Icon className="mx-auto size-5 animate-spin" />
                </TableCell>
              </TableRow>
            ) : tasks.length === 0 ? (
              <TableRow>
                <TableCell colSpan={8} className="h-32 text-center text-muted-foreground">
                  暂无弱口令检测任务，点击「新建检测」开始。
                </TableCell>
              </TableRow>
            ) : (
              tasks.map((task) => {
                const meta = statusMeta(task);
                const hit = hintCount(task, "hit");
                const done = hintCount(task, "deny") + hintCount(task, "unreachable") + hintCount(task, "inconclusive");
                return (
                  <TableRow key={task.id}>
                    <TableCell>
                      <button
                        type="button"
                        className="max-w-64 truncate text-left font-medium hover:underline"
                        onClick={() => setDetailId(task.id)}
                      >
                        {task.name || `任务 #${task.id}`}
                      </button>
                      <div className="max-w-64 truncate text-muted-foreground text-xs">{task.targets.join("、")}</div>
                      {task.error && (
                        <div className="mt-1 max-w-64 truncate text-[11px] text-destructive">{task.error}</div>
                      )}
                    </TableCell>
                    <TableCell className="font-mono text-xs">{task.protocols.join(", ")}</TableCell>
                    <TableCell>
                      <Badge variant="outline" className={cn("gap-1", meta.className)}>
                        {task.status === "running" && <Loader2Icon className="size-3 animate-spin" />}
                        {meta.label}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-muted-foreground text-xs">
                      {task.progress?.endpoints != null
                        ? `${task.progress.endpoints} 个端点 · ${task.progress.attempts ?? 0} 次尝试`
                        : "—"}
                      {done > 0 && <div>已判定 {done} 行</div>}
                    </TableCell>
                    <TableCell>
                      <span
                        className={cn(
                          "font-mono text-sm",
                          hit > 0 ? "font-semibold text-red-600 dark:text-red-400" : "text-muted-foreground",
                        )}
                      >
                        {hit}
                      </span>
                    </TableCell>
                    <TableCell className="text-muted-foreground text-xs">{elapsedText(task)}</TableCell>
                    <TableCell className="text-muted-foreground text-xs">{fmtTime(task.created_at)}</TableCell>
                    <TableCell>
                      <div className="flex items-center gap-1">
                        <Button size="sm" variant="outline" onClick={() => setDetailId(task.id)}>
                          详情
                        </Button>
                        {(task.status === "running" || task.status === "queued") && (
                          <Button size="sm" variant="outline" onClick={() => void cancelTask(task.id)}>
                            <SquareIcon className="size-3" />
                            停止
                          </Button>
                        )}
                        {task.status !== "running" && task.status !== "queued" && (
                          <Button size="sm" variant="ghost" onClick={() => void removeTask(task.id)}>
                            <Trash2Icon className="size-4" />
                          </Button>
                        )}
                      </div>
                    </TableCell>
                  </TableRow>
                );
              })
            )}
          </TableBody>
        </Table>
      </div>

      {/* 字典管理 */}
      <Dialog open={dictOpen} onOpenChange={setDictOpen}>
        <DialogContent className="flex max-h-[92vh] flex-col sm:max-w-2xl">
          <DialogHeader>
            <DialogTitle>弱口令字典</DialogTitle>
            <DialogDescription>
              默认只用内置精简字典；导入档按「用户:口令」一行一组（只有口令的行表示不需要用户名），上限 5000 组。
              任务里选了哪个档会记进日志与报告，结论可追溯。
            </DialogDescription>
          </DialogHeader>
          <div className="min-h-0 flex-1 space-y-4 overflow-y-auto pr-1">
            <div className="rounded-md border">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>字典档</TableHead>
                    <TableHead className="w-24">组数</TableHead>
                    <TableHead className="w-32">导入时间</TableHead>
                    <TableHead className="w-20" />
                  </TableRow>
                </TableHeader>
                <TableBody>
                  <TableRow>
                    <TableCell className="font-mono text-xs">builtin</TableCell>
                    <TableCell className="text-xs text-muted-foreground">内置</TableCell>
                    <TableCell className="text-xs text-muted-foreground">—</TableCell>
                    <TableCell />
                  </TableRow>
                  {dicts.map((d) => (
                    <TableRow key={d.name}>
                      <TableCell className="font-mono text-xs">{d.name}</TableCell>
                      <TableCell className="text-xs">{d.entry_count}</TableCell>
                      <TableCell className="text-xs text-muted-foreground">{fmtTime(d.created_at)}</TableCell>
                      <TableCell>
                        <Button size="sm" variant="ghost" onClick={() => void removeDict(d.name)}>
                          <Trash2Icon className="size-4" />
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
            <div className="space-y-2">
              <Label htmlFor="dict-name">导入新字典</Label>
              <Input
                id="dict-name"
                value={dictName}
                onChange={(e) => setDictName(e.target.value)}
                placeholder="字典名（字母、数字、- 和 _）"
                className="font-mono"
              />
              <Textarea
                value={dictContent}
                onChange={(e) => setDictContent(e.target.value)}
                placeholder={"# 注释行会被忽略\nroot:root\nadmin:Admin@123\nPassword1"}
                className="min-h-32 font-mono text-xs"
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDictOpen(false)}>
              关闭
            </Button>
            <Button onClick={() => void importDict()} disabled={dictBusy}>
              {dictBusy && <Loader2Icon className="size-4 animate-spin" />}
              导入
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* 新建 */}
      <Dialog open={createOpen} onOpenChange={setCreateOpen}>
        <DialogContent className="flex max-h-[92vh] flex-col sm:max-w-2xl">
          <DialogHeader>
            <DialogTitle>新建弱口令检测</DialogTitle>
            <DialogDescription>
              检测在应用容器内执行，请确认目标已获得授权。每个端点每轮会按所选协议做握手确认后再验证口令。
            </DialogDescription>
          </DialogHeader>
          <div className="min-h-0 flex-1 space-y-4 overflow-y-auto pr-1">
            <div className="space-y-1.5">
              <Label htmlFor="cred-name">任务名称</Label>
              <Input id="cred-name" value={name} onChange={(e) => setName(e.target.value)} placeholder="留空自动生成" />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="cred-targets">目标（每行一个，可用 host:port 指定端口）</Label>
              <Textarea
                id="cred-targets"
                value={targets}
                onChange={(e) => setTargets(e.target.value)}
                placeholder={"192.168.1.10\n192.168.1.11:2222"}
                className="min-h-24 font-mono text-xs"
              />
              <p className="text-muted-foreground text-xs">
                支持 IPv4 与域名；写了端口就只测那个端口，没写则按协议默认端口表（协议仍需握手确认）。
              </p>
            </div>

            <div className="space-y-2">
              <Label>协议</Label>
              <div className="flex flex-wrap gap-1.5">
                {supported.map((p) => (
                  <button
                    key={p.name}
                    type="button"
                    onClick={() => toggleProtocol(p.name)}
                    className={cn(
                      "rounded-md border px-2 py-1 font-mono text-xs transition-colors",
                      picked.has(p.name) ? "border-primary bg-primary/10 text-primary" : "hover:bg-muted/50",
                    )}
                  >
                    {p.name}
                    {p.default_port > 0 && <span className="ml-1 text-muted-foreground">:{p.default_port}</span>}
                  </button>
                ))}
              </div>
              {unsupported.length > 0 && (
                <div className="rounded-md border border-dashed px-3 py-2 text-[11px] text-muted-foreground">
                  <p>暂不支持以下协议（创建时会被拒绝，不会发起连接）：</p>
                  <ul className="mt-1 space-y-0.5">
                    {unsupported.map((p) => (
                      <li key={p.name}>
                        <span className="font-mono">{p.name}</span>
                        {p.default_port > 0 && <span> :{p.default_port}</span>}
                        {p.note ? <span> —— {p.note}</span> : null}
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>

            <div className="grid gap-3 sm:grid-cols-2">
              <div className="space-y-1.5">
                <Label>字典档</Label>
                <Select value={dictProfile} onValueChange={setDictProfile}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {dictionaries.map((d) => (
                      <SelectItem key={d} value={d}>
                        {d === "builtin" ? "内置精简字典" : d}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                {builtinDict ? (
                  // 分档与版本写在选择器下面：操作员要能回答「这次到底试了哪些」，
                  // 只写「内置精简字典」等于什么都没说。顺序也要写出来——它决定先试出什么。
                  <p className="text-muted-foreground text-xs">
                    内置字典 {builtinDict.version} · 共 {builtinDict.total} 组（
                    {builtinDict.tiers.map((t) => `${t.label} ${t.count}`).join(" / ")}）。尝试顺序：
                    {builtinDict.order}
                  </p>
                ) : null}
              </div>
              <div className="space-y-1.5">
                <Label>任务预算</Label>
                <Select value={budget} onValueChange={setBudget}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {BUDGETS.map((b) => (
                      <SelectItem key={b.value} value={b.value}>
                        {b.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="cred-conc">并发端点数</Label>
                <Input
                  id="cred-conc"
                  value={concurrency}
                  onChange={(e) => setConcurrency(e.target.value)}
                  inputMode="numeric"
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="cred-rate">限速（次/秒，0 不限）</Label>
                <Input
                  id="cred-rate"
                  value={rateLimit}
                  onChange={(e) => setRateLimit(e.target.value)}
                  inputMode="numeric"
                />
              </div>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setCreateOpen(false)}>
              取消
            </Button>
            <Button onClick={() => void submitCreate()} disabled={submitting}>
              {submitting && <Loader2Icon className="size-4 animate-spin" />}
              开始检测
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* 详情 */}
      <Dialog open={detailId != null} onOpenChange={(open) => !open && setDetailId(null)}>
        <DialogContent className="flex max-h-[92vh] flex-col sm:max-w-5xl">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              {detail?.task.name || `任务 #${detailId ?? ""}`}
              {detail && (
                <Badge variant="outline" className={cn("gap-1", statusMeta(detail.task).className)}>
                  {statusMeta(detail.task).label}
                </Badge>
              )}
            </DialogTitle>
            <DialogDescription>
              {detail
                ? `${detail.task.targets.join("、")} · ${detail.task.protocols.join(", ")} · 字典 ${detail.task.dict_profile || "builtin"}`
                : "加载中…"}
            </DialogDescription>
          </DialogHeader>

          {detail && (
            <div className="min-h-0 flex-1 space-y-4 overflow-y-auto pr-1">
              <div className="flex flex-wrap gap-2">
                {OUTCOME_ORDER.filter((o) => (detail.counts?.[o] ?? 0) > 0).map((o) => (
                  <Badge key={o} variant="outline" className={cn("gap-1", OUTCOME_META[o].className)}>
                    {OUTCOME_META[o].label}
                    <span className="font-mono">{detail.counts[o]}</span>
                  </Badge>
                ))}
                {Object.keys(detail.counts ?? {}).length === 0 && (
                  <span className="text-muted-foreground text-xs">还没有结果行</span>
                )}
              </div>

              {detail.task.log && (
                <pre className="max-h-40 overflow-auto whitespace-pre-wrap rounded-md border bg-muted/30 p-2 font-mono text-[11px] leading-relaxed">
                  {detail.task.log}
                </pre>
              )}

              <div className="flex items-center justify-between gap-2">
                <div className="flex items-center gap-2">
                  <Label className="text-xs">筛选</Label>
                  <Select value={outcome} onValueChange={setOutcome}>
                    <SelectTrigger className="h-8 w-36">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="all">全部结论</SelectItem>
                      {OUTCOME_ORDER.map((o) => (
                        <SelectItem key={o} value={o}>
                          {OUTCOME_META[o].label}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                  <span className="text-muted-foreground text-xs">{resultTotal} 行</span>
                </div>
                {detailActive && (
                  <span className="flex items-center gap-1 text-muted-foreground text-xs">
                    <Loader2Icon className="size-3 animate-spin" />
                    实时刷新中
                  </span>
                )}
              </div>

              <div className="overflow-auto rounded-md border">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead className="w-40">端点</TableHead>
                      <TableHead className="w-24">协议</TableHead>
                      <TableHead className="w-36">账号</TableHead>
                      <TableHead className="w-32">口令</TableHead>
                      <TableHead className="w-24">结论</TableHead>
                      <TableHead>依据</TableHead>
                      <TableHead className="w-28">操作</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {results.length === 0 ? (
                      <TableRow>
                        <TableCell colSpan={7} className="h-20 text-center text-muted-foreground text-xs">
                          {detailActive ? "正在等待结果…" : "没有结果行"}
                        </TableCell>
                      </TableRow>
                    ) : (
                      results.map((row) => {
                        const meta = OUTCOME_META[row.outcome] ?? { label: row.outcome, className: "" };
                        return (
                          <TableRow key={row.id}>
                            <TableCell className="font-mono text-xs">
                              {row.host}:{row.port}
                              {row.tls && (
                                <Badge variant="outline" className="ml-1 px-1 py-0 text-[10px]">
                                  TLS
                                </Badge>
                              )}
                            </TableCell>
                            <TableCell className="font-mono text-xs">{row.protocol}</TableCell>
                            <TableCell className="font-mono text-xs">{row.username || "—"}</TableCell>
                            <TableCell className="font-mono text-xs">{row.password || "—"}</TableCell>
                            <TableCell>
                              <Badge variant="outline" className={cn("text-[11px]", meta.className)}>
                                {meta.label}
                              </Badge>
                            </TableCell>
                            <TableCell
                              className="max-w-72 truncate text-muted-foreground text-xs"
                              title={row.banner || row.reason}
                            >
                              {row.banner || row.reason || "—"}
                            </TableCell>
                            <TableCell>
                              {row.evidence ? (
                                <Button size="sm" variant="outline" onClick={() => setEvidence(row)}>
                                  原始报文
                                </Button>
                              ) : (
                                <span className="text-muted-foreground text-xs">—</span>
                              )}
                            </TableCell>
                          </TableRow>
                        );
                      })
                    )}
                  </TableBody>
                </Table>
              </div>
            </div>
          )}
          <DialogFooter className="gap-2">
            {detail && (
              <>
                <Button variant="outline" onClick={() => void downloadReport(detail.task.id, true)}>
                  内部报告
                </Button>
                <Button variant="outline" onClick={() => void downloadReport(detail.task.id, false)}>
                  对外报告
                </Button>
              </>
            )}
            <Button onClick={() => setDetailId(null)}>关闭</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* 原始协议报文 */}
      <Dialog open={evidence != null} onOpenChange={(open) => !open && setEvidence(null)}>
        <DialogContent className="flex max-h-[92vh] flex-col sm:max-w-3xl">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <KeyRoundIcon className="size-4" />
              {evidence ? `${evidence.host}:${evidence.port} · ${evidence.protocol}` : "原始报文"}
            </DialogTitle>
            <DialogDescription>
              证据按原始字节记录{evidence?.tls ? "（TLS 通道内的明文，复现时需先升 TLS）" : ""}，逐字节可复现。
            </DialogDescription>
          </DialogHeader>
          <div className="min-h-0 flex-1 overflow-auto">
            <pre className="whitespace-pre-wrap rounded-md border bg-muted/30 p-3 font-mono text-[11px] leading-relaxed">
              {evidence?.evidence || ""}
            </pre>
          </div>
          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => {
                if (evidence?.evidence) {
                  void navigator.clipboard.writeText(evidence.evidence);
                  toast.success("已复制");
                }
              }}
            >
              <CopyIcon className="size-4" />
              复制证据
            </Button>
            <Button onClick={() => setEvidence(null)}>关闭</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
