"use client";

import * as React from "react";

import {
  CopyIcon,
  Loader2Icon,
  NetworkIcon,
  PlusIcon,
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
import type { SubdomainOptionsInfo, SubdomainResult, SubdomainTask } from "@/lib/types";

// 子域名枚举（C3）：字典 + 可选公开接口 + A/AAAA/CNAME 解析，结果自动进资产台账与端口探测。
//
// 这一页刻意不提供任何「顺手打一枪」的入口：DNS 查询走本机配置的解析器，端口探测
// 会真发包，两者都受客户授权清单约束。公开接口默认关闭——它会把根域名发给第三方。

const STATUS_META: Record<string, { label: string; className: string }> = {
  queued: { label: "排队中", className: "border-slate-500/30 bg-slate-500/10 text-slate-600 dark:text-slate-400" },
  running: { label: "进行中", className: "border-sky-500/30 bg-sky-500/10 text-sky-600 dark:text-sky-400" },
  done: { label: "已完成", className: "border-emerald-500/30 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400" },
  failed: { label: "失败", className: "border-red-500/30 bg-red-500/10 text-red-600 dark:text-red-400" },
  canceled: { label: "已取消", className: "border-amber-500/30 bg-amber-500/10 text-amber-600 dark:text-amber-400" },
};

const SOURCE_META: Record<string, string> = {
  input: "直接给出",
  dict: "字典命中",
  public: "公开接口",
};

const PORT_SPECS = [
  { value: "top100", label: "常见 100 端口（默认）" },
  { value: "top1000", label: "常见 1000 端口" },
  { value: "web", label: "只看 Web 端口" },
];

function fmtTime(ts?: string) {
  if (!ts) return "—";
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return ts;
  return d.toLocaleString("zh-CN", { hour12: false });
}

function summaryNum(task: SubdomainTask | null, key: string): number {
  const v = task?.summary?.[key];
  return typeof v === "number" ? v : 0;
}

function summaryText(task: SubdomainTask | null, key: string): string {
  const v = task?.summary?.[key];
  return typeof v === "string" ? v : "";
}

// 结论那一栏的口径与后端一致：泛解析与「没写进资产」都不能显示成正常发现。
function verdictOf(row: SubdomainResult): { label: string; className: string } {
  if (row.wildcard) {
    return {
      label: "与泛解析一致（待确认）",
      className: "border-amber-500/30 bg-amber-500/10 text-amber-600 dark:text-amber-400",
    };
  }
  if (row.asset_id == null) {
    return {
      label: "已解析，未进资产",
      className: "border-red-500/30 bg-red-500/10 text-red-600 dark:text-red-400",
    };
  }
  return {
    label: row.ips.length > 0 ? "已解析并进资产" : "有记录，无 IP",
    className: "border-emerald-500/30 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400",
  };
}

export default function SubdomainPage() {
  const [tasks, setTasks] = React.useState<SubdomainTask[]>([]);
  const [meta, setMeta] = React.useState<SubdomainOptionsInfo>({});
  const [selectedID, setSelectedID] = React.useState<number | null>(null);
  const [detail, setDetail] = React.useState<SubdomainTask | null>(null);
  const [results, setResults] = React.useState<SubdomainResult[]>([]);
  const [busy, setBusy] = React.useState(false);
  const [picked, setPicked] = React.useState<Set<number>>(new Set());
  const [open, setOpen] = React.useState(false);
  const [creating, setCreating] = React.useState(false);

  const [name, setName] = React.useState("");
  const [targets, setTargets] = React.useState("");
  const [words, setWords] = React.useState("");
  const [concurrency, setConcurrency] = React.useState("16");
  const [timeoutSecs, setTimeoutSecs] = React.useState("3");
  const [maxQueries, setMaxQueries] = React.useState("20000");
  const [ports, setPorts] = React.useState("top100");
  const [publicOn, setPublicOn] = React.useState(false);
  const [probeOn, setProbeOn] = React.useState(true);
  const [keepWildcard, setKeepWildcard] = React.useState(false);

  const splitList = (raw: string) =>
    raw
      .split(/[\s,;]+/)
      .map((s) => s.trim())
      .filter(Boolean);

  const loadTasks = React.useCallback(async () => {
    setBusy(true);
    try {
      const [list, info] = await Promise.all([api.subdomainTasks(50), api.subdomainOptions()]);
      setTasks(list.tasks ?? []);
      setMeta(info ?? {});
    } catch (e) {
      toast.error("读取任务列表失败：" + (e as Error).message);
    } finally {
      setBusy(false);
    }
  }, []);

  const loadDetail = React.useCallback(async (id: number) => {
    try {
      const [one, res] = await Promise.all([api.subdomainTask(id), api.subdomainResults(id)]);
      setDetail(one.task ?? null);
      setResults(res.results ?? []);
    } catch (e) {
      toast.error("读取任务详情失败：" + (e as Error).message);
    }
  }, []);

  React.useEffect(() => {
    void loadTasks();
  }, [loadTasks]);

  React.useEffect(() => {
    if (selectedID != null) void loadDetail(selectedID);
  }, [selectedID, loadDetail]);

  const create = async () => {
    const list = splitList(targets);
    if (list.length === 0) {
      toast.error("至少填写一个根域名，例如 example.com");
      return;
    }
    setCreating(true);
    try {
      const task = await api.createSubdomainTask({
        name: name.trim(),
        targets: list,
        options: {
          words: splitList(words),
          concurrency: Number(concurrency) || 16,
          timeout_seconds: Number(timeoutSecs) || 3,
          max_queries: Number(maxQueries) || 20000,
          ports,
          probe_ports: probeOn,
          keep_wildcard: keepWildcard,
          public_sources: publicOn ? (meta.public_sources ?? ["crtsh"]) : [],
        },
      });
      toast.success(`任务 #${task.id} 已排队`);
      setOpen(false);
      setSelectedID(task.id);
      await loadTasks();
    } catch (e) {
      toast.error((e as Error).message);
    } finally {
      setCreating(false);
    }
  };

  const cancel = async (id: number) => {
    try {
      await api.cancelSubdomainTask(id);
      toast.success("已请求停止");
      await Promise.all([loadTasks(), loadDetail(id)]);
    } catch (e) {
      toast.error((e as Error).message);
    }
  };

  const togglePick = (id: number) => {
    setPicked((prev) => {
      const next = new Set(prev);
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }
      return next;
    });
  };

  // 删除只认勾选：一个「删除已结束」的按钮会替用户决定删掉哪些历史任务，
  // 而台账删掉就问不回来（资产留着，但没人知道这些名字是哪一轮、用什么方式得到的）。
  const remove = async () => {
    if (picked.size === 0) {
      toast.error("先勾选要删除的任务");
      return;
    }
    try {
      const r = await api.deleteSubdomainTasks([...picked]);
      toast.success(`已删除 ${r.deleted} 个任务（结果台账一并清除，资产保留）`);
      setPicked(new Set());
      setSelectedID(null);
      setDetail(null);
      setResults([]);
      await loadTasks();
    } catch (e) {
      toast.error((e as Error).message);
    }
  };

  const copyMarkdown = async () => {
    if (!detail) return;
    try {
      const r = await api.subdomainReport(detail.id);
      const md = r.markdown ?? "";
      if (!md) {
        toast.error("没有拿到报告内容");
        return;
      }
      await navigator.clipboard.writeText(md);
      toast.success("报告 Markdown 已复制");
    } catch (e) {
      toast.error((e as Error).message);
    }
  };

  const running = tasks.some((t) => t.status === "queued" || t.status === "running");

  return (
    <div className="space-y-4 p-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="flex items-center gap-2 font-semibold text-lg">
            <NetworkIcon className="size-4" /> 子域名枚举
          </h1>
          <p className="text-muted-foreground text-sm">
            字典爆破 + 可选公开接口 + A/AAAA/CNAME 解析；确认存在的名字自动写入资产台账，
            解析出的 IP 可直接进入端口探测，不需要手工搬运。
          </p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={() => void loadTasks()} disabled={busy}>
            <RefreshCwIcon className={busy ? "animate-spin" : ""} /> 刷新
          </Button>
          <Button variant="outline" size="sm" onClick={() => void remove()} disabled={picked.size === 0}>
            <Trash2Icon /> 删除所选{picked.size > 0 ? `（${picked.size}）` : ""}
          </Button>
          <Button size="sm" onClick={() => setOpen(true)}>
            <PlusIcon /> 新建枚举任务
          </Button>
        </div>
      </div>

      <div className="rounded-md border border-amber-500/30 bg-amber-500/5 p-3 text-xs">
        <div className="mb-1 font-medium">三条口径，先看再点</div>
        <ul className="list-disc space-y-1 pl-4 text-muted-foreground">
          <li>
            字典爆破的 DNS 查询发往<strong>本机配置的解析器</strong>，不发给目标主机；用公共/运营商
            DNS 时，被查询的域名会出现在它的日志里。
          </li>
          <li>
            公开接口（crt.sh 是公开证书透明度日志）会把<strong>客户的根域名发给第三方</strong>，
            授权清单管不住这条外发，因此默认关闭，勾选即视为同意。
          </li>
          <li>
            {meta.note ??
              "端口探测会真发包，受客户授权清单约束；解析出的 IP 不在授权范围内时只跳过探测、保留名字，并把原因写进任务日志。"}
          </li>
        </ul>
      </div>

      <Table>
        <TableHeader>
          <TableRow>
            <TableHead className="w-8" />
            <TableHead>任务</TableHead>
            <TableHead>目标</TableHead>
            <TableHead>状态</TableHead>
            <TableHead className="text-right">命中</TableHead>
            <TableHead className="text-right">未判定</TableHead>
            <TableHead className="text-right">探测端口</TableHead>
            <TableHead>创建时间</TableHead>
            <TableHead>操作</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {tasks.length === 0 ? (
            <TableRow>
              <TableCell colSpan={9} className="py-6 text-center text-muted-foreground text-sm">
                还没有枚举任务。新建时填根域名（example.com），一行一个或逗号分隔。
              </TableCell>
            </TableRow>
          ) : (
            tasks.map((t) => (
              <TableRow
                key={t.id}
                className={selectedID === t.id ? "bg-muted/40" : "cursor-pointer"}
                onClick={() => setSelectedID(t.id)}
              >
                <TableCell onClick={(e) => e.stopPropagation()}>
                  <input
                    type="checkbox"
                    checked={picked.has(t.id)}
                    onChange={() => togglePick(t.id)}
                    aria-label={`选择任务 ${t.id}`}
                  />
                </TableCell>
                <TableCell>
                  <div className="font-medium">{t.name || `任务 #${t.id}`}</div>
                  <div className="text-muted-foreground text-xs">#{t.id}</div>
                </TableCell>
                <TableCell className="max-w-[18rem] truncate font-mono text-xs">{t.targets.join("、")}</TableCell>
                <TableCell>
                  <Badge variant="outline" className={STATUS_META[t.status]?.className ?? ""}>
                    {STATUS_META[t.status]?.label ?? t.status}
                  </Badge>
                </TableCell>
                <TableCell className="text-right">{summaryNum(t, "found")}</TableCell>
                <TableCell className="text-right">{summaryNum(t, "unresolved")}</TableCell>
                <TableCell className="text-right">{summaryNum(t, "open_ports")}</TableCell>
                <TableCell className="text-muted-foreground text-xs">{fmtTime(t.created_at)}</TableCell>
                <TableCell>
                  {t.status === "queued" || t.status === "running" ? (
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={(e) => {
                        e.stopPropagation();
                        void cancel(t.id);
                      }}
                    >
                      <SquareIcon /> 停止
                    </Button>
                  ) : null}
                </TableCell>
              </TableRow>
            ))
          )}
        </TableBody>
      </Table>

      {running ? (
        <div className="flex items-center gap-2 text-muted-foreground text-xs">
          <Loader2Icon className="animate-spin" /> 有任务在跑，进度会随每次刷新带出来。
        </div>
      ) : null}

      {detail ? (
        <div className="space-y-3 rounded-lg border bg-muted/20 p-4">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="font-medium text-sm">
              任务 #{detail.id} · {detail.name || "未命名"} · {STATUS_META[detail.status]?.label ?? detail.status}
            </div>
            <Button variant="outline" size="sm" onClick={() => void copyMarkdown()}>
              <CopyIcon /> 复制报告 Markdown
            </Button>
          </div>

          <div className="text-xs">
            {summaryText(detail, "stopped_text") ||
              summaryText(detail, "probe_skipped") ||
              "本轮枚举完整，端口探测已执行。"}
            {summaryNum(detail, "wildcard_dropped") > 0
              ? `（泛解析剔除 ${summaryNum(detail, "wildcard_dropped")} 条）`
              : ""}
            {summaryNum(detail, "unresolved") > 0
              ? `（${summaryNum(detail, "unresolved")} 次解析未判定——超时与 SERVFAIL 不等于不存在）`
              : ""}
          </div>

          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>子域名</TableHead>
                <TableHead>来源</TableHead>
                <TableHead>记录</TableHead>
                <TableHead>结论</TableHead>
                <TableHead>资产</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {results.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={5} className="py-4 text-center text-muted-foreground text-sm">
                    {detail.status === "done"
                      ? "这一轮没有确认存在的子域名。泛解析剔除与未判定次数见上方说明。"
                      : "任务还没产出结果。"}
                  </TableCell>
                </TableRow>
              ) : (
                results.map((row) => {
                  const verdict = verdictOf(row);
                  return (
                    <TableRow key={row.id}>
                      <TableCell className="font-mono text-xs">{row.name}</TableCell>
                      <TableCell className="text-xs">{SOURCE_META[row.source] ?? row.source}</TableCell>
                      <TableCell className="font-mono text-xs">
                        {row.records.map((r) => `${r.type} ${r.values.join(",")}`).join(" / ") || "—"}
                      </TableCell>
                      <TableCell>
                        <Badge variant="outline" className={verdict.className}>
                          {verdict.label}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-muted-foreground text-xs">
                        {row.asset_id != null ? `#${row.asset_id}` : "—"}
                      </TableCell>
                    </TableRow>
                  );
                })
              )}
            </TableBody>
          </Table>

          {detail.log ? (
            <details className="text-xs">
              <summary className="cursor-pointer text-muted-foreground">任务日志</summary>
              <pre className="mt-2 max-h-64 overflow-auto rounded bg-background p-2 font-mono whitespace-pre-wrap">
                {detail.log}
              </pre>
            </details>
          ) : null}
        </div>
      ) : null}

      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle>新建子域名枚举任务</DialogTitle>
            <DialogDescription>
              根域名必须在客户授权清单内；不在范围内会在建任务这一步就被拒绝。
            </DialogDescription>
          </DialogHeader>
          <div className="grid gap-3">
            <div className="grid gap-1">
              <Label>任务名称（可留空）</Label>
              <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="主站子域名测绘" />
            </div>
            <div className="grid gap-1">
              <Label>根域名 *</Label>
              <Textarea
                rows={3}
                value={targets}
                onChange={(e) => setTargets(e.target.value)}
                placeholder={"example.com\ncorp.example.com"}
              />
              <span className="text-muted-foreground text-xs">
                IP 与 CIDR 不参与：它们没有「子域名」这件事。带子域写法（shop.corp.example.com）按标签数保守取根。
              </span>
            </div>
            <div className="grid gap-1">
              <Label>自定义字典（留空用内置 {meta.builtin_words ?? 0} 条）</Label>
              <Textarea
                rows={2}
                value={words}
                onChange={(e) => setWords(e.target.value)}
                placeholder="jenkins\ngitlab\nnexus"
              />
            </div>
            <div className="grid grid-cols-3 gap-3">
              <div className="grid gap-1">
                <Label>并发</Label>
                <Input value={concurrency} onChange={(e) => setConcurrency(e.target.value)} />
              </div>
              <div className="grid gap-1">
                <Label>单次超时（秒）</Label>
                <Input value={timeoutSecs} onChange={(e) => setTimeoutSecs(e.target.value)} />
              </div>
              <div className="grid gap-1">
                <Label>查询预算</Label>
                <Input value={maxQueries} onChange={(e) => setMaxQueries(e.target.value)} />
              </div>
            </div>
            <div className="grid gap-1">
              <Label>端口探测范围</Label>
              <Select value={ports} onValueChange={setPorts}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {PORT_SPECS.map((p) => (
                    <SelectItem key={p.value} value={p.value}>
                      {p.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="grid gap-2 text-sm">
              <label className="flex items-start gap-2">
                <input
                  type="checkbox"
                  className="mt-1"
                  checked={probeOn}
                  onChange={(e) => setProbeOn(e.target.checked)}
                />
                <span>
                  解析出的 IP 顺带做端口探测（默认开）。IP 不在授权范围内时只跳过这一步、保留名字，
                  并把原因写进任务日志。
                </span>
              </label>
              <label className="flex items-start gap-2">
                <input
                  type="checkbox"
                  className="mt-1"
                  checked={publicOn}
                  onChange={(e) => setPublicOn(e.target.checked)}
                />
                <span>
                  使用公开接口 crt.sh（默认关）。<strong>勾选即把根域名发给第三方</strong>，
                  授权清单管不住这条外发；失败只影响这一路来源，会在结论里写明。
                </span>
              </label>
              <label className="flex items-start gap-2">
                <input
                  type="checkbox"
                  className="mt-1"
                  checked={keepWildcard}
                  onChange={(e) => setKeepWildcard(e.target.checked)}
                />
                <span>
                  保留泛解析命中（默认不保留）。开启后与 <code>*.根</code> 答复一致的条目会带「待确认」标记列出，
                  不与真子域名混为一谈。
                </span>
              </label>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setOpen(false)}>
              取消
            </Button>
            <Button onClick={() => void create()} disabled={creating}>
              {creating ? <Loader2Icon className="animate-spin" /> : null} 开始枚举
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
