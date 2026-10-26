"use client";

import * as React from "react";

import {
  ArrowRightLeftIcon,
  CheckIcon,
  DownloadIcon,
  EyeIcon,
  KeyRoundIcon,
  Loader2Icon,
  NetworkIcon,
  PlayIcon,
  PlusIcon,
  RefreshCwIcon,
  ShieldCheckIcon,
  SquareTerminalIcon,
  Trash2Icon,
  UploadIcon,
  WaypointsIcon,
  XIcon,
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
import { ScrollArea } from "@/components/ui/scroll-area";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
import { api } from "@/lib/api";
import type {
  IntranetBatchItem,
  IntranetExecResult,
  IntranetScopeRequest,
  IntranetSession,
  IntranetTunnel,
  Task,
  Webshell,
} from "@/lib/types";

import { FieldRow, fmtTime } from "../_components/deep-ui";

const TUNNEL_KIND_LABEL: Record<string, string> = {
  socks5: "SOCKS5 代理",
  port_forward: "端口转发",
  reverse_forward: "反向转发",
};

function sessionStatusMeta(status: string) {
  switch (status) {
    case "active":
      return { label: "活跃", className: "border-emerald-500/30 bg-emerald-500/10 text-emerald-600" };
    case "closed":
      return { label: "已关闭", className: "border-slate-500/30 bg-slate-500/10 text-slate-600 dark:text-slate-400" };
    default:
      return { label: status || "—", className: "border-slate-500/30 bg-slate-500/10 text-slate-600" };
  }
}

function tunnelStatusMeta(status: string) {
  switch (status) {
    case "planned":
      return { label: "已规划", className: "border-sky-500/30 bg-sky-500/10 text-sky-600" };
    case "deployed":
      return { label: "已部署", className: "border-amber-500/30 bg-amber-500/10 text-amber-600" };
    case "verified":
      return { label: "已验证", className: "border-emerald-500/30 bg-emerald-500/10 text-emerald-600" };
    case "failed":
      return { label: "失败", className: "border-red-500/30 bg-red-500/10 text-red-600 dark:text-red-400" };
    case "stopped":
      return { label: "已停止", className: "border-slate-500/30 bg-slate-500/10 text-slate-600 dark:text-slate-400" };
    default:
      return { label: status || "—", className: "" };
  }
}

function scopeStatusMeta(status: string) {
  switch (status) {
    case "pending":
      return { label: "待审批", className: "border-amber-500/30 bg-amber-500/10 text-amber-600" };
    case "approved":
      return { label: "已批准", className: "border-emerald-500/30 bg-emerald-500/10 text-emerald-600" };
    case "rejected":
      return { label: "已拒绝", className: "border-red-500/30 bg-red-500/10 text-red-600 dark:text-red-400" };
    default:
      return { label: status || "—", className: "" };
  }
}

function tunnelEndpoint(t: IntranetTunnel) {
  const listen = `${t.listen_host || "0.0.0.0"}:${t.listen_port}`;
  if (t.kind === "socks5") return listen;
  return `${listen} → ${t.remote_host || "?"}:${t.remote_port || "?"}`;
}

function taskLabel(task: Task) {
  if (task.name?.trim()) return task.name;
  if (task.description?.trim()) return task.description;
  if (task.goal.trim()) return task.goal;
  return `任务 #${task.id}`;
}

function webshellLabel(shell: Webshell) {
  const name = shell.name || shell.url;
  return `${name} · ${(shell.shell_type || "php").toUpperCase()}`;
}

function fmtBytes(n: number) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

function readFileBase64(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      const raw = String(reader.result ?? "");
      resolve(raw.includes(",") ? raw.slice(raw.indexOf(",") + 1) : raw);
    };
    reader.onerror = () => reject(reader.error ?? new Error("读取文件失败"));
    reader.readAsDataURL(file);
  });
}

interface TerminalLine {
  id: string;
  command: string;
  output: string;
  isError: boolean;
  at: string;
}

export default function DeepIntranetPage() {
  const [sessions, setSessions] = React.useState<IntranetSession[]>([]);
  const [tunnels, setTunnels] = React.useState<IntranetTunnel[]>([]);
  const [requests, setRequests] = React.useState<IntranetScopeRequest[]>([]);
  const [webshells, setWebshells] = React.useState<Webshell[]>([]);
  const [tasks, setTasks] = React.useState<Task[]>([]);
  const [loading, setLoading] = React.useState(false);
  const [refreshKey, setRefreshKey] = React.useState(0);
  const [busyId, setBusyId] = React.useState<string | null>(null);

  const refresh = React.useCallback(() => setRefreshKey((k) => k + 1), []);

  // biome-ignore lint/correctness/useExhaustiveDependencies: refreshKey is an explicit manual-reload trigger.
  React.useEffect(() => {
    let alive = true;
    async function load() {
      try {
        const [s, t, r] = await Promise.all([
          api.intranetSessions({ limit: 200 }),
          api.intranetTunnels({ limit: 200 }),
          api.intranetScopeRequests({ limit: 200 }),
        ]);
        if (!alive) return;
        setSessions(s.sessions ?? []);
        setTunnels(t.tunnels ?? []);
        setRequests(r.requests ?? []);
      } catch (e) {
        if (alive) toast.error((e as Error).message);
      } finally {
        if (alive) setLoading(false);
      }
    }
    setLoading(true);
    void load();
    const timer = setInterval(load, 6000);
    return () => {
      alive = false;
      clearInterval(timer);
    };
  }, [refreshKey]);

  // biome-ignore lint/correctness/useExhaustiveDependencies: refreshKey is an explicit manual-reload trigger.
  React.useEffect(() => {
    let alive = true;
    void (async () => {
      try {
        const [w, t] = await Promise.all([api.webshells({ limit: 200 }), api.tasks()]);
        if (!alive) return;
        setWebshells(w.webshells ?? []);
        setTasks(t.tasks ?? []);
      } catch {
        // 下拉数据加载失败不阻塞主视图，用户可点刷新重试
      }
    })();
    return () => {
      alive = false;
    };
  }, [refreshKey]);

  const pendingScopes = requests.filter((r) => r.status === "pending").length;
  const activeSessions = sessions.filter((s) => s.status === "active").length;

  // ---- 新建会话 ----
  const [sessionOpen, setSessionOpen] = React.useState(false);
  const [sessionSaving, setSessionSaving] = React.useState(false);
  const [sessionForm, setSessionForm] = React.useState({
    webshell_id: "",
    name: "",
    task_id: "none",
    host: "",
    cwd: "",
    note: "",
  });

  function openCreateSession() {
    setSessionForm({ webshell_id: "", name: "", task_id: "none", host: "", cwd: "", note: "" });
    setSessionOpen(true);
  }

  async function saveSession() {
    if (!sessionForm.webshell_id) {
      toast.error("请选择要复用的 webshell");
      return;
    }
    setSessionSaving(true);
    try {
      const r = await api.createIntranetSession({
        webshell_id: Number(sessionForm.webshell_id),
        name: sessionForm.name.trim(),
        task_id: sessionForm.task_id !== "none" ? Number(sessionForm.task_id) : undefined,
        host: sessionForm.host.trim(),
        cwd: sessionForm.cwd.trim(),
        note: sessionForm.note,
      });
      setSessionOpen(false);
      refresh();
      const probe = r.probe;
      if (r.probe_error) {
        toast.warning(`会话已建立，但初始探测异常：${r.probe_error}`);
      } else {
        toast.success(`会话已建立${probe?.host ? ` · ${probe.host}` : ""}${probe?.user ? ` · ${probe.user}` : ""}`);
      }
      void openTerminal(r.session);
    } catch (e) {
      toast.error((e as Error).message);
    } finally {
      setSessionSaving(false);
    }
  }

  // ---- 终端 ----
  const [termSession, setTermSession] = React.useState<IntranetSession | null>(null);
  const [termLines, setTermLines] = React.useState<TerminalLine[]>([]);
  const [termCommand, setTermCommand] = React.useState("id");
  const [termRunning, setTermRunning] = React.useState(false);
  const [termMode, setTermMode] = React.useState("exec");
  const [uploadFile, setUploadFile] = React.useState<File | null>(null);
  const [uploadPath, setUploadPath] = React.useState("");
  const [uploadResult, setUploadResult] = React.useState<IntranetExecResult | null>(null);
  const [downloadPath, setDownloadPath] = React.useState("");
  const [downloadBusy, setDownloadBusy] = React.useState(false);

  const openTerminal = React.useCallback(async (session: IntranetSession) => {
    setTermSession(session);
    setTermLines([]);
    setTermMode("exec");
    setUploadFile(null);
    setUploadPath("");
    setUploadResult(null);
    setDownloadPath("");
    try {
      const r = await api.intranetSessionEvents(session.id, 50);
      setTermLines(
        (r.events ?? []).map((ev) => ({
          id: `ev-${ev.id}`,
          command: ev.command,
          output: ev.output,
          isError: ev.is_error,
          at: ev.created_at,
        })),
      );
    } catch {
      // 历史事件读取失败时仍可执行新命令
    }
  }, []);

  function appendTermLine(command: string, result: IntranetExecResult) {
    const output = result.note ? `${result.output}\n[${result.note}]` : result.output;
    setTermLines((prev) => [
      ...prev,
      {
        id: `live-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
        command,
        output,
        isError: result.is_error,
        at: new Date().toISOString(),
      },
    ]);
  }

  async function runTermCommand() {
    if (!termSession) return;
    const cmd = termCommand.trim();
    if (!cmd) {
      toast.error("请输入命令");
      return;
    }
    setTermRunning(true);
    try {
      const r = await api.intranetExec(termSession.id, cmd);
      setTermSession(r.session);
      appendTermLine(cmd, r.result);
      refresh();
    } catch (e) {
      toast.error((e as Error).message);
    } finally {
      setTermRunning(false);
    }
  }

  async function doUpload() {
    if (!termSession) return;
    if (!uploadFile) {
      toast.error("请选择本地文件");
      return;
    }
    if (!uploadPath.trim()) {
      toast.error("请填写目标路径");
      return;
    }
    if (uploadFile.size > 4 * 1024 * 1024) {
      toast.error("文件超过 4MB 上限");
      return;
    }
    setTermRunning(true);
    setUploadResult(null);
    try {
      const b64 = await readFileBase64(uploadFile);
      const r = await api.intranetUpload(termSession.id, uploadPath.trim(), b64);
      setTermSession(r.session);
      setUploadResult(r.result);
      appendTermLine(`upload ${uploadFile.name} -> ${uploadPath.trim()}`, r.result);
      if (r.result.is_error) {
        toast.error(r.result.note || "上传失败");
      } else {
        toast.success("上传完成");
      }
      refresh();
    } catch (e) {
      toast.error((e as Error).message);
    } finally {
      setTermRunning(false);
    }
  }

  async function doDownload() {
    if (!termSession) return;
    const path = downloadPath.trim();
    if (!path) {
      toast.error("请填写要下载的路径");
      return;
    }
    setDownloadBusy(true);
    try {
      const r = await api.intranetDownload(termSession.id, path);
      if (r.result.is_error) {
        toast.error(r.result.note || "下载失败");
        return;
      }
      const bin = atob(r.content_base64);
      const bytes = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
      const blob = new Blob([bytes]);
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = path.split("/").pop() || "download.bin";
      a.click();
      URL.revokeObjectURL(url);
      toast.success(`已下载 ${fmtBytes(r.size)}${r.truncated ? `（文件共 ${fmtBytes(r.total)}，已截断）` : ""}`);
      refresh();
    } catch (e) {
      toast.error((e as Error).message);
    } finally {
      setDownloadBusy(false);
    }
  }

  async function toggleSession(session: IntranetSession) {
    const next = session.status === "active" ? "closed" : "active";
    setBusyId(`session-${session.id}`);
    try {
      await api.updateIntranetSession(session.id, { status: next });
      toast.success(next === "active" ? "会话已重新打开" : "会话已关闭");
      refresh();
    } catch (e) {
      toast.error((e as Error).message);
    } finally {
      setBusyId(null);
    }
  }

  async function removeSession(session: IntranetSession) {
    if (!window.confirm(`删除会话「${session.name || session.host}」？只删除平台记录，不影响 webshell。`)) return;
    setBusyId(`session-${session.id}`);
    try {
      await api.deleteIntranetSession(session.id);
      toast.success("已删除");
      refresh();
    } catch (e) {
      toast.error((e as Error).message);
    } finally {
      setBusyId(null);
    }
  }

  // ---- 批量执行 ----
  const [selected, setSelected] = React.useState<Set<number>>(new Set());
  const [batchOpen, setBatchOpen] = React.useState(false);
  const [batchCommand, setBatchCommand] = React.useState("hostname; id");
  const [batchRunning, setBatchRunning] = React.useState(false);
  const [batchItems, setBatchItems] = React.useState<IntranetBatchItem[]>([]);

  function toggleSelected(id: number, on: boolean) {
    setSelected((prev) => {
      const next = new Set(prev);
      if (on) next.add(id);
      else next.delete(id);
      return next;
    });
  }

  async function runBatch() {
    const ids = [...selected];
    if (ids.length === 0) return;
    const cmd = batchCommand.trim();
    if (!cmd) {
      toast.error("请输入命令");
      return;
    }
    setBatchRunning(true);
    setBatchItems([]);
    setBatchOpen(true);
    try {
      const r = await api.intranetBatchExec(ids, cmd);
      setBatchItems(r.results ?? []);
      refresh();
    } catch (e) {
      toast.error((e as Error).message);
    } finally {
      setBatchRunning(false);
    }
  }

  // ---- 新建隧道 ----
  const [tunnelOpen, setTunnelOpen] = React.useState(false);
  const [tunnelSaving, setTunnelSaving] = React.useState(false);
  const [tunnelForm, setTunnelForm] = React.useState({
    name: "",
    session_id: "",
    task_id: "none",
    kind: "port_forward",
    listen_host: "127.0.0.1",
    listen_port: "",
    remote_host: "127.0.0.1",
    remote_port: "",
    deploy_command: "",
    verify_command: "",
    teardown_command: "",
    note: "",
  });

  function openCreateTunnel() {
    setTunnelForm({
      name: "",
      session_id: "",
      task_id: "none",
      kind: "port_forward",
      listen_host: "127.0.0.1",
      listen_port: "",
      remote_host: "127.0.0.1",
      remote_port: "",
      deploy_command: "",
      verify_command: "",
      teardown_command: "",
      note: "",
    });
    setTunnelOpen(true);
  }

  async function saveTunnel() {
    if (!tunnelForm.session_id) {
      toast.error("请选择承载隧道的会话");
      return;
    }
    const listenPort = Number(tunnelForm.listen_port);
    if (!listenPort || listenPort < 1 || listenPort > 65535) {
      toast.error("监听端口必须在 1-65535 之间");
      return;
    }
    const remotePort = Number(tunnelForm.remote_port);
    if (tunnelForm.kind !== "socks5" && (!remotePort || remotePort < 1 || remotePort > 65535)) {
      toast.error("远端端口必须在 1-65535 之间");
      return;
    }
    setTunnelSaving(true);
    try {
      await api.createIntranetTunnel({
        name: tunnelForm.name.trim(),
        session_id: Number(tunnelForm.session_id),
        task_id: tunnelForm.task_id !== "none" ? Number(tunnelForm.task_id) : undefined,
        kind: tunnelForm.kind,
        listen_host: tunnelForm.listen_host.trim(),
        listen_port: listenPort,
        remote_host: tunnelForm.remote_host.trim(),
        remote_port: remotePort || undefined,
        deploy_command: tunnelForm.deploy_command,
        verify_command: tunnelForm.verify_command,
        teardown_command: tunnelForm.teardown_command,
        note: tunnelForm.note,
      });
      toast.success("隧道已登记，请先「规划」再「部署」");
      setTunnelOpen(false);
      refresh();
    } catch (e) {
      toast.error((e as Error).message);
    } finally {
      setTunnelSaving(false);
    }
  }

  // ---- 隧道操作 ----
  const [detailTunnel, setDetailTunnel] = React.useState<IntranetTunnel | null>(null);

  async function tunnelAction(t: IntranetTunnel, action: "probe" | "plan" | "deploy" | "verify" | "teardown") {
    setBusyId(`tunnel-${t.id}-${action}`);
    try {
      if (action === "probe") {
        const r = await api.intranetTunnelProbe(t.id);
        setDetailTunnel(t);
        toast.success(r.probe?.host ? `探测成功：${r.probe.host}` : "探测完成");
      } else if (action === "plan") {
        const r = await api.intranetTunnelPlan(t.id);
        setDetailTunnel(r.tunnel);
        toast.success("已生成部署计划");
      } else if (action === "deploy") {
        if (!window.confirm(`部署隧道「${t.name || t.id}」？部署后会登记受管资源并在到期后自动回收。`)) return;
        const r = await api.intranetTunnelDeploy(t.id);
        if (r.tunnel.status === "failed") {
          toast.error(`部署失败：${r.result.note || r.result.output || "无回显"}`);
        } else {
          toast.success("部署指令已执行，请继续验证");
        }
      } else if (action === "verify") {
        const r = await api.intranetTunnelVerify(t.id);
        if (r.tunnel.status === "verified") {
          toast.success("隧道验证通过");
        } else {
          toast.error(`验证失败：${r.result.output || r.result.note || "端口未监听"}`);
        }
      } else {
        if (!window.confirm(`拆除隧道「${t.name || t.id}」？会执行拆除命令并释放受管资源。`)) return;
        await api.intranetTunnelTeardown(t.id);
        toast.success("隧道已拆除");
      }
      refresh();
    } catch (e) {
      toast.error((e as Error).message);
    } finally {
      setBusyId(null);
    }
  }

  async function removeTunnel(t: IntranetTunnel) {
    if (!window.confirm(`删除隧道「${t.name || t.id}」？未停止的隧道会先尝试拆除。`)) return;
    setBusyId(`tunnel-${t.id}-delete`);
    try {
      await api.deleteIntranetTunnel(t.id);
      toast.success("已删除");
      refresh();
    } catch (e) {
      toast.error((e as Error).message);
    } finally {
      setBusyId(null);
    }
  }

  // ---- 范围审批 ----
  const [scopeOpen, setScopeOpen] = React.useState(false);
  const [scopeSaving, setScopeSaving] = React.useState(false);
  const [scopeForm, setScopeForm] = React.useState({
    task_id: "none",
    host: "",
    port: "",
    reason: "",
    session_id: "none",
  });
  const [decision, setDecision] = React.useState<{ request: IntranetScopeRequest; approve: boolean } | null>(null);
  const [decisionNote, setDecisionNote] = React.useState("");
  const [decisionBusy, setDecisionBusy] = React.useState(false);

  function openCreateScope() {
    setScopeForm({ task_id: "none", host: "", port: "", reason: "", session_id: "none" });
    setScopeOpen(true);
  }

  async function saveScope() {
    if (scopeForm.task_id === "none") {
      toast.error("请选择所属任务");
      return;
    }
    if (!scopeForm.host.trim()) {
      toast.error("请填写要申请的主机");
      return;
    }
    setScopeSaving(true);
    try {
      const r = await api.createIntranetScopeRequest({
        task_id: Number(scopeForm.task_id),
        host: scopeForm.host.trim(),
        port: scopeForm.port ? Number(scopeForm.port) : undefined,
        reason: scopeForm.reason,
        session_id: scopeForm.session_id !== "none" ? Number(scopeForm.session_id) : undefined,
      });
      toast.success(r.created ? "范围申请已提交，等待审批" : "该主机已有待审批申请");
      setScopeOpen(false);
      refresh();
    } catch (e) {
      toast.error((e as Error).message);
    } finally {
      setScopeSaving(false);
    }
  }

  async function submitDecision() {
    if (!decision) return;
    setDecisionBusy(true);
    try {
      if (decision.approve) {
        await api.approveIntranetScopeRequest(decision.request.id, decisionNote);
        toast.success(`已批准 ${decision.request.host}，范围已写入任务 #${decision.request.task_id}`);
      } else {
        await api.rejectIntranetScopeRequest(decision.request.id, decisionNote);
        toast.success("已拒绝该申请");
      }
      setDecision(null);
      setDecisionNote("");
      refresh();
    } catch (e) {
      toast.error((e as Error).message);
    } finally {
      setDecisionBusy(false);
    }
  }

  // ---- 任务交接 ----
  const [handoffOpen, setHandoffOpen] = React.useState(false);
  const [handoffSaving, setHandoffSaving] = React.useState(false);
  const [handoffForm, setHandoffForm] = React.useState({
    from_task_id: "none",
    name: "",
    description: "",
    goal: "",
  });

  function openHandoff() {
    setHandoffForm({ from_task_id: "none", name: "", description: "", goal: "" });
    setHandoffOpen(true);
  }

  async function saveHandoff() {
    if (handoffForm.from_task_id === "none") {
      toast.error("请选择来源任务");
      return;
    }
    setHandoffSaving(true);
    try {
      const r = await api.intranetHandoff({
        from_task_id: Number(handoffForm.from_task_id),
        name: handoffForm.name.trim(),
        description: handoffForm.description.trim(),
        goal: handoffForm.goal.trim(),
      });
      toast.success(`已创建交接任务 #${r.task.id}`);
      for (const w of r.warnings ?? []) toast.warning(w);
      setHandoffOpen(false);
      refresh();
    } catch (e) {
      toast.error((e as Error).message);
    } finally {
      setHandoffSaving(false);
    }
  }

  const showLoading = loading && sessions.length === 0 && tunnels.length === 0 && requests.length === 0;

  return (
    <div className="flex min-h-0 flex-1 flex-col gap-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <WaypointsIcon className="h-5 w-5 text-muted-foreground" />
          <h1 className="font-semibold text-xl tracking-tight">内网渗透</h1>
          <Badge variant="secondary">{activeSessions}</Badge>
          {pendingScopes > 0 ? (
            <Badge variant="outline" className="border-amber-500/30 bg-amber-500/10 text-amber-600">
              {pendingScopes} 项待审批
            </Badge>
          ) : null}
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Button variant="outline" size="sm" onClick={openHandoff}>
            <ArrowRightLeftIcon className="size-4" />
            任务交接
          </Button>
          <Button variant="outline" size="sm" onClick={openCreateTunnel}>
            <NetworkIcon className="size-4" />
            新建隧道
          </Button>
          <Button size="sm" onClick={openCreateSession}>
            <PlusIcon className="size-4" />
            新建会话
          </Button>
          <Button variant="ghost" size="sm" onClick={refresh}>
            <RefreshCwIcon className="size-4" />
          </Button>
        </div>
      </div>

      <p className="text-muted-foreground text-sm">
        会话复用已登记的 webshell 执行命令并维护工作目录；隧道按「探测 → 规划 → 部署 → 验证 →
        拆除」两阶段管理，部署会登记受管资源。所有操作都可直接使用，接入 LLM 时 agent 通过同名工具操作同一份数据。
      </p>

      {showLoading ? (
        <div className="flex items-center justify-center py-16 text-muted-foreground text-sm">
          <Loader2Icon className="mr-2 size-4 animate-spin" />
          加载中…
        </div>
      ) : null}

      <Tabs defaultValue="sessions" className="flex min-h-0 flex-1 flex-col gap-3">
        <TabsList className="w-fit">
          <TabsTrigger value="sessions">会话 ({sessions.length})</TabsTrigger>
          <TabsTrigger value="tunnels">隧道 ({tunnels.length})</TabsTrigger>
          <TabsTrigger value="scopes">范围审批 ({requests.length})</TabsTrigger>
        </TabsList>

        <TabsContent value="sessions" className="flex min-h-0 flex-1 flex-col gap-3">
          {sessions.length === 0 ? (
            <div className="rounded-md border border-dashed py-12 text-center text-muted-foreground text-sm">
              还没有内网会话。先添加 webshell，再点击右上角「新建会话」。
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-10" />
                  <TableHead>会话</TableHead>
                  <TableHead className="w-56">工作目录</TableHead>
                  <TableHead className="w-20">状态</TableHead>
                  <TableHead className="w-32">最近活动</TableHead>
                  <TableHead className="w-44 text-right">操作</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {sessions.map((s) => {
                  const meta = sessionStatusMeta(s.status);
                  return (
                    <TableRow key={s.id}>
                      <TableCell>
                        <Checkbox
                          checked={selected.has(s.id)}
                          onCheckedChange={(v) => toggleSelected(s.id, v === true)}
                        />
                      </TableCell>
                      <TableCell>
                        <div className="flex items-center gap-2">
                          <div className="max-w-60 truncate font-medium text-sm" title={s.name}>
                            {s.name || s.webshell_name || s.host || `会话 #${s.id}`}
                          </div>
                          <Badge variant="outline" className="text-[10px] uppercase">
                            {(s.shell_type || "php").toUpperCase()}
                          </Badge>
                        </div>
                        <div
                          className="max-w-72 truncate font-mono text-xs text-muted-foreground"
                          title={s.webshell_url}
                        >
                          {s.host || "—"} · {s.webshell_url || "无 webshell"}
                        </div>
                      </TableCell>
                      <TableCell className="max-w-56 truncate font-mono text-xs" title={s.cwd}>
                        {s.cwd || "—"}
                      </TableCell>
                      <TableCell>
                        <Badge variant="outline" className={meta.className}>
                          {meta.label}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-muted-foreground text-xs">
                        {fmtTime(s.last_seen ?? s.updated_at)}
                      </TableCell>
                      <TableCell className="text-right">
                        <div className="flex items-center justify-end gap-1">
                          <Button
                            variant="ghost"
                            size="sm"
                            disabled={s.status !== "active"}
                            onClick={() => void openTerminal(s)}
                          >
                            <SquareTerminalIcon className="size-3.5" />
                            终端
                          </Button>
                          <Button
                            variant="ghost"
                            size="sm"
                            disabled={busyId === `session-${s.id}`}
                            onClick={() => void toggleSession(s)}
                          >
                            {s.status === "active" ? "关闭" : "重开"}
                          </Button>
                          <Button
                            variant="ghost"
                            size="sm"
                            disabled={busyId === `session-${s.id}`}
                            onClick={() => void removeSession(s)}
                          >
                            <Trash2Icon className="size-3.5" />
                          </Button>
                        </div>
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          )}
          {selected.size > 0 ? (
            <div className="flex flex-wrap items-center gap-2 rounded-md border bg-muted/40 px-3 py-2">
              <span className="text-sm">已选 {selected.size} 个会话</span>
              <Input
                value={batchCommand}
                onChange={(e) => setBatchCommand(e.target.value)}
                placeholder="批量命令，例如 hostname; id"
                className="max-w-md font-mono"
              />
              <Button size="sm" disabled={batchRunning} onClick={() => void runBatch()}>
                {batchRunning ? <Loader2Icon className="size-4 animate-spin" /> : <PlayIcon className="size-4" />}
                批量执行
              </Button>
              <Button variant="ghost" size="sm" onClick={() => setSelected(new Set())}>
                清除选择
              </Button>
            </div>
          ) : null}
        </TabsContent>

        <TabsContent value="tunnels" className="flex min-h-0 flex-1 flex-col gap-3">
          {tunnels.length === 0 ? (
            <div className="rounded-md border border-dashed py-12 text-center text-muted-foreground text-sm">
              还没有隧道。通过会话探测目标环境后，创建隧道并「规划 → 部署 → 验证」。
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>隧道</TableHead>
                  <TableHead className="w-28">类型</TableHead>
                  <TableHead className="w-64">端点</TableHead>
                  <TableHead className="w-20">状态</TableHead>
                  <TableHead className="w-20">PID</TableHead>
                  <TableHead className="w-72 text-right">操作</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {tunnels.map((t) => {
                  const meta = tunnelStatusMeta(t.status);
                  const busy = busyId?.startsWith(`tunnel-${t.id}-`);
                  return (
                    <TableRow key={t.id}>
                      <TableCell>
                        <div className="max-w-52 truncate font-medium text-sm" title={t.name}>
                          {t.name || `隧道 #${t.id}`}
                        </div>
                        <div className="text-muted-foreground text-xs">
                          会话 #{t.session_id ?? "—"}
                          {t.task_id ? ` · 任务 #${t.task_id}` : ""}
                        </div>
                      </TableCell>
                      <TableCell>
                        <Badge variant="outline">{TUNNEL_KIND_LABEL[t.kind] ?? t.kind}</Badge>
                      </TableCell>
                      <TableCell className="max-w-64 truncate font-mono text-xs" title={tunnelEndpoint(t)}>
                        {tunnelEndpoint(t)}
                      </TableCell>
                      <TableCell>
                        <Badge variant="outline" className={meta.className}>
                          {meta.label}
                        </Badge>
                      </TableCell>
                      <TableCell className="font-mono text-xs text-muted-foreground">{t.pid ?? "—"}</TableCell>
                      <TableCell className="text-right">
                        <div className="flex flex-wrap items-center justify-end gap-1">
                          <Button variant="ghost" size="sm" onClick={() => setDetailTunnel(t)}>
                            <EyeIcon className="size-3.5" />
                          </Button>
                          <Button
                            variant="ghost"
                            size="sm"
                            disabled={busy}
                            onClick={() => void tunnelAction(t, "probe")}
                          >
                            探测
                          </Button>
                          <Button
                            variant="ghost"
                            size="sm"
                            disabled={busy}
                            onClick={() => void tunnelAction(t, "plan")}
                          >
                            规划
                          </Button>
                          <Button
                            variant="ghost"
                            size="sm"
                            disabled={busy || t.status === "stopped"}
                            onClick={() => void tunnelAction(t, "deploy")}
                          >
                            部署
                          </Button>
                          <Button
                            variant="ghost"
                            size="sm"
                            disabled={busy || t.status === "stopped" || t.status === "planned"}
                            onClick={() => void tunnelAction(t, "verify")}
                          >
                            验证
                          </Button>
                          <Button
                            variant="ghost"
                            size="sm"
                            disabled={busy || t.status === "stopped"}
                            onClick={() => void tunnelAction(t, "teardown")}
                          >
                            拆除
                          </Button>
                          <Button variant="ghost" size="sm" disabled={busy} onClick={() => void removeTunnel(t)}>
                            <Trash2Icon className="size-3.5" />
                          </Button>
                        </div>
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          )}
        </TabsContent>

        <TabsContent value="scopes" className="flex min-h-0 flex-1 flex-col gap-3">
          <div className="flex items-center justify-between gap-3">
            <p className="text-muted-foreground text-sm">
              agent 在严格模式下遇到范围外主机时会提交申请；人工批准后写入任务范围，会话、隧道与后续 agent
              调用都会放行。
            </p>
            <Button size="sm" onClick={openCreateScope}>
              <KeyRoundIcon className="size-4" />
              发起申请
            </Button>
          </div>
          {requests.length === 0 ? (
            <div className="rounded-md border border-dashed py-12 text-center text-muted-foreground text-sm">
              暂无范围申请。
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-16">ID</TableHead>
                  <TableHead className="w-24">任务</TableHead>
                  <TableHead className="w-52">主机</TableHead>
                  <TableHead>原因</TableHead>
                  <TableHead className="w-24">状态</TableHead>
                  <TableHead className="w-32">申请时间</TableHead>
                  <TableHead className="w-40 text-right">操作</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {requests.map((r) => {
                  const meta = scopeStatusMeta(r.status);
                  return (
                    <TableRow key={r.id}>
                      <TableCell className="font-mono text-xs">#{r.id}</TableCell>
                      <TableCell className="font-mono text-xs">#{r.task_id}</TableCell>
                      <TableCell className="font-mono text-xs">
                        {r.host}
                        {r.port ? `:${r.port}` : ""}
                        {r.session_id ? <span className="text-muted-foreground"> · 会话 #{r.session_id}</span> : null}
                      </TableCell>
                      <TableCell className="max-w-72 truncate text-xs" title={r.reason}>
                        {r.reason || "—"}
                        {r.decided_note ? (
                          <span className="text-muted-foreground"> · 审批备注：{r.decided_note}</span>
                        ) : null}
                      </TableCell>
                      <TableCell>
                        <Badge variant="outline" className={meta.className}>
                          {meta.label}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-muted-foreground text-xs">{fmtTime(r.created_at)}</TableCell>
                      <TableCell className="text-right">
                        {r.status === "pending" ? (
                          <div className="flex items-center justify-end gap-1">
                            <Button
                              variant="ghost"
                              size="sm"
                              className="text-emerald-600"
                              onClick={() => {
                                setDecision({ request: r, approve: true });
                                setDecisionNote("");
                              }}
                            >
                              <CheckIcon className="size-3.5" />
                              批准
                            </Button>
                            <Button
                              variant="ghost"
                              size="sm"
                              className="text-red-600"
                              onClick={() => {
                                setDecision({ request: r, approve: false });
                                setDecisionNote("");
                              }}
                            >
                              <XIcon className="size-3.5" />
                              拒绝
                            </Button>
                          </div>
                        ) : (
                          <span className="text-muted-foreground text-xs">{fmtTime(r.decided_at)}</span>
                        )}
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          )}
        </TabsContent>
      </Tabs>

      {/* 新建会话 */}
      <Dialog open={sessionOpen} onOpenChange={setSessionOpen}>
        <DialogContent className="sm:max-w-lg">
          <DialogHeader>
            <DialogTitle>新建内网会话</DialogTitle>
            <DialogDescription>会话不驻留进程，每次执行都复用所选 webshell；工作目录由平台维护。</DialogDescription>
          </DialogHeader>
          <form
            className="flex flex-col gap-4"
            onSubmit={(e) => {
              e.preventDefault();
              void saveSession();
            }}
          >
            <FieldRow label="Webshell">
              <Select
                value={sessionForm.webshell_id}
                onValueChange={(v) => setSessionForm({ ...sessionForm, webshell_id: v })}
              >
                <SelectTrigger>
                  <SelectValue placeholder="选择已登记的 webshell" />
                </SelectTrigger>
                <SelectContent>
                  {webshells.map((w) => (
                    <SelectItem key={w.id} value={String(w.id)}>
                      {webshellLabel(w)}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </FieldRow>
            <FieldRow label="名称">
              <Input
                value={sessionForm.name}
                onChange={(e) => setSessionForm({ ...sessionForm, name: e.target.value })}
                placeholder="留空自动使用主机名"
              />
            </FieldRow>
            <FieldRow label="所属任务">
              <Select value={sessionForm.task_id} onValueChange={(v) => setSessionForm({ ...sessionForm, task_id: v })}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="none">不关联任务</SelectItem>
                  {tasks.map((t) => (
                    <SelectItem key={t.id} value={t.id}>
                      #{t.id} {taskLabel(t)}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </FieldRow>
            <FieldRow label="主机" hint="用于范围校验，留空从 webshell 地址推断">
              <Input
                value={sessionForm.host}
                onChange={(e) => setSessionForm({ ...sessionForm, host: e.target.value })}
                placeholder="10.0.0.5"
              />
            </FieldRow>
            <FieldRow label="初始目录">
              <Input
                value={sessionForm.cwd}
                onChange={(e) => setSessionForm({ ...sessionForm, cwd: e.target.value })}
                placeholder="/var/www"
              />
            </FieldRow>
            <FieldRow label="备注">
              <Textarea
                value={sessionForm.note}
                onChange={(e) => setSessionForm({ ...sessionForm, note: e.target.value })}
                rows={2}
              />
            </FieldRow>
            <DialogFooter>
              <Button type="submit" disabled={sessionSaving}>
                {sessionSaving ? <Loader2Icon className="size-4 animate-spin" /> : null}
                创建并探测
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>

      {/* 终端 */}
      <Dialog open={Boolean(termSession)} onOpenChange={(o) => !o && setTermSession(null)}>
        <DialogContent className="sm:max-w-4xl">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <SquareTerminalIcon className="size-4" />
              {termSession?.name || termSession?.host || "会话"}
              {termSession ? (
                <Badge variant="outline" className={sessionStatusMeta(termSession.status).className}>
                  {sessionStatusMeta(termSession.status).label}
                </Badge>
              ) : null}
            </DialogTitle>
            <DialogDescription className="flex flex-wrap items-center gap-2 font-mono text-xs">
              <span>{termSession?.webshell_url}</span>
              <span className="rounded bg-muted px-1.5 py-0.5">cwd: {termSession?.cwd || "—"}</span>
            </DialogDescription>
          </DialogHeader>
          <Tabs value={termMode} onValueChange={setTermMode}>
            <TabsList className="w-fit">
              <TabsTrigger value="exec">命令</TabsTrigger>
              <TabsTrigger value="upload">上传</TabsTrigger>
              <TabsTrigger value="download">下载</TabsTrigger>
            </TabsList>
            <TabsContent value="exec" className="flex flex-col gap-3">
              <ScrollArea className="h-80 rounded-md border">
                <div className="flex flex-col gap-3 p-3 font-mono text-xs">
                  {termLines.length === 0 ? (
                    <span className="text-muted-foreground">（无历史输出）</span>
                  ) : (
                    termLines.map((line) => (
                      <div key={line.id} className="flex flex-col gap-1">
                        <div className="text-muted-foreground">
                          <span className="text-emerald-600 dark:text-emerald-400">$ </span>
                          {line.command}
                          <span className="ml-2 text-[10px]">{fmtTime(line.at)}</span>
                        </div>
                        <pre
                          className={`whitespace-pre-wrap break-all rounded bg-muted/50 p-2 ${
                            line.isError ? "text-red-600 dark:text-red-400" : ""
                          }`}
                        >
                          {line.output || "（无输出）"}
                        </pre>
                      </div>
                    ))
                  )}
                </div>
              </ScrollArea>
              <div className="flex gap-2">
                <Input
                  value={termCommand}
                  onChange={(e) => setTermCommand(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter") void runTermCommand();
                  }}
                  placeholder="例如 id / uname -a"
                  className="font-mono"
                />
                <Button onClick={() => void runTermCommand()} disabled={termRunning}>
                  {termRunning ? <Loader2Icon className="size-4 animate-spin" /> : <PlayIcon className="size-4" />}
                  执行
                </Button>
              </div>
            </TabsContent>
            <TabsContent value="upload" className="flex flex-col gap-3">
              <FieldRow label="本地文件" hint="上限 4MB，分块 base64 写入">
                <Input
                  type="file"
                  onChange={(e) => {
                    const file = e.target.files?.[0] ?? null;
                    setUploadFile(file);
                    if (file && !uploadPath) setUploadPath(`/tmp/${file.name}`);
                  }}
                />
              </FieldRow>
              <FieldRow label="目标路径">
                <Input
                  value={uploadPath}
                  onChange={(e) => setUploadPath(e.target.value)}
                  placeholder="/tmp/tool"
                  className="font-mono"
                />
              </FieldRow>
              <div className="flex justify-end">
                <Button onClick={() => void doUpload()} disabled={termRunning || !uploadFile}>
                  {termRunning ? <Loader2Icon className="size-4 animate-spin" /> : <UploadIcon className="size-4" />}
                  上传
                </Button>
              </div>
              {uploadResult ? (
                <pre className="whitespace-pre-wrap break-all rounded-md border p-3 font-mono text-xs">
                  {uploadResult.output || uploadResult.note || "（无输出）"}
                </pre>
              ) : null}
            </TabsContent>
            <TabsContent value="download" className="flex flex-col gap-3">
              <FieldRow label="远程路径" hint="单次最多 512KB，超出会截断">
                <Input
                  value={downloadPath}
                  onChange={(e) => setDownloadPath(e.target.value)}
                  placeholder="/etc/passwd"
                  className="font-mono"
                />
              </FieldRow>
              <div className="flex justify-end">
                <Button onClick={() => void doDownload()} disabled={downloadBusy}>
                  {downloadBusy ? <Loader2Icon className="size-4 animate-spin" /> : <DownloadIcon className="size-4" />}
                  下载
                </Button>
              </div>
            </TabsContent>
          </Tabs>
        </DialogContent>
      </Dialog>

      {/* 批量执行结果 */}
      <Dialog
        open={batchOpen}
        onOpenChange={(o) => {
          setBatchOpen(o);
          if (!o) setBatchItems([]);
        }}
      >
        <DialogContent className="sm:max-w-3xl">
          <DialogHeader>
            <DialogTitle>批量执行</DialogTitle>
            <DialogDescription className="font-mono text-xs">
              {batchCommand} · {batchItems.length} 个会话
            </DialogDescription>
          </DialogHeader>
          {batchRunning ? (
            <div className="flex items-center justify-center py-10 text-muted-foreground text-sm">
              <Loader2Icon className="mr-2 size-4 animate-spin" />
              正在执行…
            </div>
          ) : (
            <ScrollArea className="max-h-96 rounded-md border">
              <div className="flex flex-col gap-3 p-3 font-mono text-xs">
                {batchItems.map((item) => (
                  <div key={item.session_id} className="flex flex-col gap-1">
                    <div className="text-muted-foreground">
                      <span className="text-emerald-600 dark:text-emerald-400"># </span>
                      {item.name || `会话 #${item.session_id}`}
                    </div>
                    <pre
                      className={`whitespace-pre-wrap break-all rounded bg-muted/50 p-2 ${
                        item.result.is_error || item.error ? "text-red-600 dark:text-red-400" : ""
                      }`}
                    >
                      {item.error || item.result.note || item.result.output || "（无输出）"}
                    </pre>
                  </div>
                ))}
              </div>
            </ScrollArea>
          )}
        </DialogContent>
      </Dialog>

      {/* 新建隧道 */}
      <Dialog open={tunnelOpen} onOpenChange={setTunnelOpen}>
        <DialogContent className="sm:max-w-2xl">
          <DialogHeader>
            <DialogTitle>新建隧道</DialogTitle>
            <DialogDescription>
              隧道绑定一个会话，命令在目标主机执行；端口转发由 socat 自动生成部署命令，SOCKS5 需手动填写。
            </DialogDescription>
          </DialogHeader>
          <form
            className="flex flex-col gap-4"
            onSubmit={(e) => {
              e.preventDefault();
              void saveTunnel();
            }}
          >
            <div className="grid grid-cols-2 gap-3">
              <FieldRow label="名称">
                <Input
                  value={tunnelForm.name}
                  onChange={(e) => setTunnelForm({ ...tunnelForm, name: e.target.value })}
                  placeholder="内网 8080"
                />
              </FieldRow>
              <FieldRow label="类型">
                <Select value={tunnelForm.kind} onValueChange={(v) => setTunnelForm({ ...tunnelForm, kind: v })}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="port_forward">端口转发</SelectItem>
                    <SelectItem value="reverse_forward">反向转发</SelectItem>
                    <SelectItem value="socks5">SOCKS5（自定义命令）</SelectItem>
                  </SelectContent>
                </Select>
              </FieldRow>
            </div>
            <FieldRow label="承载会话">
              <Select
                value={tunnelForm.session_id}
                onValueChange={(v) => setTunnelForm({ ...tunnelForm, session_id: v })}
              >
                <SelectTrigger>
                  <SelectValue placeholder="选择会话" />
                </SelectTrigger>
                <SelectContent>
                  {sessions
                    .filter((s) => s.status === "active")
                    .map((s) => (
                      <SelectItem key={s.id} value={String(s.id)}>
                        #{s.id} {s.name || s.host}
                      </SelectItem>
                    ))}
                </SelectContent>
              </Select>
            </FieldRow>
            <div className="grid grid-cols-2 gap-3">
              <FieldRow label="监听地址" hint="目标侧绑定地址，默认仅本机">
                <Input
                  value={tunnelForm.listen_host}
                  onChange={(e) => setTunnelForm({ ...tunnelForm, listen_host: e.target.value })}
                  className="font-mono"
                />
              </FieldRow>
              <FieldRow label="监听端口">
                <Input
                  value={tunnelForm.listen_port}
                  onChange={(e) => setTunnelForm({ ...tunnelForm, listen_port: e.target.value })}
                  placeholder="8080"
                  inputMode="numeric"
                  className="font-mono"
                />
              </FieldRow>
            </div>
            <div className="grid grid-cols-2 gap-3">
              <FieldRow label="远端地址" hint="从目标主机访问的地址">
                <Input
                  value={tunnelForm.remote_host}
                  onChange={(e) => setTunnelForm({ ...tunnelForm, remote_host: e.target.value })}
                  className="font-mono"
                />
              </FieldRow>
              <FieldRow label="远端端口">
                <Input
                  value={tunnelForm.remote_port}
                  onChange={(e) => setTunnelForm({ ...tunnelForm, remote_port: e.target.value })}
                  placeholder="80"
                  inputMode="numeric"
                  className="font-mono"
                />
              </FieldRow>
            </div>
            <FieldRow label="所属任务">
              <Select value={tunnelForm.task_id} onValueChange={(v) => setTunnelForm({ ...tunnelForm, task_id: v })}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="none">跟随会话</SelectItem>
                  {tasks.map((t) => (
                    <SelectItem key={t.id} value={t.id}>
                      #{t.id} {taskLabel(t)}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </FieldRow>
            <FieldRow label="部署命令" hint="留空自动生成；SOCKS5 必填">
              <Textarea
                value={tunnelForm.deploy_command}
                onChange={(e) => setTunnelForm({ ...tunnelForm, deploy_command: e.target.value })}
                rows={2}
                className="font-mono text-xs"
                placeholder="nohup socat ... & echo JW_PID:$!"
              />
            </FieldRow>
            <div className="grid grid-cols-2 gap-3">
              <FieldRow label="验证命令" hint="留空按监听端口生成">
                <Textarea
                  value={tunnelForm.verify_command}
                  onChange={(e) => setTunnelForm({ ...tunnelForm, verify_command: e.target.value })}
                  rows={2}
                  className="font-mono text-xs"
                />
              </FieldRow>
              <FieldRow label="拆除命令" hint="留空按部署 PID 生成">
                <Textarea
                  value={tunnelForm.teardown_command}
                  onChange={(e) => setTunnelForm({ ...tunnelForm, teardown_command: e.target.value })}
                  rows={2}
                  className="font-mono text-xs"
                />
              </FieldRow>
            </div>
            <FieldRow label="备注">
              <Input value={tunnelForm.note} onChange={(e) => setTunnelForm({ ...tunnelForm, note: e.target.value })} />
            </FieldRow>
            <DialogFooter>
              <Button type="submit" disabled={tunnelSaving}>
                {tunnelSaving ? <Loader2Icon className="size-4 animate-spin" /> : null}
                登记隧道
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>

      {/* 隧道详情 */}
      <Dialog open={Boolean(detailTunnel)} onOpenChange={(o) => !o && setDetailTunnel(null)}>
        <DialogContent className="sm:max-w-3xl">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <NetworkIcon className="size-4" />
              {detailTunnel?.name || `隧道 #${detailTunnel?.id}`}
              {detailTunnel ? (
                <Badge variant="outline" className={tunnelStatusMeta(detailTunnel.status).className}>
                  {tunnelStatusMeta(detailTunnel.status).label}
                </Badge>
              ) : null}
            </DialogTitle>
            <DialogDescription className="font-mono text-xs">
              {detailTunnel ? tunnelEndpoint(detailTunnel) : ""}
            </DialogDescription>
          </DialogHeader>
          {detailTunnel ? (
            <div className="flex flex-col gap-3 text-sm">
              <div className="grid grid-cols-2 gap-2 text-xs">
                <div>
                  <span className="text-muted-foreground">会话：</span>#{detailTunnel.session_id ?? "—"}
                </div>
                <div>
                  <span className="text-muted-foreground">任务：</span>
                  {detailTunnel.task_id ? `#${detailTunnel.task_id}` : "—"}
                </div>
                <div>
                  <span className="text-muted-foreground">PID：</span>
                  {detailTunnel.pid ?? "—"}
                </div>
                <div>
                  <span className="text-muted-foreground">更新时间：</span>
                  {fmtTime(detailTunnel.updated_at)}
                </div>
              </div>
              {(
                [
                  ["部署命令", detailTunnel.deploy_command],
                  ["验证命令", detailTunnel.verify_command],
                  ["拆除命令", detailTunnel.teardown_command],
                ] as const
              ).map(([label, value]) => (
                <div key={label} className="flex flex-col gap-1">
                  <div className="text-muted-foreground text-xs">{label}</div>
                  <pre className="whitespace-pre-wrap break-all rounded-md border p-2 font-mono text-xs">
                    {value || "（未设置）"}
                  </pre>
                </div>
              ))}
              <div className="flex flex-col gap-1">
                <div className="text-muted-foreground text-xs">证据 / 输出</div>
                <ScrollArea className="h-52 rounded-md border">
                  <pre className="whitespace-pre-wrap break-all p-2 font-mono text-xs">
                    {detailTunnel.evidence || "（无）"}
                  </pre>
                </ScrollArea>
              </div>
            </div>
          ) : null}
        </DialogContent>
      </Dialog>

      {/* 发起范围申请 */}
      <Dialog open={scopeOpen} onOpenChange={setScopeOpen}>
        <DialogContent className="sm:max-w-lg">
          <DialogHeader>
            <DialogTitle>发起范围申请</DialogTitle>
            <DialogDescription>审批通过后会把主机写入任务范围，后续会话/隧道与 agent 调用均放行。</DialogDescription>
          </DialogHeader>
          <form
            className="flex flex-col gap-4"
            onSubmit={(e) => {
              e.preventDefault();
              void saveScope();
            }}
          >
            <FieldRow label="所属任务">
              <Select value={scopeForm.task_id} onValueChange={(v) => setScopeForm({ ...scopeForm, task_id: v })}>
                <SelectTrigger>
                  <SelectValue placeholder="选择任务" />
                </SelectTrigger>
                <SelectContent>
                  {tasks.map((t) => (
                    <SelectItem key={t.id} value={t.id}>
                      #{t.id} {taskLabel(t)}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </FieldRow>
            <div className="grid grid-cols-2 gap-3">
              <FieldRow label="主机">
                <Input
                  value={scopeForm.host}
                  onChange={(e) => setScopeForm({ ...scopeForm, host: e.target.value })}
                  placeholder="10.0.0.5"
                  className="font-mono"
                />
              </FieldRow>
              <FieldRow label="端口" hint="留空表示整机">
                <Input
                  value={scopeForm.port}
                  onChange={(e) => setScopeForm({ ...scopeForm, port: e.target.value })}
                  placeholder="8080"
                  inputMode="numeric"
                  className="font-mono"
                />
              </FieldRow>
            </div>
            <FieldRow label="关联会话">
              <Select value={scopeForm.session_id} onValueChange={(v) => setScopeForm({ ...scopeForm, session_id: v })}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="none">不关联</SelectItem>
                  {sessions.map((s) => (
                    <SelectItem key={s.id} value={String(s.id)}>
                      #{s.id} {s.name || s.host}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </FieldRow>
            <FieldRow label="申请原因">
              <Textarea
                value={scopeForm.reason}
                onChange={(e) => setScopeForm({ ...scopeForm, reason: e.target.value })}
                rows={3}
                placeholder="说明为什么要访问该主机"
              />
            </FieldRow>
            <DialogFooter>
              <Button type="submit" disabled={scopeSaving}>
                {scopeSaving ? <Loader2Icon className="size-4 animate-spin" /> : null}
                提交申请
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>

      {/* 审批 */}
      <Dialog open={Boolean(decision)} onOpenChange={(o) => !o && setDecision(null)}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>{decision?.approve ? "批准范围申请" : "拒绝范围申请"}</DialogTitle>
            <DialogDescription className="font-mono text-xs">
              任务 #{decision?.request.task_id} · {decision?.request.host}
              {decision?.request.port ? `:${decision.request.port}` : ""}
            </DialogDescription>
          </DialogHeader>
          <div className="flex flex-col gap-3">
            <div className="rounded-md border bg-muted/40 p-3 text-xs">
              {decision?.request.reason || "（无申请原因）"}
            </div>
            <FieldRow label="审批备注">
              <Textarea
                value={decisionNote}
                onChange={(e) => setDecisionNote(e.target.value)}
                rows={2}
                placeholder="可选"
              />
            </FieldRow>
            <DialogFooter>
              <Button variant="outline" onClick={() => setDecision(null)} disabled={decisionBusy}>
                取消
              </Button>
              {decision?.approve ? (
                <Button onClick={() => void submitDecision()} disabled={decisionBusy}>
                  {decisionBusy ? (
                    <Loader2Icon className="size-4 animate-spin" />
                  ) : (
                    <ShieldCheckIcon className="size-4" />
                  )}
                  批准并写入范围
                </Button>
              ) : (
                <Button variant="destructive" onClick={() => void submitDecision()} disabled={decisionBusy}>
                  {decisionBusy ? <Loader2Icon className="size-4 animate-spin" /> : <XIcon className="size-4" />}
                  拒绝
                </Button>
              )}
            </DialogFooter>
          </div>
        </DialogContent>
      </Dialog>

      {/* 任务交接 */}
      <Dialog open={handoffOpen} onOpenChange={setHandoffOpen}>
        <DialogContent className="sm:max-w-lg">
          <DialogHeader>
            <DialogTitle>任务交接</DialogTitle>
            <DialogDescription>
              创建新任务并继承来源任务的范围、会话与隧道（留空默认迁移全部）；新任务可继续由 agent 或人工推进。
            </DialogDescription>
          </DialogHeader>
          <form
            className="flex flex-col gap-4"
            onSubmit={(e) => {
              e.preventDefault();
              void saveHandoff();
            }}
          >
            <FieldRow label="来源任务">
              <Select
                value={handoffForm.from_task_id}
                onValueChange={(v) => setHandoffForm({ ...handoffForm, from_task_id: v })}
              >
                <SelectTrigger>
                  <SelectValue placeholder="选择要交接的任务" />
                </SelectTrigger>
                <SelectContent>
                  {tasks.map((t) => (
                    <SelectItem key={t.id} value={t.id}>
                      #{t.id} {taskLabel(t)}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </FieldRow>
            <FieldRow label="新任务名称">
              <Input
                value={handoffForm.name}
                onChange={(e) => setHandoffForm({ ...handoffForm, name: e.target.value })}
                placeholder="留空自动生成"
              />
            </FieldRow>
            <FieldRow label="新任务目标">
              <Textarea
                value={handoffForm.goal}
                onChange={(e) => setHandoffForm({ ...handoffForm, goal: e.target.value })}
                rows={3}
                placeholder="留空沿用来源任务目标"
              />
            </FieldRow>
            <FieldRow label="新任务描述">
              <Textarea
                value={handoffForm.description}
                onChange={(e) => setHandoffForm({ ...handoffForm, description: e.target.value })}
                rows={2}
                placeholder="留空沿用来源任务描述"
              />
            </FieldRow>
            <DialogFooter>
              <Button type="submit" disabled={handoffSaving}>
                {handoffSaving ? (
                  <Loader2Icon className="size-4 animate-spin" />
                ) : (
                  <ArrowRightLeftIcon className="size-4" />
                )}
                创建交接任务
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>
    </div>
  );
}
