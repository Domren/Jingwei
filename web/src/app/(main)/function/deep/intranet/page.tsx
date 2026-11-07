"use client";

import * as React from "react";

import {
  ActivityIcon,
  ArrowRightLeftIcon,
  CheckIcon,
  DownloadIcon,
  EraserIcon,
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
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectLabel,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
import { api } from "@/lib/api";
import type {
  IntranetArtifact,
  IntranetBatchItem,
  IntranetCredential,
  IntranetEvacuationReport,
  IntranetExecResult,
  IntranetScopeRequest,
  IntranetScript,
  IntranetScriptRun,
  IntranetSession,
  IntranetSessionEvent,
  IntranetTunnel,
  Task,
  Webshell,
} from "@/lib/types";

import { FieldRow, fmtTime } from "../_components/deep-ui";
import { fmtDuration, ShellTerminal, shellExitBadge } from "../_components/shell-terminal";

// ExecOutcome 是「一次操作一个结果」的展示：终端页签已经习惯的退出码、耗时与
// 「超时」，在上传/下载页签里也不该退化成把 note 拼进输出的一坨文本——那正是
// 「命令不返回」被读成「这个 shell 坏了」的地方。
function ExecOutcome({ result, extra }: { result: IntranetExecResult; extra?: string }) {
  const badge = shellExitBadge(result);
  return (
    <div className="flex flex-col gap-1">
      <div className="flex flex-wrap items-center gap-2 text-muted-foreground text-xs">
        <Badge variant="outline" className={`h-4 px-1.5 text-[10px] ${badge.className}`}>
          exit {badge.label}
        </Badge>
        <span>{fmtDuration(result.duration_ms)}</span>
        {result.cwd ? <span className="font-mono">{result.cwd}</span> : null}
        {extra ? <span>{extra}</span> : null}
      </div>
      <pre
        className={`whitespace-pre-wrap break-all rounded-md border p-3 font-mono text-xs ${
          result.is_error ? "text-red-600 dark:text-red-400" : ""
        }`}
      >
        {result.output || "（无输出）"}
      </pre>
      {result.note && result.note !== result.output ? (
        <div className="text-amber-600 dark:text-amber-400 text-xs">{result.note}</div>
      ) : null}
    </div>
  );
}

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

function sessionHealthMeta(metadata: Record<string, unknown> | undefined) {
  const health = typeof metadata?.health === "string" ? metadata.health : "";
  const failures = Number(metadata?.health_failures ?? 0);
  const latency = Number(metadata?.health_latency_ms ?? 0);
  const err = typeof metadata?.health_error === "string" ? metadata.health_error : "";
  switch (health) {
    case "ok":
      return {
        label: latency > 0 ? `存活 ${latency}ms` : "存活",
        className: "border-emerald-500/30 bg-emerald-500/10 text-emerald-600",
        title: err,
      };
    case "degraded":
      return {
        label: `心跳异常 ${failures}/3`,
        className: "border-amber-500/30 bg-amber-500/10 text-amber-600",
        title: err,
      };
    case "lost":
      return {
        label: "失联",
        className: "border-red-500/30 bg-red-500/10 text-red-600 dark:text-red-400",
        title: err,
      };
    default:
      return null;
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

const ARTIFACT_KIND_LABEL: Record<string, string> = {
  file: "文件",
  cron: "计划任务",
  systemd: "systemd 服务",
  user_systemd: "用户 systemd",
  at: "at 任务",
  profile: "profile 启动项",
  ssh_key: "SSH 公钥",
  schtasks: "Windows 计划任务",
  registry: "注册表 Run",
  service: "Windows 服务",
  wmi: "WMI 订阅",
  startup: "启动文件夹",
  php_user_ini: "PHP .user.ini",
  php_htaccess: "PHP .htaccess",
  other: "其它",
};

const CRED_SOURCE_LABEL: Record<string, string> = {
  weakpass: "弱口令命中",
  reuse: "横向复用",
  manual: "人工登记",
  intel: "情报",
  config: "配置文件",
  browser: "浏览器",
};

interface PersistKindMeta {
  label: string;
  os: "linux" | "windows";
  schedule?: { label: string; hint: string; placeholder: string; fallback: string };
  user?: boolean;
  publicKey?: boolean;
  command?: boolean;
}

const PERSIST_KIND_META: Record<string, PersistKindMeta> = {
  cron: {
    label: "cron 计划任务",
    os: "linux",
    schedule: {
      label: "cron 表达式",
      hint: "5 段或 @reboot/@daily 等",
      placeholder: "*/10 * * * *",
      fallback: "*/10 * * * *",
    },
    command: true,
  },
  systemd: { label: "systemd 系统服务", os: "linux", command: true },
  user_systemd: { label: "用户级 systemd", os: "linux", user: true, command: true },
  at: {
    label: "at 一次性任务",
    os: "linux",
    schedule: {
      label: "触发时间",
      hint: "at 时间语法；重启后需重新登记",
      placeholder: "now + 10 minutes",
      fallback: "now + 10 minutes",
    },
    user: true,
    command: true,
  },
  profile: {
    label: "profile 登录启动",
    os: "linux",
    schedule: { label: "目标文件", hint: "用户家目录下的点文件", placeholder: ".profile", fallback: ".profile" },
    user: true,
    command: true,
  },
  ssh_key: { label: "SSH 公钥", os: "linux", user: true, publicKey: true },
  schtasks: {
    label: "计划任务 (schtasks)",
    os: "windows",
    schedule: {
      label: "触发规则",
      hint: "onlogon / onstart / minute:N / hourly:N / daily:HH:MM",
      placeholder: "onlogon",
      fallback: "onlogon",
    },
    command: true,
  },
  registry: { label: "注册表 Run 键", os: "windows", command: true },
  service: { label: "Windows 服务", os: "windows", command: true },
  wmi: { label: "WMI 事件订阅", os: "windows", command: true },
  startup: { label: "启动文件夹", os: "windows", command: true },
};

function artifactStatusMeta(status: string) {
  switch (status) {
    case "active":
      return { label: "生效中", className: "border-amber-500/30 bg-amber-500/10 text-amber-600" };
    case "revoked":
      return { label: "已撤销", className: "border-emerald-500/30 bg-emerald-500/10 text-emerald-600" };
    default:
      return { label: status || "—", className: "" };
  }
}

// 判据用前缀而不是全等：服务端改措辞（「未配置验证命令，无法复核」这类）时，
// 不能让一个没验证过的结论显示成绿色。
function traceVerdictClass(verdict: string) {
  if (verdict.startsWith("已验证")) return "bg-emerald-500/15 text-emerald-700 dark:text-emerald-400";
  if (verdict.startsWith("撤销失败")) return "bg-red-500/15 text-red-700 dark:text-red-400";
  return "bg-amber-500/15 text-amber-700 dark:text-amber-400";
}

function credentialStatusMeta(status: string) {
  switch (status) {
    case "valid":
      return { label: "已验证可用", className: "border-emerald-500/30 bg-emerald-500/10 text-emerald-600" };
    case "invalid":
      return { label: "已失效", className: "border-red-500/30 bg-red-500/10 text-red-600 dark:text-red-400" };
    default:
      return { label: "待验证", className: "border-slate-500/30 bg-slate-500/10 text-slate-600 dark:text-slate-400" };
  }
}

function credentialLabel(c: IntranetCredential) {
  const port = c.port ? `:${c.port}` : "";
  return `#${c.id} ${c.username}@${c.host}${port} · ${(c.protocol || "http").toUpperCase()} · ${
    CRED_SOURCE_LABEL[c.source] ?? c.source
  }`;
}

function tunnelEndpoint(t: IntranetTunnel) {
  // 监听端在控制端（chisel client 不带 R:）时，listen_host 是 chisel server 的绑定地址，
  // 要连的是控制端；写成目标地址会把人引向一个从未开过的端口。
  const listen =
    t.listen_side === "pivot" ? `控制端:${t.listen_port}` : `${t.listen_host || "0.0.0.0"}:${t.listen_port}`;
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

// SSH 会话没有 webshell：承载它的是凭据台账里的一条账号，目标是只有 22 端口 open
// 的内网主机。列表里必须一眼分清两种承载方式，否则「无 webshell」看起来像坏了。
function sessionTransportLabel(session: IntranetSession) {
  return session.transport === "ssh" ? "SSH" : (session.shell_type || "php").toUpperCase();
}

function sessionEndpoint(session: IntranetSession) {
  if (session.transport !== "ssh") {
    return `${session.host || "—"} · ${session.webshell_url || "无 webshell"}`;
  }
  const identity = `${session.host || "—"}:${session.ssh_port || 22}`;
  const via = session.ssh_dial_host
    ? ` 经 ${session.ssh_dial_host}:${session.ssh_dial_port || session.ssh_port || 22}`
    : "";
  return `${identity}${via} · ${session.ssh_user || "?"}`;
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

export default function DeepIntranetPage() {
  const [sessions, setSessions] = React.useState<IntranetSession[]>([]);
  const [tunnels, setTunnels] = React.useState<IntranetTunnel[]>([]);
  const [requests, setRequests] = React.useState<IntranetScopeRequest[]>([]);
  const [artifacts, setArtifacts] = React.useState<IntranetArtifact[]>([]);
  const [credentials, setCredentials] = React.useState<IntranetCredential[]>([]);
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
        const [s, t, r, a, c] = await Promise.all([
          api.intranetSessions({ limit: 200 }),
          api.intranetTunnels({ limit: 200 }),
          api.intranetScopeRequests({ limit: 200 }),
          api.intranetArtifacts({ limit: 200 }),
          api.intranetCredentials({ limit: 200 }),
        ]);
        if (!alive) return;
        setSessions(s.sessions ?? []);
        setTunnels(t.tunnels ?? []);
        setRequests(r.requests ?? []);
        setArtifacts(a.artifacts ?? []);
        setCredentials(c.credentials ?? []);
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
    transport: "webshell",
    webshell_id: "",
    name: "",
    task_id: "none",
    host: "",
    cwd: "",
    note: "",
    port: "22",
    user: "",
    credential_id: "",
    dial_host: "",
    dial_port: "",
  });

  function openCreateSession() {
    setSessionForm({
      transport: "webshell",
      webshell_id: "",
      name: "",
      task_id: "none",
      host: "",
      cwd: "",
      note: "",
      port: "22",
      user: "",
      credential_id: "",
      dial_host: "",
      dial_port: "",
    });
    setSessionOpen(true);
  }

  function pickSessionCredential(id: string) {
    const c = credentials.find((x) => String(x.id) === id);
    setSessionForm((f) => ({
      ...f,
      credential_id: id,
      host: f.host.trim() || c?.host || "",
      user: f.user.trim() || c?.username || "",
      // 只有登记成 SSH 的凭据才带着 22 这类端口；HTTP 凭据的 80 不能当成 SSH 端口。
      port: c?.protocol === "ssh" && c.port > 0 ? String(c.port) : f.port,
    }));
  }

  async function saveSession() {
    const isSSH = sessionForm.transport === "ssh";
    if (!isSSH && !sessionForm.webshell_id) {
      toast.error("请选择要复用的 webshell");
      return;
    }
    if (isSSH && !sessionForm.host.trim()) {
      toast.error("SSH 会话需要目标在内网段里的地址，例如 10.99.0.20");
      return;
    }
    if (isSSH && !sessionForm.credential_id.trim()) {
      toast.error("SSH 会话必须绑定凭据台账里的一条凭据");
      return;
    }
    setSessionSaving(true);
    try {
      const r = await api.createIntranetSession(
        isSSH
          ? {
              transport: "ssh",
              name: sessionForm.name.trim(),
              task_id: sessionForm.task_id !== "none" ? Number(sessionForm.task_id) : undefined,
              host: sessionForm.host.trim(),
              port: Number(sessionForm.port) || 22,
              user: sessionForm.user.trim(),
              credential_id: Number(sessionForm.credential_id),
              dial_host: sessionForm.dial_host.trim() || undefined,
              dial_port: sessionForm.dial_port.trim() ? Number(sessionForm.dial_port) : undefined,
              cwd: sessionForm.cwd.trim(),
              note: sessionForm.note,
            }
          : {
              webshell_id: Number(sessionForm.webshell_id),
              name: sessionForm.name.trim(),
              task_id: sessionForm.task_id !== "none" ? Number(sessionForm.task_id) : undefined,
              host: sessionForm.host.trim(),
              cwd: sessionForm.cwd.trim(),
              note: sessionForm.note,
            },
      );
      setSessionOpen(false);
      refresh();
      const probe = r.probe;
      if (r.probe_error) {
        toast.warning(`会话已建立，但初始探测异常：${r.probe_error}`);
      } else {
        toast.success(`会话已建立${probe?.host ? ` · ${probe.host}` : ""}${probe?.user ? ` · ${probe.user}` : ""}`);
      }
      // 探测失败的 SSH 会话会被平台关掉：打开一个只会每条命令都报同一个错的终端，
      // 只会让人以为是执行坏了，而不是登录坏了。
      if (r.session.status !== "closed") void openTerminal(r.session);
    } catch (e) {
      toast.error((e as Error).message);
    } finally {
      setSessionSaving(false);
    }
  }

  // ---- 终端 ----
  // 命令页签交给共用的 ShellTerminal；「执行记录」是会话台账的事件流（含 worker 与
  // 其它标签页跑过的命令）。两者分开而不是混成一份输出：事件里没有退出码和结束标记，
  // 硬塞进终端只会显示假的 exit 0。
  const [termSession, setTermSession] = React.useState<IntranetSession | null>(null);
  const [scriptSession, setScriptSession] = React.useState<IntranetSession | null>(null);
  const [scriptCatalog, setScriptCatalog] = React.useState<IntranetScript[]>([]);
  const [scriptRuns, setScriptRuns] = React.useState<IntranetScriptRun[]>([]);
  const [scriptBusy, setScriptBusy] = React.useState(false);
  const [termEvents, setTermEvents] = React.useState<IntranetSessionEvent[]>([]);
  const [termMode, setTermMode] = React.useState("exec");
  const [uploadFile, setUploadFile] = React.useState<File | null>(null);
  const [uploadPath, setUploadPath] = React.useState("");
  const [uploadResult, setUploadResult] = React.useState<IntranetExecResult | null>(null);
  const [uploadBusy, setUploadBusy] = React.useState(false);
  const [downloadPath, setDownloadPath] = React.useState("");
  const [downloadBusy, setDownloadBusy] = React.useState(false);
  const [downloadResult, setDownloadResult] = React.useState<{ result: IntranetExecResult; extra?: string } | null>(
    null,
  );

  const loadTermEvents = React.useCallback(async (id: number) => {
    try {
      const r = await api.intranetSessionEvents(id, 50);
      setTermEvents(r.events ?? []);
    } catch {
      // 读不到历史不影响执行
    }
  }, []);

  const openScripts = React.useCallback(async (sess: IntranetSession) => {
    setScriptSession(sess);
    setScriptRuns([]);
    try {
      const [catalog, runs] = await Promise.all([api.intranetScripts(), api.intranetScriptRuns(sess.id)]);
      setScriptCatalog(catalog);
      setScriptRuns(runs);
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "读取信息收集脚本失败");
    }
  }, []);

  async function runScript(scriptId: string) {
    if (!scriptSession) return;
    setScriptBusy(true);
    try {
      const r = await api.runIntranetScript(scriptSession.id, scriptId);
      setScriptRuns((prev) => [r.run, ...prev.filter((x) => x.id !== r.run.id)]);
      toast.success(`已执行「${r.run.name}」`);
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "脚本执行失败");
    } finally {
      setScriptBusy(false);
    }
  }

  const openTerminal = React.useCallback(
    (session: IntranetSession) => {
      setTermSession(session);
      setTermMode("exec");
      setUploadFile(null);
      setUploadPath("");
      setUploadResult(null);
      setDownloadPath("");
      setDownloadResult(null);
      setTermEvents([]);
      void loadTermEvents(session.id);
    },
    [loadTermEvents],
  );

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
    setUploadBusy(true);
    setUploadResult(null);
    try {
      const b64 = await readFileBase64(uploadFile);
      const r = await api.intranetUpload(termSession.id, uploadPath.trim(), b64);
      setTermSession(r.session);
      setUploadResult(r.result);
      void loadTermEvents(termSession.id);
      if (r.result.is_error) {
        toast.error(r.result.note || "上传失败");
      } else {
        toast.success("上传完成");
      }
      refresh();
    } catch (e) {
      toast.error((e as Error).message);
    } finally {
      setUploadBusy(false);
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
      setDownloadResult({ result: r.result });
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
      const extra = `已下载 ${fmtBytes(r.size)}${r.truncated ? `（文件共 ${fmtBytes(r.total)}，已截断）` : ""}`;
      setDownloadResult({ result: r.result, extra });
      toast.success(extra);
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

  async function pingSession(session: IntranetSession) {
    setBusyId(`session-${session.id}`);
    try {
      const r = await api.intranetSessionHeartbeat(session.id);
      if (r.alive) {
        toast.success("会话存活");
      } else {
        toast.error(`心跳失败：${r.result.note || r.result.output || "目标未返回标记"}`);
      }
      refresh();
    } catch (e) {
      toast.error((e as Error).message);
    } finally {
      setBusyId(null);
    }
  }

  async function failoverSession(session: IntranetSession) {
    if (!window.confirm(`为会话「${session.name || session.host}」自动切换同主机的备用 webshell？`)) return;
    setBusyId(`session-${session.id}`);
    try {
      const r = await api.intranetSessionFailover(session.id);
      toast.success(`已切换到 webshell #${r.webshell.id}（${r.latency_ms} ms）`);
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
    listen_side: "target",
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
      listen_side: "target",
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
        listen_side: tunnelForm.listen_side,
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

  // ---- 落地物台账与撤离清理 ----
  const [artifactOpen, setArtifactOpen] = React.useState(false);
  const [artifactMode, setArtifactMode] = React.useState<"persist" | "manual">("persist");
  const [artifactSaving, setArtifactSaving] = React.useState(false);
  const [artifactFilter, setArtifactFilter] = React.useState<"all" | "active" | "revoked">("all");
  const [artifactForm, setArtifactForm] = React.useState({
    session_id: "",
    task_id: "none",
    persist_kind: "cron",
    name: "",
    description: "",
    schedule: "*/10 * * * *",
    command: "",
    public_key: "",
    user: "",
    ttl_seconds: "",
    path: "",
    revoke_command: "",
    verify_command: "",
  });

  const activeArtifacts = artifacts.filter((a) => a.status === "active").length;
  const shownArtifacts = artifactFilter === "all" ? artifacts : artifacts.filter((a) => a.status === artifactFilter);
  const persistMeta = PERSIST_KIND_META[artifactForm.persist_kind] ?? PERSIST_KIND_META.cron;

  function openCreateArtifact() {
    const active = sessions.find((s) => s.status === "active");
    setArtifactMode("persist");
    setArtifactForm({
      session_id: active ? String(active.id) : "",
      task_id: active?.task_id ? String(active.task_id) : "none",
      persist_kind: "cron",
      name: "",
      description: "",
      schedule: "*/10 * * * *",
      command: "",
      public_key: "",
      user: "",
      ttl_seconds: "",
      path: "",
      revoke_command: "",
      verify_command: "",
    });
    setArtifactOpen(true);
  }

  async function saveArtifact() {
    const sessionId = Number(artifactForm.session_id);
    if (!sessionId) {
      toast.error("请选择内网会话");
      return;
    }
    setArtifactSaving(true);
    try {
      const taskId = artifactForm.task_id === "none" ? undefined : Number(artifactForm.task_id);
      const ttl = artifactForm.ttl_seconds.trim();
      const ttlSeconds = ttl ? Number(ttl) : undefined;
      if (ttlSeconds !== undefined && (!Number.isFinite(ttlSeconds) || ttlSeconds < 60 || ttlSeconds > 2592000)) {
        toast.error("TTL 需在 60 到 2592000 秒（30 天）之间");
        return;
      }
      if (artifactMode === "persist") {
        const kind = artifactForm.persist_kind;
        const needsSchedule = ["cron", "at", "profile", "schtasks"].includes(kind);
        const needsUser = ["ssh_key", "user_systemd", "at", "profile"].includes(kind);
        const r = await api.persistIntranetSession(sessionId, {
          kind,
          name: artifactForm.name.trim(),
          description: artifactForm.description.trim(),
          schedule: needsSchedule ? artifactForm.schedule.trim() : undefined,
          command: kind === "ssh_key" ? undefined : artifactForm.command.trim(),
          public_key: kind === "ssh_key" ? artifactForm.public_key.trim() : undefined,
          user: needsUser ? artifactForm.user.trim() : undefined,
          ttl_seconds: ttlSeconds,
          task_id: taskId,
        });
        if (!r.deployed) {
          toast.error(r.error || "部署未通过验证，已登记台账供撤离清理");
        } else if (r.reused) {
          toast.success(`落地物 #${r.artifact.id} 已在位，已幂等复用`);
        } else {
          toast.success(`已部署并登记落地物 #${r.artifact.id}`);
        }
      } else {
        const revoke = artifactForm.revoke_command.trim();
        if (!revoke) {
          toast.error("撤销命令必填：无法撤销的落地物不允许登记");
          return;
        }
        await api.registerIntranetArtifact({
          session_id: sessionId,
          task_id: taskId,
          kind: "other",
          name: artifactForm.name.trim(),
          path: artifactForm.path.trim(),
          description: artifactForm.description.trim(),
          revoke_command: revoke,
          verify_command: artifactForm.verify_command.trim(),
          ttl_seconds: ttlSeconds,
        });
        toast.success("已登记落地物");
      }
      setArtifactOpen(false);
      refresh();
    } catch (e) {
      toast.error((e as Error).message);
    } finally {
      setArtifactSaving(false);
    }
  }

  async function revokeArtifact(art: IntranetArtifact) {
    if (!window.confirm(`撤销落地物 #${art.id}「${art.name || art.path}」？会执行撤销命令并验证痕迹消失。`)) return;
    setBusyId(`artifact-${art.id}`);
    try {
      const r = await api.revokeIntranetArtifact(art.id);
      if (!r.revoked) toast.error(r.error || "撤销未通过验证");
      else toast.success(`落地物 #${art.id} 已撤销`);
      refresh();
    } catch (e) {
      toast.error((e as Error).message);
    } finally {
      setBusyId(null);
    }
  }

  // ---- 凭据台账：口令只写不读，界面里永远看不见明文 ----
  const [credFilter, setCredFilter] = React.useState<"all" | "untested" | "valid" | "invalid">("all");
  const [credOpen, setCredOpen] = React.useState(false);
  const [credSaving, setCredSaving] = React.useState(false);
  const [credForm, setCredForm] = React.useState({
    host: "",
    port: "",
    protocol: "http",
    url: "",
    username: "",
    password: "",
    source: "manual",
    task_id: "none",
    evidence: "",
  });

  const shownCredentials = React.useMemo(
    () => (credFilter === "all" ? credentials : credentials.filter((c) => c.status === credFilter)),
    [credFilter, credentials],
  );

  function setCredentialForm(field: keyof typeof credForm, value: string) {
    setCredForm((f) => ({ ...f, [field]: value }));
  }

  function openCreateCredential() {
    setCredForm({
      host: "",
      port: "",
      protocol: "http",
      url: "",
      username: "",
      password: "",
      source: "manual",
      task_id: "none",
      evidence: "",
    });
    setCredOpen(true);
  }

  async function saveCredential() {
    if (!credForm.username.trim() || !credForm.password) {
      toast.error("账号与口令都不能为空");
      return;
    }
    if (!credForm.host.trim() && !credForm.url.trim()) {
      toast.error("需要内网主机地址，或可解析的登录 URL");
      return;
    }
    setCredSaving(true);
    try {
      const saved = await api.registerIntranetCredential({
        host: credForm.host.trim(),
        port: Number(credForm.port) > 0 ? Number(credForm.port) : undefined,
        protocol: credForm.protocol.trim(),
        url: credForm.url.trim(),
        username: credForm.username.trim(),
        password: credForm.password,
        source: credForm.source,
        task_id: credForm.task_id === "none" ? undefined : Number(credForm.task_id),
        evidence: credForm.evidence.trim(),
      });
      toast.success(`已登记凭据 #${saved.id}，口令只留在台账里`);
      setCredOpen(false);
      refresh();
    } catch (e) {
      toast.error((e as Error).message);
    } finally {
      setCredSaving(false);
    }
  }

  async function reuseCredential(cred: IntranetCredential) {
    setBusyId(`cred-${cred.id}`);
    try {
      const r = await api.intranetCredentialReuse(cred.id);
      const targets = r.targets ?? [];
      const valid = targets.filter((t) => t.status === "valid");
      const skipped = targets.filter((t) => t.status === "skipped");
      if (valid.length > 0) {
        toast.success(`凭据 #${cred.id} 在 ${valid.length} 个登录页复用成功`);
      } else if (skipped.length > 0 && skipped.length === targets.length) {
        toast.error(skipped[0]?.error || "目标不在任务范围内，未发起验证");
      } else if (r.note) {
        toast.warning(r.note);
      } else {
        toast.warning(`凭据 #${cred.id} 未能登录任何目标`);
      }
      refresh();
    } catch (e) {
      toast.error((e as Error).message);
    } finally {
      setBusyId(null);
    }
  }

  const [evacuateOpen, setEvacuateOpen] = React.useState(false);
  const [evacuateTask, setEvacuateTask] = React.useState("none");
  const [evacuateCloseSessions, setEvacuateCloseSessions] = React.useState(true);
  const [evacuateDeleteShells, setEvacuateDeleteShells] = React.useState(false);
  const [evacuateScan, setEvacuateScan] = React.useState(true);
  const [evacuateBusy, setEvacuateBusy] = React.useState<"preview" | "run" | null>(null);
  const [evacuateReport, setEvacuateReport] = React.useState<IntranetEvacuationReport | null>(null);

  function openEvacuate() {
    const withArtifacts = tasks.find((t) =>
      artifacts.some((a) => a.task_id != null && String(a.task_id) === t.id && a.status === "active"),
    );
    const fallbackTask = tasks[0] ? String(tasks[0].id) : "none";
    setEvacuateTask(withArtifacts ? String(withArtifacts.id) : fallbackTask);
    setEvacuateReport(null);
    setEvacuateOpen(true);
  }

  async function runEvacuate(dryRun: boolean) {
    if (evacuateTask === "none") {
      toast.error("请选择任务");
      return;
    }
    if (
      !dryRun &&
      !window.confirm(
        `对任务 #${evacuateTask} 执行撤离清理？将按台账逆序撤销落地物、拆除隧道、移除本任务关联的 Java 内存马并${evacuateCloseSessions ? "关闭会话" : "保留会话"}${evacuateDeleteShells ? "，并自删除本任务会话绑定的 v2 webshell" : ""}。`,
      )
    ) {
      return;
    }
    setEvacuateBusy(dryRun ? "preview" : "run");
    try {
      const r = await api.evacuateIntranetTask({
        task_id: Number(evacuateTask),
        dry_run: dryRun,
        close_sessions: evacuateCloseSessions,
        delete_webshells: evacuateDeleteShells,
        scan: evacuateScan,
      });
      setEvacuateReport(r.report);
      if (dryRun) {
        toast.success("撤离预览已生成");
      } else {
        const residual = r.report.residual.length;
        if (residual > 0) toast.warning(`撤离完成，仍有 ${residual} 项残留`);
        else toast.success("撤离完成，未发现残留");
        refresh();
      }
    } catch (e) {
      toast.error((e as Error).message);
    } finally {
      setEvacuateBusy(null);
    }
  }

  const showLoading =
    loading && sessions.length === 0 && tunnels.length === 0 && requests.length === 0 && artifacts.length === 0;

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
          <TabsTrigger value="credentials">凭据台账 ({credentials.length})</TabsTrigger>
          <TabsTrigger value="artifacts">落地物 ({activeArtifacts})</TabsTrigger>
          <TabsTrigger value="scopes">范围审批 ({requests.length})</TabsTrigger>
        </TabsList>

        <TabsContent value="sessions" className="flex min-h-0 flex-1 flex-col gap-3">
          {sessions.length === 0 ? (
            <div className="rounded-md border border-dashed py-12 text-center text-muted-foreground text-sm">
              还没有内网会话。有 Web 服务的目标先添加 webshell；只有 22
              端口的内网主机登记好凭据后，点右上角「新建会话」选 SSH。
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
                  const health = sessionHealthMeta(s.metadata);
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
                            {sessionTransportLabel(s)}
                          </Badge>
                        </div>
                        <div
                          className="max-w-72 truncate font-mono text-xs text-muted-foreground"
                          title={sessionEndpoint(s)}
                        >
                          {sessionEndpoint(s)}
                        </div>
                      </TableCell>
                      <TableCell className="max-w-56 truncate font-mono text-xs" title={s.cwd}>
                        {s.cwd || "—"}
                      </TableCell>
                      <TableCell>
                        <div className="flex flex-col items-start gap-1">
                          <Badge variant="outline" className={meta.className}>
                            {meta.label}
                          </Badge>
                          {health ? (
                            <Badge
                              variant="outline"
                              className={`text-[10px] ${health.className}`}
                              title={health.title || undefined}
                            >
                              {health.label}
                            </Badge>
                          ) : null}
                        </div>
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
                            disabled={s.status !== "active"}
                            onClick={() => void openScripts(s)}
                          >
                            信息收集
                          </Button>
                          <Button
                            variant="ghost"
                            size="sm"
                            title="心跳检测"
                            disabled={s.status !== "active" || busyId === `session-${s.id}`}
                            onClick={() => void pingSession(s)}
                          >
                            <ActivityIcon className="size-3.5" />
                          </Button>
                          <Button
                            variant="ghost"
                            size="sm"
                            title="切换到同主机备用 webshell"
                            disabled={s.status !== "active" || busyId === `session-${s.id}`}
                            onClick={() => void failoverSession(s)}
                          >
                            <ArrowRightLeftIcon className="size-3.5" />
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

        <TabsContent value="credentials" className="flex min-h-0 flex-1 flex-col gap-3">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <p className="text-muted-foreground text-sm">
              弱口令命中与横向验证过的账号都汇总在这里，按 host+账号+口令
              去重；从泄露页面、配置文件里读出的口令可用「登记凭据」手工入账。
              台账只回写「有没有口令」，明文不下发到浏览器：复用验证与 SSH 会话都由平台按凭据 ID 取用。
            </p>
            <div className="flex flex-wrap items-center gap-2">
              <Select
                value={credFilter}
                onValueChange={(v) => setCredFilter(v as "all" | "untested" | "valid" | "invalid")}
              >
                <SelectTrigger className="w-28">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">全部</SelectItem>
                  <SelectItem value="untested">待验证</SelectItem>
                  <SelectItem value="valid">已验证</SelectItem>
                  <SelectItem value="invalid">已失效</SelectItem>
                </SelectContent>
              </Select>
              <Button size="sm" onClick={openCreateCredential}>
                <KeyRoundIcon className="size-4" />
                登记凭据
              </Button>
            </div>
          </div>
          {shownCredentials.length === 0 ? (
            <div className="rounded-md border border-dashed py-12 text-center text-muted-foreground text-sm">
              暂无凭据。渗透基线的弱口令命中会自动登记；只有 22 端口的内网主机需要先用「登记凭据」把账号口令入账，
              之后才能开 SSH 会话或对登录页做复用验证。
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-16">ID</TableHead>
                  <TableHead className="w-52">主机</TableHead>
                  <TableHead className="w-40">账号</TableHead>
                  <TableHead className="w-24">来源</TableHead>
                  <TableHead className="w-24">状态</TableHead>
                  <TableHead>依据</TableHead>
                  <TableHead className="w-32">最近使用</TableHead>
                  <TableHead className="w-28 text-right">操作</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {shownCredentials.map((c) => {
                  const meta = credentialStatusMeta(c.status);
                  return (
                    <TableRow key={c.id}>
                      <TableCell className="font-mono text-xs">#{c.id}</TableCell>
                      <TableCell>
                        <div className="font-mono text-xs">
                          {c.host}
                          {c.port ? `:${c.port}` : ""}
                        </div>
                        <div className="text-muted-foreground text-xs">
                          {(c.protocol || "http").toUpperCase()} · {fmtTime(c.created_at)}
                        </div>
                      </TableCell>
                      <TableCell className="font-mono text-xs">{c.username || "—"}</TableCell>
                      <TableCell>
                        <Badge variant="outline">{CRED_SOURCE_LABEL[c.source] ?? c.source ?? "—"}</Badge>
                      </TableCell>
                      <TableCell>
                        <Badge variant="outline" className={meta.className}>
                          {meta.label}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <div className="max-w-md truncate text-xs" title={c.evidence || c.url || ""}>
                          {c.evidence || c.url || "—"}
                        </div>
                      </TableCell>
                      <TableCell className="text-muted-foreground text-xs">
                        {c.last_used_at ? fmtTime(c.last_used_at) : "—"}
                      </TableCell>
                      <TableCell className="text-right">
                        <Button
                          variant="ghost"
                          size="sm"
                          disabled={busyId === `cred-${c.id}`}
                          title="用这一组账号口令精确验证登记过的登录页（不走字典）"
                          onClick={() => void reuseCredential(c)}
                        >
                          {busyId === `cred-${c.id}` ? (
                            <Loader2Icon className="size-3.5 animate-spin" />
                          ) : (
                            <ShieldCheckIcon className="size-3.5" />
                          )}
                          复用验证
                        </Button>
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          )}
        </TabsContent>

        <TabsContent value="artifacts" className="flex min-h-0 flex-1 flex-col gap-3">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <p className="text-muted-foreground text-sm">
              目标侧落地物（文件 / Linux 持久化 / Windows 持久化）统一登记在这里，每条都带撤销与验证命令；
              同指纹重复部署会幂等复用，TTL 到期自动撤销；撤离清理按台账逆序执行撤销并输出报告。
            </p>
            <div className="flex flex-wrap items-center gap-2">
              <Select
                value={artifactFilter}
                onValueChange={(v) => setArtifactFilter(v as "all" | "active" | "revoked")}
              >
                <SelectTrigger className="w-28">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">全部</SelectItem>
                  <SelectItem value="active">生效中</SelectItem>
                  <SelectItem value="revoked">已撤销</SelectItem>
                </SelectContent>
              </Select>
              <Button variant="outline" size="sm" onClick={openEvacuate}>
                <EraserIcon className="size-4" />
                撤离清理
              </Button>
              <Button size="sm" onClick={openCreateArtifact}>
                <PlusIcon className="size-4" />
                部署 / 登记
              </Button>
            </div>
          </div>
          {shownArtifacts.length === 0 ? (
            <div className="rounded-md border border-dashed py-12 text-center text-muted-foreground text-sm">
              暂无落地物记录。通过会话上传的新文件会自动登记；cron / systemd / at / profile / SSH 公钥以及 Windows 的
              schtasks / 注册表 / 服务 / WMI / 启动文件夹可用右上角「部署 / 登记」创建。
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-16">ID</TableHead>
                  <TableHead className="w-28">类型</TableHead>
                  <TableHead className="w-36">主机</TableHead>
                  <TableHead>名称 / 路径</TableHead>
                  <TableHead className="w-24">状态</TableHead>
                  <TableHead className="w-32">登记时间</TableHead>
                  <TableHead className="w-28 text-right">操作</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {shownArtifacts.map((a) => {
                  const meta = artifactStatusMeta(a.status);
                  return (
                    <TableRow key={a.id}>
                      <TableCell className="font-mono text-xs">#{a.id}</TableCell>
                      <TableCell>
                        <Badge variant="outline">{ARTIFACT_KIND_LABEL[a.kind] ?? a.kind}</Badge>
                      </TableCell>
                      <TableCell className="font-mono text-xs">{a.host || "—"}</TableCell>
                      <TableCell>
                        <div className="text-sm">{a.name || a.path || "—"}</div>
                        <div className="max-w-md truncate font-mono text-muted-foreground text-xs" title={a.evidence}>
                          {a.path || a.description || "—"}
                        </div>
                      </TableCell>
                      <TableCell>
                        <Badge variant="outline" className={meta.className}>
                          {meta.label}
                        </Badge>
                        {a.status === "active" && a.expires_at ? (
                          <div className="mt-1 text-muted-foreground text-xs">到期 {fmtTime(a.expires_at)}</div>
                        ) : null}
                      </TableCell>
                      <TableCell className="text-muted-foreground text-xs">{fmtTime(a.created_at)}</TableCell>
                      <TableCell className="text-right">
                        {a.status === "active" ? (
                          <Button
                            variant="ghost"
                            size="sm"
                            className="text-red-600"
                            disabled={busyId === `artifact-${a.id}`}
                            onClick={() => void revokeArtifact(a)}
                          >
                            {busyId === `artifact-${a.id}` ? (
                              <Loader2Icon className="size-3.5 animate-spin" />
                            ) : (
                              <Trash2Icon className="size-3.5" />
                            )}
                            撤销
                          </Button>
                        ) : (
                          <span className="text-muted-foreground text-xs">{fmtTime(a.revoked_at)}</span>
                        )}
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

      {/* 登记凭据 */}
      <Dialog open={credOpen} onOpenChange={setCredOpen}>
        <DialogContent className="sm:max-w-lg">
          <DialogHeader>
            <DialogTitle>登记内网凭据</DialogTitle>
            <DialogDescription>
              把字典之外的账号口令入账：信息泄露页面读出的口令、会话里 cat 配置文件得到的凭据、人工提供的情报。
              口令保存后不再回显，复用时由平台按记录取用。
            </DialogDescription>
          </DialogHeader>
          <form
            className="flex flex-col gap-4"
            onSubmit={(e) => {
              e.preventDefault();
              void saveCredential();
            }}
          >
            <FieldRow label="内网主机" hint="它在内网段里的地址；填了登录 URL 可留空自动推导">
              <Input
                value={credForm.host}
                onChange={(e) => setCredentialForm("host", e.target.value)}
                placeholder="10.99.0.20"
              />
            </FieldRow>
            <div className="flex gap-4">
              <FieldRow label="端口" hint="留空按协议默认">
                <Input
                  className="w-28"
                  value={credForm.port}
                  onChange={(e) => setCredentialForm("port", e.target.value)}
                  placeholder="22"
                />
              </FieldRow>
              <FieldRow label="协议">
                <Select value={credForm.protocol} onValueChange={(v) => setCredentialForm("protocol", v)}>
                  <SelectTrigger className="w-36">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="ssh">SSH</SelectItem>
                    <SelectItem value="http">HTTP</SelectItem>
                    <SelectItem value="https">HTTPS</SelectItem>
                    <SelectItem value="mysql">MySQL</SelectItem>
                    <SelectItem value="rdp">RDP</SelectItem>
                    <SelectItem value="smb">SMB</SelectItem>
                    <SelectItem value="ftp">FTP</SelectItem>
                  </SelectContent>
                </Select>
              </FieldRow>
            </div>
            <FieldRow label="登录地址" hint="复用验证要打的目标；SSH 凭据可留空">
              <Input
                value={credForm.url}
                onChange={(e) => setCredentialForm("url", e.target.value)}
                placeholder="http://10.99.0.20/manager/login"
              />
            </FieldRow>
            <div className="flex gap-4">
              <FieldRow label="账号">
                <Input
                  value={credForm.username}
                  onChange={(e) => setCredentialForm("username", e.target.value)}
                  placeholder="root"
                />
              </FieldRow>
              <FieldRow label="口令">
                <Input
                  type="password"
                  autoComplete="new-password"
                  value={credForm.password}
                  onChange={(e) => setCredentialForm("password", e.target.value)}
                  placeholder="按原样保存，不做改动"
                />
              </FieldRow>
            </div>
            <div className="flex gap-4">
              <FieldRow label="来源">
                <Select value={credForm.source} onValueChange={(v) => setCredentialForm("source", v)}>
                  <SelectTrigger className="w-40">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="manual">人工登记</SelectItem>
                    <SelectItem value="intel">情报</SelectItem>
                    <SelectItem value="config">配置文件</SelectItem>
                    <SelectItem value="browser">浏览器</SelectItem>
                    <SelectItem value="weakpass">弱口令命中</SelectItem>
                    <SelectItem value="reuse">横向复用</SelectItem>
                  </SelectContent>
                </Select>
              </FieldRow>
              <FieldRow label="所属任务">
                <Select value={credForm.task_id} onValueChange={(v) => setCredentialForm("task_id", v)}>
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
            </div>
            <FieldRow label="依据" hint="凭据从哪里来，例如「10.99.0.20 监控面板泄露」">
              <Textarea
                rows={2}
                value={credForm.evidence}
                onChange={(e) => setCredentialForm("evidence", e.target.value)}
              />
            </FieldRow>
            <DialogFooter>
              <Button type="button" variant="outline" onClick={() => setCredOpen(false)}>
                取消
              </Button>
              <Button type="submit" disabled={credSaving}>
                {credSaving ? <Loader2Icon className="size-4 animate-spin" /> : <PlusIcon className="size-4" />}
                登记
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>

      {/* 新建会话 */}
      <Dialog open={sessionOpen} onOpenChange={setSessionOpen}>
        <DialogContent className="sm:max-w-lg">
          <DialogHeader>
            <DialogTitle>新建内网会话</DialogTitle>
            <DialogDescription>
              会话不驻留进程：Webshell 承载的会话每次执行都复用所选 webshell，SSH
              承载的会话复用凭据台账里的账号。工作目录由平台维护。
            </DialogDescription>
          </DialogHeader>
          <form
            className="flex flex-col gap-4"
            onSubmit={(e) => {
              e.preventDefault();
              void saveSession();
            }}
          >
            <FieldRow label="承载方式" hint="只有 22 端口 open、没有 Web 服务的内网主机选 SSH">
              <Select
                value={sessionForm.transport}
                onValueChange={(v) => setSessionForm({ ...sessionForm, transport: v })}
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="webshell">Webshell（HTTP 壳）</SelectItem>
                  <SelectItem value="ssh">SSH（凭据台账账号）</SelectItem>
                </SelectContent>
              </Select>
            </FieldRow>
            {sessionForm.transport === "ssh" ? (
              <>
                <FieldRow label="内网主机" hint="它在内网段里的地址，用于范围校验与资产回流">
                  <Input
                    value={sessionForm.host}
                    onChange={(e) => setSessionForm({ ...sessionForm, host: e.target.value })}
                    placeholder="10.99.0.20"
                  />
                </FieldRow>
                <FieldRow
                  label="凭据"
                  hint={
                    credentials.length === 0
                      ? "台账里还没有凭据：先到「凭据台账」登记账号口令，再回来开 SSH 会话"
                      : "口令不落在校本会话上，建立连接时由平台按记录取用"
                  }
                >
                  <Select value={sessionForm.credential_id} onValueChange={pickSessionCredential}>
                    <SelectTrigger>
                      <SelectValue placeholder="选择凭据台账里的账号" />
                    </SelectTrigger>
                    <SelectContent>
                      {credentials.map((c) => (
                        <SelectItem key={c.id} value={String(c.id)}>
                          {credentialLabel(c)}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </FieldRow>
                <FieldRow label="SSH 端口">
                  <Input
                    value={sessionForm.port}
                    onChange={(e) => setSessionForm({ ...sessionForm, port: e.target.value })}
                    placeholder="22"
                  />
                </FieldRow>
                <FieldRow label="登录账号" hint="留空用凭据里的账号">
                  <Input
                    value={sessionForm.user}
                    onChange={(e) => setSessionForm({ ...sessionForm, user: e.target.value })}
                    placeholder="root"
                  />
                </FieldRow>
                <FieldRow
                  label="接入地址"
                  hint="只能经端口转发隧道到达时填隧道监听地址（例如 127.0.0.1:40123），主机仍按内网身份记账"
                >
                  <div className="flex gap-2">
                    <Input
                      value={sessionForm.dial_host}
                      onChange={(e) => setSessionForm({ ...sessionForm, dial_host: e.target.value })}
                      placeholder="dial 主机（可留空）"
                    />
                    <Input
                      className="w-32"
                      value={sessionForm.dial_port}
                      onChange={(e) => setSessionForm({ ...sessionForm, dial_port: e.target.value })}
                      placeholder="端口"
                    />
                  </div>
                </FieldRow>
              </>
            ) : (
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
            )}
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
            {sessionForm.transport === "ssh" ? null : (
              <FieldRow label="主机" hint="用于范围校验，留空从 webshell 地址推断">
                <Input
                  value={sessionForm.host}
                  onChange={(e) => setSessionForm({ ...sessionForm, host: e.target.value })}
                  placeholder="10.0.0.5"
                />
              </FieldRow>
            )}
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
      <Dialog open={Boolean(scriptSession)} onOpenChange={(o) => !o && setScriptSession(null)}>
        <DialogContent className="flex max-h-[92vh] flex-col sm:max-w-3xl">
          <DialogHeader>
            <DialogTitle>信息收集脚本</DialogTitle>
            <DialogDescription>
              {scriptSession
                ? `会话「${scriptSession.name || scriptSession.host || `#${scriptSession.id}`}」· 结果按结构化条目与原始输出一起入库`
                : ""}
            </DialogDescription>
          </DialogHeader>
          <div className="min-h-0 flex-1 space-y-3 overflow-y-auto pr-1">
            <div className="flex flex-wrap gap-1.5">
              {scriptCatalog
                .filter((sc) => {
                  const os = String(scriptSession?.metadata?.os ?? "");
                  if (os === "windows") return sc.os === "windows";
                  if (os === "posix") return sc.os === "linux";
                  return true;
                })
                .map((sc) => (
                  <Button
                    key={sc.id}
                    size="sm"
                    variant="outline"
                    disabled={scriptBusy}
                    title={sc.note || sc.command}
                    onClick={() => void runScript(sc.id)}
                  >
                    {sc.name}
                  </Button>
                ))}
            </div>
            <div className="space-y-2">
              {scriptRuns.length === 0 ? (
                <p className="text-xs text-muted-foreground">还没有运行记录。点上面的脚本执行一条只读收集。</p>
              ) : (
                scriptRuns.map((run) => (
                  <div key={run.id} className="rounded-md border p-2">
                    <div className="flex items-center justify-between gap-2 text-xs">
                      <span className="font-medium">
                        {run.name} <span className="font-mono text-muted-foreground">{run.script_id}</span>
                      </span>
                      <span className="text-muted-foreground">
                        {run.status === "done" ? "完成" : "失败"} · 退出码 {run.exit_code ?? "—"} ·{" "}
                        {fmtTime(run.created_at)}
                      </span>
                    </div>
                    <div className="mt-1 text-[11px] text-muted-foreground">
                      结构化条目 {String(run.parsed?.count ?? 0)} 条
                    </div>
                    {/* 结论一句（F5：终端防护与补丁基线都靠它把「没读到」与「没有」分开说清） */}
                    {typeof run.parsed?.summary === "string" && run.parsed.summary ? (
                      <div className="mt-1 rounded border bg-muted/20 p-1.5 text-[11px]">{run.parsed.summary}</div>
                    ) : null}
                    {typeof run.parsed?.finding_note === "string" && run.parsed.finding_note ? (
                      <div className="mt-1 text-[11px] text-muted-foreground">{run.parsed.finding_note}</div>
                    ) : null}
                    {Array.isArray(run.parsed?.items) && run.parsed.items.length > 0 && (
                      <pre className="mt-1 max-h-40 overflow-auto rounded bg-muted/30 p-2 font-mono text-[11px] whitespace-pre-wrap">
                        {run.parsed.items
                          .slice(0, 50)
                          .map((it) => (typeof it === "string" ? it : JSON.stringify(it)))
                          .join("\n")}
                      </pre>
                    )}
                    {run.output && (
                      <details className="mt-1">
                        <summary className="cursor-pointer text-[11px] text-muted-foreground">原始输出</summary>
                        <pre className="mt-1 max-h-48 overflow-auto rounded bg-muted/20 p-2 font-mono text-[11px] whitespace-pre-wrap">
                          {run.output}
                        </pre>
                      </details>
                    )}
                  </div>
                ))
              )}
            </div>
          </div>
          <DialogFooter>
            <Button onClick={() => setScriptSession(null)}>关闭</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

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
          <Tabs
            value={termMode}
            onValueChange={(v) => {
              setTermMode(v);
              // 执行记录是台账，不是这个标签页的滚动缓冲：终端里刚跑完的命令、worker
              // 在别处跑的命令都得切过去时重新读一次，否则看到的是打开对话框那一刻的快照。
              if (v === "events" && termSession) void loadTermEvents(termSession.id);
            }}
          >
            <TabsList className="w-fit">
              <TabsTrigger value="exec">命令</TabsTrigger>
              <TabsTrigger value="upload">上传</TabsTrigger>
              <TabsTrigger value="download">下载</TabsTrigger>
              <TabsTrigger value="events">执行记录</TabsTrigger>
            </TabsList>
            <TabsContent value="exec">
              {termSession ? (
                <ShellTerminal
                  // 会话切换必须重挂：终端把目录与滚动缓冲放在自己的 state 里，
                  // 复用同一个实例会把上一个会话的输出留在屏幕上。
                  key={`intranet-${termSession.id}`}
                  historyKey={`intranet-${termSession.id}`}
                  osKind={String(termSession.metadata?.os ?? "")}
                  initialCwd={termSession.cwd || ""}
                  heightClass="h-[46vh]"
                  run={async ({ command, osKind: family, timeoutSeconds }) => {
                    const r = await api.intranetExec(termSession.id, command, timeoutSeconds, family);
                    setTermSession(r.session);
                    refresh();
                    return r.result;
                  }}
                />
              ) : null}
            </TabsContent>
            <TabsContent value="events" className="flex flex-col gap-2">
              <div className="flex items-center justify-between gap-2 text-muted-foreground text-xs">
                <span>会话台账记录的命令，含 worker 与其它标签页跑的；事件里不带退出码与结束标记。</span>
                <Button
                  variant="ghost"
                  size="sm"
                  className="h-6"
                  onClick={() => termSession && void loadTermEvents(termSession.id)}
                >
                  <RefreshCwIcon className="size-3.5" />
                  刷新
                </Button>
              </div>
              <ScrollArea className="h-[46vh] rounded-md border">
                <div className="flex flex-col gap-3 p-3 font-mono text-xs">
                  {termEvents.length === 0 ? (
                    <span className="text-muted-foreground">（暂无执行记录）</span>
                  ) : (
                    termEvents.map((ev) => (
                      <div key={ev.id} className="flex flex-col gap-1">
                        <div className="text-muted-foreground">
                          <span className="text-emerald-600 dark:text-emerald-400">$ </span>
                          {ev.command}
                          <span className="ml-2 text-[10px]">
                            {ev.kind} · {fmtTime(ev.created_at)}
                          </span>
                        </div>
                        <pre
                          className={`whitespace-pre-wrap break-all rounded bg-muted/50 p-2 ${
                            ev.is_error ? "text-red-600 dark:text-red-400" : ""
                          }`}
                        >
                          {ev.output || "（无输出）"}
                        </pre>
                      </div>
                    ))
                  )}
                </div>
              </ScrollArea>
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
                <Button onClick={() => void doUpload()} disabled={uploadBusy || !uploadFile}>
                  {uploadBusy ? <Loader2Icon className="size-4 animate-spin" /> : <UploadIcon className="size-4" />}
                  上传
                </Button>
              </div>
              {uploadResult ? <ExecOutcome result={uploadResult} /> : null}
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
              {downloadResult ? (
                <ExecOutcome
                  result={{ ...downloadResult.result, output: downloadResult.result.output || "（内容已保存到本地）" }}
                  extra={downloadResult.extra}
                />
              ) : null}
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
            <FieldRow
              label="监听侧"
              hint="规划自动选型会改写；手写部署命令时用它纠正，验证与拆除复核都按这里记的一侧进行"
            >
              <Select
                value={tunnelForm.listen_side}
                onValueChange={(v) => setTunnelForm({ ...tunnelForm, listen_side: v })}
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="target">目标（socat / ssh -D -L / chisel R:）</SelectItem>
                  <SelectItem value="pivot">控制端（chisel client 不带 R:）</SelectItem>
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
                  <span className="text-muted-foreground">监听侧：</span>
                  {detailTunnel.listen_side === "pivot" ? "控制端（验证与复核查这一侧）" : "目标"}
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

      {/* 部署标准模块 / 登记落地物 */}
      <Dialog open={artifactOpen} onOpenChange={setArtifactOpen}>
        <DialogContent className="sm:max-w-lg">
          <DialogHeader>
            <DialogTitle>部署标准模块 / 登记落地物</DialogTitle>
            <DialogDescription>
              标准模块由平台生成「部署 + 撤销 + 验证」命令并自动登记台账；手工登记必须提供撤销命令。
            </DialogDescription>
          </DialogHeader>
          <form
            className="flex max-h-[70vh] flex-col gap-4 overflow-y-auto pr-1"
            onSubmit={(e) => {
              e.preventDefault();
              void saveArtifact();
            }}
          >
            <FieldRow label="方式">
              <Select value={artifactMode} onValueChange={(v) => setArtifactMode(v as "persist" | "manual")}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="persist">标准模块（Linux / Windows 持久化）</SelectItem>
                  <SelectItem value="manual">手工登记（任意落地物）</SelectItem>
                </SelectContent>
              </Select>
            </FieldRow>
            <FieldRow label="会话" hint="命令与撤销都通过该会话执行">
              <Select
                value={artifactForm.session_id}
                onValueChange={(v) => setArtifactForm({ ...artifactForm, session_id: v })}
              >
                <SelectTrigger>
                  <SelectValue placeholder="选择活跃会话" />
                </SelectTrigger>
                <SelectContent>
                  {sessions
                    .filter((s) => s.status === "active")
                    .map((s) => (
                      <SelectItem key={s.id} value={String(s.id)}>
                        #{s.id} {s.name || s.host || "会话"}
                      </SelectItem>
                    ))}
                </SelectContent>
              </Select>
            </FieldRow>
            <FieldRow label="所属任务">
              <Select
                value={artifactForm.task_id}
                onValueChange={(v) => setArtifactForm({ ...artifactForm, task_id: v })}
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="none">不关联任务</SelectItem>
                  {tasks.map((t) => (
                    <SelectItem key={t.id} value={String(t.id)}>
                      #{t.id} {taskLabel(t)}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </FieldRow>
            {artifactMode === "persist" ? (
              <>
                <FieldRow
                  label="模块"
                  hint={`当前模块适用于 ${persistMeta.os === "windows" ? "Windows" : "Linux/Unix"} 目标`}
                >
                  <Select
                    value={artifactForm.persist_kind}
                    onValueChange={(v) => {
                      const meta = PERSIST_KIND_META[v];
                      setArtifactForm((f) => ({ ...f, persist_kind: v, schedule: meta?.schedule?.fallback ?? "" }));
                    }}
                  >
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectGroup>
                        <SelectLabel>Linux / Unix</SelectLabel>
                        {Object.entries(PERSIST_KIND_META)
                          .filter(([, m]) => m.os === "linux")
                          .map(([value, m]) => (
                            <SelectItem key={value} value={value}>
                              {m.label}
                            </SelectItem>
                          ))}
                      </SelectGroup>
                      <SelectGroup>
                        <SelectLabel>Windows</SelectLabel>
                        {Object.entries(PERSIST_KIND_META)
                          .filter(([, m]) => m.os === "windows")
                          .map(([value, m]) => (
                            <SelectItem key={value} value={value}>
                              {m.label}
                            </SelectItem>
                          ))}
                      </SelectGroup>
                    </SelectContent>
                  </Select>
                </FieldRow>
                {persistMeta.schedule ? (
                  <FieldRow label={persistMeta.schedule.label} hint={persistMeta.schedule.hint}>
                    <Input
                      value={artifactForm.schedule}
                      onChange={(e) => setArtifactForm({ ...artifactForm, schedule: e.target.value })}
                      placeholder={persistMeta.schedule.placeholder}
                    />
                  </FieldRow>
                ) : null}
                {persistMeta.publicKey ? (
                  <FieldRow label="公钥">
                    <Textarea
                      value={artifactForm.public_key}
                      onChange={(e) => setArtifactForm({ ...artifactForm, public_key: e.target.value })}
                      rows={2}
                      placeholder="ssh-ed25519 AAAA..."
                    />
                  </FieldRow>
                ) : null}
                {persistMeta.user ? (
                  <FieldRow label="目标账号" hint="留空使用当前用户">
                    <Input
                      value={artifactForm.user}
                      onChange={(e) => setArtifactForm({ ...artifactForm, user: e.target.value })}
                      placeholder="root"
                    />
                  </FieldRow>
                ) : null}
                {persistMeta.command ? (
                  <FieldRow label="执行命令">
                    <Textarea
                      value={artifactForm.command}
                      onChange={(e) => setArtifactForm({ ...artifactForm, command: e.target.value })}
                      rows={2}
                      placeholder="要维持执行的命令"
                    />
                  </FieldRow>
                ) : null}
                <FieldRow label="TTL（秒）" hint="可选；到期后后台自动撤销，60–2592000">
                  <Input
                    value={artifactForm.ttl_seconds}
                    onChange={(e) => setArtifactForm({ ...artifactForm, ttl_seconds: e.target.value })}
                    placeholder="留空表示不过期，例如 86400"
                    inputMode="numeric"
                  />
                </FieldRow>
              </>
            ) : (
              <>
                <FieldRow label="路径 / 标识">
                  <Input
                    value={artifactForm.path}
                    onChange={(e) => setArtifactForm({ ...artifactForm, path: e.target.value })}
                    placeholder="/tmp/tool 或 crontab:xyz"
                  />
                </FieldRow>
                <FieldRow label="撤销命令" hint="必填；撤离时按此删除痕迹">
                  <Textarea
                    value={artifactForm.revoke_command}
                    onChange={(e) => setArtifactForm({ ...artifactForm, revoke_command: e.target.value })}
                    rows={2}
                    placeholder="rm -f /tmp/tool && echo JW_ARTIFACT_OK"
                  />
                </FieldRow>
                <FieldRow label="验证命令" hint="撤销后应输出 JW_ARTIFACT_GONE">
                  <Textarea
                    value={artifactForm.verify_command}
                    onChange={(e) => setArtifactForm({ ...artifactForm, verify_command: e.target.value })}
                    rows={2}
                    placeholder="test -e /tmp/tool && echo JW_ARTIFACT_PRESENT || echo JW_ARTIFACT_GONE"
                  />
                </FieldRow>
                <FieldRow label="TTL（秒）" hint="可选；到期后后台自动撤销，60–2592000">
                  <Input
                    value={artifactForm.ttl_seconds}
                    onChange={(e) => setArtifactForm({ ...artifactForm, ttl_seconds: e.target.value })}
                    placeholder="留空表示不过期，例如 86400"
                    inputMode="numeric"
                  />
                </FieldRow>
              </>
            )}
            <FieldRow label="名称">
              <Input
                value={artifactForm.name}
                onChange={(e) => setArtifactForm({ ...artifactForm, name: e.target.value })}
                placeholder="留空自动生成"
              />
            </FieldRow>
            <FieldRow label="说明">
              <Input
                value={artifactForm.description}
                onChange={(e) => setArtifactForm({ ...artifactForm, description: e.target.value })}
                placeholder="可选"
              />
            </FieldRow>
            <DialogFooter>
              <Button type="submit" disabled={artifactSaving}>
                {artifactSaving ? <Loader2Icon className="size-4 animate-spin" /> : <PlusIcon className="size-4" />}
                {artifactMode === "persist" ? "部署并登记" : "登记落地物"}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>

      {/* 撤离清理 */}
      <Dialog open={evacuateOpen} onOpenChange={setEvacuateOpen}>
        <DialogContent className="sm:max-w-3xl">
          <DialogHeader>
            <DialogTitle>撤离清理</DialogTitle>
            <DialogDescription>
              按落地物台账 id 倒序撤销并验证，随后复核残留、拆除任务隧道、释放受管资源并关闭会话。 内存马会在父 webshell
              之前清理（父 shell 反注册优先，失败则端点自移除）；未确认移除时保留父 webshell 并列入残留。webshell
              默认只探活并列入残留提醒；显式开启后才会对 v2 载荷执行自删除与 404/标记复核。
            </DialogDescription>
          </DialogHeader>
          <div className="flex flex-col gap-4">
            <FieldRow label="任务">
              <Select value={evacuateTask} onValueChange={setEvacuateTask}>
                <SelectTrigger>
                  <SelectValue placeholder="选择要撤离的任务" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="none">选择任务</SelectItem>
                  {tasks.map((t) => (
                    <SelectItem key={t.id} value={String(t.id)}>
                      #{t.id} {taskLabel(t)}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </FieldRow>
            <label htmlFor="evac-close-sessions" className="flex items-center gap-2 text-sm">
              <Checkbox
                id="evac-close-sessions"
                checked={evacuateCloseSessions}
                onCheckedChange={(v) => setEvacuateCloseSessions(Boolean(v))}
              />
              关闭该任务的活跃会话
            </label>
            <label htmlFor="evac-delete-shells" className="flex items-center gap-2 text-sm">
              <Checkbox
                id="evac-delete-shells"
                checked={evacuateDeleteShells}
                onCheckedChange={(v) => setEvacuateDeleteShells(Boolean(v))}
              />
              自删除本任务会话绑定的 v2 webshell（旧版协议仍需手工清理）
            </label>
            <label htmlFor="evac-rescan" className="flex items-center gap-2 text-sm">
              <Checkbox id="evac-rescan" checked={evacuateScan} onCheckedChange={(v) => setEvacuateScan(Boolean(v))} />
              撤离后重新执行验证命令做残留复核
            </label>
            <div className="flex flex-wrap items-center gap-2">
              <Button
                variant="outline"
                size="sm"
                disabled={evacuateBusy !== null}
                onClick={() => void runEvacuate(true)}
              >
                {evacuateBusy === "preview" ? (
                  <Loader2Icon className="size-4 animate-spin" />
                ) : (
                  <EyeIcon className="size-4" />
                )}
                预览
              </Button>
              <Button
                variant="destructive"
                size="sm"
                disabled={evacuateBusy !== null}
                onClick={() => void runEvacuate(false)}
              >
                {evacuateBusy === "run" ? (
                  <Loader2Icon className="size-4 animate-spin" />
                ) : (
                  <EraserIcon className="size-4" />
                )}
                执行撤离
              </Button>
            </div>
            {evacuateReport ? (
              <div className="flex flex-col gap-3 rounded-md border p-3">
                <div className="text-sm">
                  {evacuateReport.dry_run ? <Badge variant="outline">预览</Badge> : null} {evacuateReport.summary}
                </div>
                <div className="flex flex-wrap gap-2">
                  <Badge variant="outline">
                    落地物 {evacuateReport.artifacts.done}/{evacuateReport.artifacts.total}
                  </Badge>
                  <Badge variant="outline">
                    隧道 {evacuateReport.tunnels.done}/{evacuateReport.tunnels.total}
                  </Badge>
                  <Badge variant="outline">
                    资源 {evacuateReport.resources.done}/{evacuateReport.resources.total}
                  </Badge>
                  <Badge variant="outline">
                    会话 {evacuateReport.sessions.done}/{evacuateReport.sessions.total}
                  </Badge>
                  <Badge variant="outline">
                    内存马 {evacuateReport.memshells.done}/{evacuateReport.memshells.total}
                  </Badge>
                  <Badge variant="outline">
                    webshell {evacuateReport.webshells.done}/{evacuateReport.webshells.total}
                  </Badge>
                  {evacuateReport.scan.checked > 0 ? (
                    <Badge variant="outline">
                      复核 {evacuateReport.scan.checked} 项（存在 {evacuateReport.scan.present}、未知{" "}
                      {evacuateReport.scan.unknown}）
                    </Badge>
                  ) : null}
                </div>
                {evacuateReport.residual.length > 0 ? (
                  <div className="rounded-md border border-red-500/30 bg-red-500/5 p-2">
                    <div className="mb-1 font-medium text-red-600 text-xs">
                      残留（{evacuateReport.residual.length}）
                    </div>
                    <ul className="list-disc space-y-1 pl-4 text-xs">
                      {evacuateReport.residual.map((item) => (
                        <li key={item}>{item}</li>
                      ))}
                    </ul>
                  </div>
                ) : null}
                {(evacuateReport.traces?.length ?? 0) > 0 ? (
                  <div className="rounded-md border bg-muted/20 p-2">
                    <div className="mb-1 flex flex-wrap items-center gap-2 text-xs">
                      <span className="font-medium">痕迹矩阵（本次留下什么、验证到什么程度）</span>
                      <span className="text-muted-foreground">
                        结论只有「已验证清除」代表验证命令确认痕迹消失；「无法复核」不是已清理
                      </span>
                      {(evacuateReport.trace_matrix ?? "") !== "" ? (
                        <Button
                          variant="outline"
                          size="sm"
                          className="h-6"
                          onClick={() => {
                            navigator.clipboard
                              .writeText(evacuateReport.trace_matrix ?? "")
                              .then(() => toast.success("痕迹矩阵 Markdown 已复制（可直接贴进报告）"))
                              .catch(() => toast.error("复制失败"));
                          }}
                        >
                          复制 Markdown
                        </Button>
                      ) : null}
                    </div>
                    <div className="overflow-x-auto">
                      <table className="w-full text-[11px]">
                        <thead>
                          <tr className="border-b text-left text-muted-foreground">
                            <th className="py-1 pr-2 font-medium">手段</th>
                            <th className="py-1 pr-2 font-medium">本次落地点</th>
                            <th className="py-1 pr-2 font-medium">部署后留下的痕迹</th>
                            <th className="py-1 pr-2 font-medium">清除验证</th>
                            <th className="py-1 pr-2 font-medium">结论</th>
                          </tr>
                        </thead>
                        <tbody>
                          {(evacuateReport.traces ?? []).map((row) => (
                            <tr key={`${row.kind}-${row.host}`} className="border-b border-dashed align-top">
                              <td className="py-1 pr-2 whitespace-nowrap">{row.name || row.kind}</td>
                              <td className="py-1 pr-2 font-mono break-all">{(row.landed ?? []).join("；")}</td>
                              <td className="py-1 pr-2 text-muted-foreground">{(row.traces ?? []).join("；")}</td>
                              <td className="py-1 pr-2 text-muted-foreground">{row.verify}</td>
                              <td className="py-1 pr-2 whitespace-nowrap">
                                <Badge variant="outline" className={traceVerdictClass(row.verdict)}>
                                  {row.verdict}
                                  {row.detail ? `：${row.detail}` : ""}
                                </Badge>
                                {(row.residue ?? []).length > 0 ? (
                                  <div className="mt-1 max-w-[22rem] text-muted-foreground">
                                    撤销后仍存在：{(row.residue ?? []).join("；")}
                                  </div>
                                ) : null}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                ) : null}
                {(evacuateReport.ledger_external?.length ?? 0) > 0 ? (
                  <div className="rounded-md border border-amber-500/30 bg-amber-500/5 p-2">
                    <div className="mb-1 font-medium text-amber-700 text-xs dark:text-amber-400">
                      台账外痕迹（{evacuateReport.ledger_external?.length}）——
                      可能是目标原有配置，也可能是残留，按内容判断
                    </div>
                    <pre className="max-h-48 overflow-auto font-mono text-[11px] whitespace-pre-wrap">
                      {evacuateReport.ledger_external?.join("\n")}
                    </pre>
                  </div>
                ) : null}
                {evacuateReport.items.length > 0 ? (
                  <ScrollArea className="max-h-64">
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead className="w-24">类型</TableHead>
                          <TableHead className="w-16">ID</TableHead>
                          <TableHead className="w-24">状态</TableHead>
                          <TableHead>详情</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {evacuateReport.items.map((item) => (
                          <TableRow key={`${item.type}-${item.id}`}>
                            <TableCell className="text-xs">{item.type}</TableCell>
                            <TableCell className="font-mono text-xs">#{item.id}</TableCell>
                            <TableCell className="text-xs">{item.status}</TableCell>
                            <TableCell className="max-w-md truncate text-muted-foreground text-xs" title={item.detail}>
                              {item.detail || item.name || item.host || "—"}
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </ScrollArea>
                ) : null}
              </div>
            ) : null}
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setEvacuateOpen(false)}>
              关闭
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
