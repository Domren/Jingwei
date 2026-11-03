"use client";

import * as React from "react";

import {
  CpuIcon,
  DownloadIcon,
  FolderOpenIcon,
  InfoIcon,
  KeyRoundIcon,
  Loader2Icon,
  PencilIcon,
  PinIcon,
  PlusIcon,
  ServerCogIcon,
  TerminalIcon,
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
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Textarea } from "@/components/ui/textarea";
import { api } from "@/lib/api";
import type { JavaMemshell, PHPPersistResult, Webshell } from "@/lib/types";

import { FieldRow, fmtTime, shellStatusMeta } from "../_components/deep-ui";
import { ShellTerminal } from "../_components/shell-terminal";
import { WebshellWorkbench } from "./webshell-workbench";

const SHELL_TYPES = [
  { value: "php", label: "PHP" },
  { value: "jsp", label: "JSP" },
  { value: "aspx", label: "ASPX" },
];

const SHELL_PROTOCOLS = [
  { value: "v2", label: "加密 v2（推荐）" },
  { value: "legacy", label: "旧版明文" },
];

const MEMSHELL_TYPES = [
  { value: "filter", label: "Filter 型" },
  { value: "servlet", label: "Servlet 型" },
  { value: "listener", label: "Listener 型" },
  { value: "valve", label: "Valve 型" },
  { value: "agent", label: "Agent 型（独立端口）" },
];

const PHP_PERSIST_MODES = [
  { value: "auto", label: "自动（按 SAPI）" },
  { value: "user_ini", label: ".user.ini（FPM/CGI）" },
  { value: "htaccess", label: ".htaccess（Apache/LiteSpeed）" },
];

function ResultRow({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="flex min-w-0 flex-col gap-0.5">
      <span className="text-muted-foreground">{label}</span>
      <span className={mono ? "break-all font-mono" : "break-all"}>{value || "—"}</span>
    </div>
  );
}

function downloadShellSource(filename: string, content: string) {
  const blob = new Blob([content], { type: "text/plain;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename || "shell.php";
  a.click();
  URL.revokeObjectURL(url);
}

function persistStatusBadge(verified: boolean, pending: boolean) {
  if (verified) {
    return { label: "已生效", className: "border-emerald-500/30 bg-emerald-500/10 text-emerald-600" };
  }
  if (pending) {
    return { label: "等待缓存生效", className: "border-amber-500/30 bg-amber-500/10 text-amber-600" };
  }
  return { label: "未确认", className: "border-slate-500/30 bg-slate-500/10 text-slate-600 dark:text-slate-400" };
}

export default function DeepWebshellsPage() {
  const [shells, setShells] = React.useState<Webshell[]>([]);
  const [total, setTotal] = React.useState(0);
  const [loading, setLoading] = React.useState(false);
  const [refreshKey, setRefreshKey] = React.useState(0);
  const [busyId, setBusyId] = React.useState<number | null>(null);

  const [editOpen, setEditOpen] = React.useState(false);
  const [editing, setEditing] = React.useState<Webshell | null>(null);
  const [saving, setSaving] = React.useState(false);
  const [form, setForm] = React.useState({
    name: "",
    url: "",
    shell_type: "php",
    protocol: "v2",
    password: "",
    target: "",
    note: "",
  });

  const [workbench, setWorkbench] = React.useState<{
    shell: Webshell;
    tab: "term" | "files" | "info";
  } | null>(null);

  const [msShell, setMsShell] = React.useState<Webshell | null>(null);
  const [memshells, setMemshells] = React.useState<JavaMemshell[]>([]);
  const [msLoading, setMsLoading] = React.useState(false);
  const [msBusyId, setMsBusyId] = React.useState<number | null>(null);
  const [msType, setMsType] = React.useState("filter");
  const [msName, setMsName] = React.useState("");
  const [msPath, setMsPath] = React.useState("");
  const [msPort, setMsPort] = React.useState("");
  const [msDeploying, setMsDeploying] = React.useState(false);
  const [msExec, setMsExec] = React.useState<JavaMemshell | null>(null);

  const [ppShell, setPpShell] = React.useState<Webshell | null>(null);
  const [ppMode, setPpMode] = React.useState("auto");
  const [ppDirectory, setPpDirectory] = React.useState("");
  const [ppFilename, setPpFilename] = React.useState("");
  const [ppConfigName, setPpConfigName] = React.useState("");
  const [ppTrigger, setPpTrigger] = React.useState("");
  const [ppWait, setPpWait] = React.useState("");
  const [ppTTL, setPpTTL] = React.useState("");
  const [ppName, setPpName] = React.useState("");
  const [ppDescription, setPpDescription] = React.useState("");
  const [ppForce, setPpForce] = React.useState(false);
  const [ppDeploying, setPpDeploying] = React.useState(false);
  const [ppBusy, setPpBusy] = React.useState(false);
  const [ppResult, setPpResult] = React.useState<PHPPersistResult | null>(null);
  const [ppError, setPpError] = React.useState("");
  const [ppRevoked, setPpRevoked] = React.useState(false);

  // biome-ignore lint/correctness/useExhaustiveDependencies: refreshKey is an explicit manual-reload trigger.
  React.useEffect(() => {
    let alive = true;
    async function load() {
      try {
        const r = await api.webshells({ limit: 100 });
        if (!alive) return;
        setShells(r.webshells ?? []);
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
  }, [refreshKey]);

  function openCreate() {
    setEditing(null);
    setForm({ name: "", url: "", shell_type: "php", protocol: "v2", password: "", target: "", note: "" });
    setEditOpen(true);
  }

  function openEdit(shell: Webshell) {
    setEditing(shell);
    setForm({
      name: shell.name,
      url: shell.url,
      shell_type: shell.shell_type || "php",
      protocol: shell.protocol || "legacy",
      password: "",
      target: shell.target,
      note: shell.note,
    });
    setEditOpen(true);
  }

  async function save() {
    if (!form.url.trim()) {
      toast.error("请填写 webshell 地址");
      return;
    }
    setSaving(true);
    try {
      const payload = {
        name: form.name.trim(),
        url: form.url.trim(),
        shell_type: form.shell_type,
        protocol: form.protocol,
        password: form.protocol === "legacy" ? form.password : "",
        target: form.target.trim(),
        note: form.note,
      };
      if (editing) {
        await api.updateWebshell(editing.id, payload);
        toast.success("已保存");
      } else {
        const created = await api.createWebshell(payload);
        if (created.protocol === "v2") {
          const src = await api.webshellPayload(created.id);
          downloadShellSource(src.filename, src.content);
          toast.success("已添加，加密载荷已下载；请部署后再点「检测」");
        } else {
          toast.success("已添加");
        }
      }
      setEditOpen(false);
      setRefreshKey((k) => k + 1);
    } catch (e) {
      toast.error((e as Error).message);
    } finally {
      setSaving(false);
    }
  }

  async function downloadPayload(shell: Webshell) {
    setBusyId(shell.id);
    try {
      const p = await api.webshellPayload(shell.id);
      downloadShellSource(p.filename, p.content);
      toast.success(`载荷已下载，SHA-256 ${p.sha256.slice(0, 16)}…`);
    } catch (e) {
      toast.error((e as Error).message);
    } finally {
      setBusyId(null);
    }
  }

  async function rotateKey(shell: Webshell) {
    if (!window.confirm(`轮换「${shell.name || shell.url}」的密钥？旧密钥会立即失效，shell 需在线。`)) return;
    setBusyId(shell.id);
    try {
      const r = await api.rotateWebshell(shell.id);
      if (r.payload) downloadShellSource(r.filename || "shell.php", r.payload);
      toast.success(`密钥已轮换到 v${r.key_version}；如需重装可使用刚下载的新载荷`);
      setRefreshKey((k) => k + 1);
    } catch (e) {
      toast.error((e as Error).message);
    } finally {
      setBusyId(null);
    }
  }

  async function check(shell: Webshell) {
    setBusyId(shell.id);
    try {
      const r = await api.checkWebshell(shell.id);
      toast[r.alive ? "success" : "error"](r.alive ? "webshell 存活" : `webshell 未响应：${r.note}`);
      setRefreshKey((k) => k + 1);
    } catch (e) {
      toast.error((e as Error).message);
    } finally {
      setBusyId(null);
    }
  }

  async function remove(shell: Webshell) {
    if (!window.confirm(`删除 webshell「${shell.name || shell.url}」？`)) return;
    setBusyId(shell.id);
    try {
      await api.deleteWebshell(shell.id);
      toast.success("已删除");
      setRefreshKey((k) => k + 1);
    } catch (e) {
      toast.error((e as Error).message);
    } finally {
      setBusyId(null);
    }
  }

  async function loadMemshells(webshellId: number) {
    setMsLoading(true);
    try {
      const r = await api.webshellMemshells(webshellId);
      setMemshells(r.memshells ?? []);
    } catch (e) {
      toast.error((e as Error).message);
    } finally {
      setMsLoading(false);
    }
  }

  function openMemshells(shell: Webshell) {
    setMsShell(shell);
    setMsExec(null);
    void loadMemshells(shell.id);
  }

  async function deployMemshell() {
    if (!msShell) return;
    setMsDeploying(true);
    try {
      const port = msType === "agent" && msPort.trim() ? Number(msPort.trim()) : 0;
      const r = await api.deployMemshell(msShell.id, {
        type: msType,
        name: msName.trim(),
        path: msPath.trim(),
        port: Number.isFinite(port) ? port : 0,
      });
      toast.success(`已注入 ${r.memshell.type} · ${r.memshell.url}`);
      setMsName("");
      setMsPath("");
      setMsPort("");
      await loadMemshells(msShell.id);
      setRefreshKey((k) => k + 1);
    } catch (e) {
      toast.error((e as Error).message);
    } finally {
      setMsDeploying(false);
    }
  }

  async function checkMemshell(ms: JavaMemshell) {
    setMsBusyId(ms.id);
    try {
      const r = await api.checkMemshell(ms.id);
      toast[r.alive ? "success" : "error"](r.alive ? `内存马存活：${r.note}` : `内存马未响应：${r.note}`);
      if (msShell) await loadMemshells(msShell.id);
    } catch (e) {
      toast.error((e as Error).message);
    } finally {
      setMsBusyId(null);
    }
  }

  async function removeMemshell(ms: JavaMemshell) {
    if (!window.confirm(`移除 ${ms.type} 内存马「${ms.name}」？将先通过父 shell 清理并复核。`)) return;
    setMsBusyId(ms.id);
    try {
      const r = await api.deleteMemshell(ms.id);
      toast.success(r.removed ? `已移除${r.note ? `：${r.note}` : ""}` : "已清理记录（端点未确认下线）");
      if (msShell) await loadMemshells(msShell.id);
      setRefreshKey((k) => k + 1);
    } catch (e) {
      const msg = (e as Error).message;
      toast.error(msg);
      if (window.confirm(`${msg}\n\n是否强制清理数据库记录？端点可能仍然存活。`)) {
        try {
          await api.deleteMemshell(ms.id, true);
          toast.success("已强制清理记录");
          if (msShell) await loadMemshells(msShell.id);
          setRefreshKey((k) => k + 1);
        } catch (e2) {
          toast.error((e2 as Error).message);
        }
      }
    } finally {
      setMsBusyId(null);
    }
  }

  function openPHPPersist(shell: Webshell) {
    setPpShell(shell);
    setPpMode("auto");
    setPpDirectory("");
    setPpFilename("");
    setPpConfigName("");
    setPpTrigger("");
    setPpWait("");
    setPpTTL("");
    setPpName("");
    setPpDescription("");
    setPpForce(false);
    setPpResult(null);
    setPpError("");
    setPpRevoked(false);
  }

  async function deployPHPPersist() {
    if (!ppShell) return;
    const waitSeconds = ppWait.trim() ? Number(ppWait.trim()) : 0;
    if (!Number.isFinite(waitSeconds) || waitSeconds < 0) {
      toast.error("等待探测秒数必须是非负整数");
      return;
    }
    const ttlSeconds = ppTTL.trim() ? Number(ppTTL.trim()) : 0;
    if (!Number.isFinite(ttlSeconds) || ttlSeconds < 0) {
      toast.error("台账 TTL 必须是非负整数");
      return;
    }
    if (ttlSeconds > 0 && (ttlSeconds < 60 || ttlSeconds > 2592000)) {
      toast.error("台账 TTL 需在 60 到 2592000 秒（30 天）之间，留空表示不过期");
      return;
    }
    setPpDeploying(true);
    setPpError("");
    try {
      const r = await api.phpSemiPersist(ppShell.id, {
        mode: ppMode,
        directory: ppDirectory.trim(),
        filename: ppFilename.trim(),
        config_name: ppConfigName.trim(),
        trigger_url: ppTrigger.trim(),
        wait_seconds: Math.trunc(waitSeconds),
        force: ppForce,
        name: ppName.trim(),
        description: ppDescription.trim(),
        ttl_seconds: Math.trunc(ttlSeconds),
      });
      setPpResult(r.result);
      setRefreshKey((k) => k + 1);
      if (r.result.verified) {
        toast.success("半持久化已生效");
      } else if (r.result.pending) {
        toast.warning("配置已写入，等待 user_ini 缓存生效；请稍后检测确认");
      } else {
        toast.warning("配置与载荷已写入，但探测未确认生效");
      }
    } catch (e) {
      const msg = (e as Error).message;
      setPpError(msg.includes("force=true") ? `${msg}（勾选「强制覆盖」后重试）` : msg);
      toast.error(msg);
    } finally {
      setPpDeploying(false);
    }
  }

  async function revokePHPPersist() {
    const art = ppResult?.artifact;
    if (!art) return;
    if (
      !window.confirm(
        `撤销落地物 #${art.id}？将删除 ${ppResult?.config_path || "prepend 配置"} 中的配置块与载荷文件，该半持久化通道随即失效。`,
      )
    ) {
      return;
    }
    setPpBusy(true);
    try {
      const r = await api.revokeIntranetArtifact(art.id);
      if (r.revoked) {
        setPpRevoked(true);
        toast.success("已撤销半持久化落地物");
        setRefreshKey((k) => k + 1);
      } else {
        toast.error(r.error || "撤销未完成，请在撤离/落地物台账中查看残留");
      }
    } catch (e) {
      toast.error((e as Error).message);
    } finally {
      setPpBusy(false);
    }
  }

  const ppBadge = persistStatusBadge(ppResult?.verified ?? false, ppResult?.pending ?? false);

  return (
    <div className="flex min-h-0 flex-1 flex-col gap-4">
      <div className="flex items-center justify-between gap-4">
        <div className="flex items-center gap-2">
          <ServerCogIcon className="h-5 w-5 text-muted-foreground" />
          <h1 className="font-semibold text-xl tracking-tight">Webshell 管理</h1>
          <Badge variant="secondary">{total}</Badge>
        </div>
        <Button onClick={openCreate}>
          <PlusIcon className="size-4" />
          添加 webshell
        </Button>
      </div>

      <p className="text-muted-foreground text-sm">
        集中管理已获取的 webshell，支持存活检测与命令执行；注入任务成功落地的 shell 会自动出现在这里。
      </p>

      {loading && shells.length === 0 ? (
        <div className="flex items-center justify-center py-16 text-muted-foreground text-sm">
          <Loader2Icon className="mr-2 size-4 animate-spin" />
          加载中…
        </div>
      ) : null}
      {!loading && shells.length === 0 ? (
        <div className="rounded-md border border-dashed py-12 text-center text-muted-foreground text-sm">
          还没有 webshell，点击右上角「添加 webshell」或先执行一次注入任务。
        </div>
      ) : null}
      {shells.length > 0 ? (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>名称</TableHead>
              <TableHead>地址</TableHead>
              <TableHead className="w-20">类型</TableHead>
              <TableHead className="w-24">协议</TableHead>
              <TableHead className="w-24">状态</TableHead>
              <TableHead className="w-36">最近检测</TableHead>
              <TableHead className="w-64 text-right">操作</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {shells.map((s) => {
              const badge = shellStatusMeta(s.status);
              return (
                <TableRow key={s.id}>
                  <TableCell className="max-w-40 truncate font-medium" title={s.name}>
                    {s.name || "—"}
                  </TableCell>
                  <TableCell className="max-w-72 truncate font-mono text-xs" title={s.url}>
                    {s.url || "—"}
                  </TableCell>
                  <TableCell>
                    <div className="flex flex-wrap items-center gap-1">
                      <Badge variant="outline">{s.shell_type?.toUpperCase() || "PHP"}</Badge>
                      {s.source === "php_prepend" ? (
                        <Badge
                          variant="outline"
                          className="border-sky-500/30 bg-sky-500/10 text-sky-600"
                          title="通过 .user.ini / .htaccess 的 auto_prepend_file 挂载"
                        >
                          半持久化
                        </Badge>
                      ) : null}
                    </div>
                  </TableCell>
                  <TableCell>
                    <Badge
                      variant="outline"
                      title={
                        s.protocol === "v2"
                          ? `载体 ${s.carrier || "—"} · 密钥 v${s.key_version || 1} · SHA-256 ${s.payload_sha256 || "—"}`
                          : "命令与口令以明文参数发送，仅建议用于临时验证"
                      }
                      className={
                        s.protocol === "v2"
                          ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-600"
                          : "border-amber-500/30 bg-amber-500/10 text-amber-600"
                      }
                    >
                      {s.protocol === "v2" ? "加密 v2" : "明文"}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    <Badge variant="outline" className={badge.className} title={badge.hint}>
                      {badge.label}
                    </Badge>
                  </TableCell>
                  <TableCell className="text-muted-foreground text-xs">{fmtTime(s.last_checked)}</TableCell>
                  <TableCell className="text-right">
                    <div className="flex items-center justify-end gap-1">
                      <Button variant="ghost" size="sm" disabled={busyId === s.id} onClick={() => check(s)}>
                        检测
                      </Button>
                      <Button
                        variant="ghost"
                        size="sm"
                        disabled={!s.url}
                        title="工作台 · 虚拟终端"
                        onClick={() => setWorkbench({ shell: s, tab: "term" })}
                      >
                        <TerminalIcon className="size-3.5" />
                        终端
                      </Button>
                      <Button
                        variant="ghost"
                        size="sm"
                        disabled={!s.url || s.protocol !== "v2"}
                        title="工作台 · 文件管理（大马）"
                        onClick={() => setWorkbench({ shell: s, tab: "files" })}
                      >
                        <FolderOpenIcon className="size-3.5" />
                      </Button>
                      <Button
                        variant="ghost"
                        size="sm"
                        disabled={!s.url}
                        title="工作台 · 系统信息"
                        onClick={() => setWorkbench({ shell: s, tab: "info" })}
                      >
                        <InfoIcon className="size-3.5" />
                      </Button>
                      {s.protocol === "v2" && s.shell_type === "jsp" ? (
                        <Button
                          variant="ghost"
                          size="sm"
                          disabled={busyId === s.id}
                          title="Java 内存马"
                          onClick={() => openMemshells(s)}
                        >
                          <CpuIcon className="size-3.5" />
                        </Button>
                      ) : null}
                      {s.protocol === "v2" && s.shell_type === "php" && s.source !== "php_prepend" ? (
                        <Button
                          variant="ghost"
                          size="sm"
                          disabled={busyId === s.id}
                          title="PHP 半持久化（.user.ini / .htaccess）"
                          onClick={() => openPHPPersist(s)}
                        >
                          <PinIcon className="size-3.5" />
                        </Button>
                      ) : null}
                      <Button
                        variant="ghost"
                        size="sm"
                        disabled={busyId === s.id || s.protocol !== "v2"}
                        title="下载加密载荷"
                        onClick={() => void downloadPayload(s)}
                      >
                        <DownloadIcon className="size-3.5" />
                      </Button>
                      <Button
                        variant="ghost"
                        size="sm"
                        disabled={busyId === s.id || s.protocol !== "v2"}
                        title="轮换密钥"
                        onClick={() => void rotateKey(s)}
                      >
                        <KeyRoundIcon className="size-3.5" />
                      </Button>
                      <Button variant="ghost" size="sm" onClick={() => openEdit(s)}>
                        <PencilIcon className="size-3.5" />
                      </Button>
                      <Button variant="ghost" size="sm" disabled={busyId === s.id} onClick={() => remove(s)}>
                        <Trash2Icon className="size-3.5" />
                      </Button>
                    </div>
                  </TableCell>
                </TableRow>
              );
            })}
          </TableBody>
        </Table>
      ) : null}

      <Dialog open={editOpen} onOpenChange={setEditOpen}>
        <DialogContent className="sm:max-w-lg">
          <DialogHeader>
            <DialogTitle>{editing ? "编辑 webshell" : "添加 webshell"}</DialogTitle>
            <DialogDescription>
              {editing
                ? "编辑 webshell 元信息；协议与密钥由创建/轮换流程管理"
                : "加密 v2 会自动生成每目标随机密钥与随机请求载体，保存后下载载荷并部署到目标"}
            </DialogDescription>
          </DialogHeader>
          <form
            className="flex flex-col gap-4"
            onSubmit={(e) => {
              e.preventDefault();
              void save();
            }}
          >
            <FieldRow
              label="地址"
              hint={
                editing?.source === "php_prepend"
                  ? "半持久化地址由 prepend 配置决定；如需更换请撤销落地物后重新部署"
                  : undefined
              }
            >
              <Input
                value={form.url}
                onChange={(e) => setForm({ ...form, url: e.target.value })}
                placeholder="http://example.com/shell.php"
                disabled={editing?.source === "php_prepend"}
              />
            </FieldRow>
            <FieldRow label="名称">
              <Input
                value={form.name}
                onChange={(e) => setForm({ ...form, name: e.target.value })}
                placeholder="留空自动使用地址"
              />
            </FieldRow>
            <FieldRow label="类型">
              <Select
                value={form.shell_type}
                onValueChange={(v) => setForm({ ...form, shell_type: v })}
                disabled={editing?.protocol === "v2"}
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {SHELL_TYPES.map((t) => (
                    <SelectItem key={t.value} value={t.value}>
                      {t.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </FieldRow>
            {editing ? (
              <FieldRow label="协议">
                <div className="flex h-9 items-center rounded-md border px-3 text-sm">
                  {form.protocol === "v2"
                    ? `加密 v2 · 密钥 v${editing.key_version || 1} · 载体 ${editing.carrier || "—"}`
                    : "旧版明文（口令与命令随请求发送）"}
                </div>
              </FieldRow>
            ) : (
              <FieldRow label="协议">
                <Select value={form.protocol} onValueChange={(v) => setForm({ ...form, protocol: v })}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {SHELL_PROTOCOLS.map((p) => (
                      <SelectItem key={p.value} value={p.value}>
                        {p.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </FieldRow>
            )}
            {form.protocol === "legacy" ? (
              <FieldRow label={editing ? "口令（留空则不改）" : "口令"}>
                <Input
                  type="password"
                  value={form.password}
                  onChange={(e) => setForm({ ...form, password: e.target.value })}
                  placeholder={editing ? "留空保持原口令" : "旧版 shell 必须设置强口令"}
                />
              </FieldRow>
            ) : null}
            <FieldRow label="所属目标">
              <Input
                value={form.target}
                onChange={(e) => setForm({ ...form, target: e.target.value })}
                placeholder="http://example.com"
              />
            </FieldRow>
            <FieldRow label="备注">
              <Textarea value={form.note} onChange={(e) => setForm({ ...form, note: e.target.value })} rows={3} />
            </FieldRow>
            <DialogFooter>
              <Button type="submit" disabled={saving}>
                {saving ? <Loader2Icon className="size-4 animate-spin" /> : null}
                保存
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>

      <WebshellWorkbench
        key={workbench?.shell.id ?? "closed"}
        shell={workbench?.shell ?? null}
        initialTab={workbench?.tab ?? "term"}
        onOpenChange={(o) => !o && setWorkbench(null)}
      />
      <Dialog
        open={Boolean(msShell)}
        onOpenChange={(o) => {
          if (!o) {
            setMsShell(null);
            setMsExec(null);
          }
        }}
      >
        <DialogContent className="sm:max-w-5xl">
          <DialogHeader>
            <DialogTitle>Java 内存马 · {msShell?.name || msShell?.url}</DialogTitle>
            <DialogDescription>
              通过加密 v2 JSP webshell 注入常驻组件；每个内存马使用独立密钥，密钥封装后入库，不随请求回显。
            </DialogDescription>
          </DialogHeader>
          {msExec ? (
            <div className="flex flex-col gap-3">
              <div className="flex items-center justify-between gap-2">
                <div className="truncate font-mono text-xs">
                  {msExec.type} · {msExec.url}
                </div>
                <Button variant="ghost" size="sm" onClick={() => setMsExec(null)}>
                  返回列表
                </Button>
              </div>
              <ShellTerminal
                key={msExec.id}
                historyKey={`memshell-${msExec.id}`}
                heightClass="h-[46vh]"
                run={({ command: cmd, cwd, osKind, timeoutSeconds }) =>
                  api.execMemshell(msExec.id, {
                    command: cmd,
                    cwd,
                    os_kind: osKind,
                    timeout_seconds: timeoutSeconds,
                  })
                }
              />
            </div>
          ) : (
            <div className="flex flex-col gap-3">
              <div className="flex flex-wrap items-end gap-2 rounded-md border p-3">
                <div className="flex flex-col gap-1">
                  <span className="text-muted-foreground text-xs">类型</span>
                  <Select value={msType} onValueChange={setMsType}>
                    <SelectTrigger className="w-44">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {MEMSHELL_TYPES.map((t) => (
                        <SelectItem key={t.value} value={t.value}>
                          {t.label}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
                <div className="flex flex-col gap-1">
                  <span className="text-muted-foreground text-xs">名称（留空随机）</span>
                  <Input
                    value={msName}
                    onChange={(e) => setMsName(e.target.value)}
                    placeholder="ms_xxxx"
                    className="w-40 font-mono"
                  />
                </div>
                <div className="flex flex-col gap-1">
                  <span className="text-muted-foreground text-xs">路径（留空随机）</span>
                  <Input
                    value={msPath}
                    onChange={(e) => setMsPath(e.target.value)}
                    placeholder="/static/xxxx.js"
                    className="w-48 font-mono"
                  />
                </div>
                {msType === "agent" ? (
                  <div className="flex flex-col gap-1">
                    <span className="text-muted-foreground text-xs">监听端口</span>
                    <Input
                      value={msPort}
                      onChange={(e) => setMsPort(e.target.value)}
                      placeholder="留空自动"
                      className="w-28 font-mono"
                    />
                  </div>
                ) : null}
                <Button onClick={() => void deployMemshell()} disabled={msDeploying}>
                  {msDeploying ? <Loader2Icon className="size-4 animate-spin" /> : <PlusIcon className="size-4" />}
                  注入
                </Button>
              </div>
              {msLoading ? (
                <div className="flex items-center justify-center py-10 text-muted-foreground text-sm">
                  <Loader2Icon className="mr-2 size-4 animate-spin" />
                  加载中…
                </div>
              ) : memshells.length === 0 ? (
                <div className="rounded-md border border-dashed py-10 text-center text-muted-foreground text-sm">
                  还没有内存马。父 shell 需要使用最新导出的加密 v2 JSP 载荷。
                </div>
              ) : (
                <div className="max-h-[46vh] overflow-auto rounded-md border">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead className="w-20">类型</TableHead>
                        <TableHead>名称 / 地址</TableHead>
                        <TableHead className="w-40">容器</TableHead>
                        <TableHead className="w-24">状态</TableHead>
                        <TableHead className="w-36">最近检测</TableHead>
                        <TableHead className="w-48 text-right">操作</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {memshells.map((ms) => {
                        const badge = shellStatusMeta(ms.status);
                        return (
                          <TableRow key={ms.id}>
                            <TableCell>
                              <Badge variant="outline">{ms.type}</Badge>
                            </TableCell>
                            <TableCell className="max-w-80 truncate">
                              <div className="font-medium">{ms.name || "—"}</div>
                              <div className="truncate font-mono text-muted-foreground text-xs" title={ms.url}>
                                {ms.url}
                              </div>
                            </TableCell>
                            <TableCell className="text-muted-foreground text-xs">
                              {ms.container || "—"}
                              {ms.servlet_api ? ` · ${ms.servlet_api}` : ""}
                              {ms.port ? ` · :${ms.port}` : ""}
                            </TableCell>
                            <TableCell>
                              <Badge variant="outline" className={badge.className}>
                                {badge.label}
                              </Badge>
                            </TableCell>
                            <TableCell className="text-muted-foreground text-xs">{fmtTime(ms.last_checked)}</TableCell>
                            <TableCell className="text-right">
                              <div className="flex items-center justify-end gap-1">
                                <Button
                                  variant="ghost"
                                  size="sm"
                                  disabled={msBusyId === ms.id}
                                  onClick={() => void checkMemshell(ms)}
                                >
                                  检测
                                </Button>
                                <Button
                                  variant="ghost"
                                  size="sm"
                                  disabled={msBusyId === ms.id}
                                  title="终端"
                                  onClick={() => setMsExec(ms)}
                                >
                                  <TerminalIcon className="size-3.5" />
                                </Button>
                                <Button
                                  variant="ghost"
                                  size="sm"
                                  disabled={msBusyId === ms.id}
                                  onClick={() => void removeMemshell(ms)}
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
                </div>
              )}
            </div>
          )}
        </DialogContent>
      </Dialog>

      <Dialog
        open={Boolean(ppShell)}
        onOpenChange={(o) => {
          if (!o) {
            setPpShell(null);
            setPpResult(null);
            setPpError("");
            setPpRevoked(false);
          }
        }}
      >
        <DialogContent className="sm:max-w-3xl">
          <DialogHeader>
            <DialogTitle>PHP 半持久化 · {ppShell?.name || ppShell?.url}</DialogTitle>
            <DialogDescription>
              通过 .user.ini（PHP-FPM/CGI）或 .htaccess（Apache mod_php/LiteSpeed）把加密 prepend 载荷挂到同目录的 PHP
              请求上：普通访问静默放行，只有精卫 v2 协议能执行命令。部署会登记可撤销落地物。
            </DialogDescription>
          </DialogHeader>
          {ppResult ? (
            <div className="flex flex-col gap-4">
              <div className="flex flex-wrap items-center gap-2">
                <Badge variant="outline" className={ppBadge.className}>
                  {ppBadge.label}
                </Badge>
                <span className="text-muted-foreground text-sm">
                  {ppRevoked ? "落地物已撤销；该 prepend 通道已失效，平台记录保留供审计。" : ppResult.note}
                </span>
              </div>
              {ppResult.warnings?.length ? (
                <div className="rounded-md border border-amber-500/30 bg-amber-500/5 p-3 text-amber-700 text-xs dark:text-amber-400">
                  {ppResult.warnings.map((w) => (
                    <div key={w}>· {w}</div>
                  ))}
                </div>
              ) : null}
              <div className="grid gap-3 rounded-md border p-3 text-xs sm:grid-cols-2">
                <ResultRow label="模式" value={ppResult.mode} />
                <ResultRow
                  label="运行时"
                  value={`${ppResult.info.sapi || "—"} · PHP ${ppResult.info.php || "—"}${
                    ppResult.info.server ? ` · ${ppResult.info.server}` : ""
                  }`}
                />
                <ResultRow label="配置" value={ppResult.config_path} mono />
                <ResultRow label="载荷" value={ppResult.payload_path} mono />
                <ResultRow label="触发地址" value={ppResult.trigger_url} mono />
                <ResultRow
                  label="落地物 / webshell"
                  value={
                    [
                      ppResult.artifact ? `落地物 #${ppResult.artifact.id}` : "",
                      ppResult.webshell ? `webshell #${ppResult.webshell.id}` : "",
                    ]
                      .filter(Boolean)
                      .join(" · ") || "—"
                  }
                />
                {ppResult.pending && ppResult.user_ini_cache_ttl ? (
                  <ResultRow label="user_ini 缓存" value={`${ppResult.user_ini_cache_ttl} 秒`} />
                ) : null}
                {ppResult.info.auto_prepend_file ? (
                  <ResultRow label="auto_prepend_file" value={ppResult.info.auto_prepend_file} mono />
                ) : null}
              </div>
              <DialogFooter className="gap-2">
                {ppResult.artifact && !ppRevoked ? (
                  <Button variant="outline" onClick={() => void revokePHPPersist()} disabled={ppBusy}>
                    {ppBusy ? <Loader2Icon className="size-4 animate-spin" /> : null}
                    撤销落地物
                  </Button>
                ) : null}
                <Button onClick={() => setPpShell(null)}>关闭</Button>
              </DialogFooter>
            </div>
          ) : (
            <form
              className="flex flex-col gap-4"
              onSubmit={(e) => {
                e.preventDefault();
                void deployPHPPersist();
              }}
            >
              <div className="grid gap-3 sm:grid-cols-2">
                <FieldRow label="模式" hint="自动按目标 SAPI 选择；选错会因 SAPI 不支持而失败">
                  <Select value={ppMode} onValueChange={setPpMode}>
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {PHP_PERSIST_MODES.map((m) => (
                        <SelectItem key={m.value} value={m.value}>
                          {m.label}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </FieldRow>
                <FieldRow label="部署目录" hint="留空使用当前 webshell 所在目录">
                  <Input
                    value={ppDirectory}
                    onChange={(e) => setPpDirectory(e.target.value)}
                    placeholder="/var/www/html"
                    className="font-mono"
                  />
                </FieldRow>
                <FieldRow label="载荷文件名" hint="留空随机生成 .xxxxxxxx.php">
                  <Input
                    value={ppFilename}
                    onChange={(e) => setPpFilename(e.target.value)}
                    placeholder="留空随机"
                    className="font-mono"
                  />
                </FieldRow>
                <FieldRow label="配置文件名" hint="留空使用 .user.ini / .htaccess">
                  <Input
                    value={ppConfigName}
                    onChange={(e) => setPpConfigName(e.target.value)}
                    placeholder="留空默认"
                    className="font-mono"
                  />
                </FieldRow>
                <FieldRow label="触发地址" hint="留空根据父 webshell 推断；必须同源">
                  <Input
                    value={ppTrigger}
                    onChange={(e) => setPpTrigger(e.target.value)}
                    placeholder={ppShell?.url || "http://example.com/index.php"}
                    className="font-mono"
                  />
                </FieldRow>
                <FieldRow label="等待探测（秒）" hint="留空自动：user_ini 8 秒 / .htaccess 3 秒，最大 120">
                  <Input
                    type="number"
                    min={0}
                    max={120}
                    value={ppWait}
                    onChange={(e) => setPpWait(e.target.value)}
                    placeholder="自动"
                  />
                </FieldRow>
                <FieldRow label="台账 TTL（秒）" hint="60–2592000；留空表示不过期">
                  <Input
                    type="number"
                    min={0}
                    value={ppTTL}
                    onChange={(e) => setPpTTL(e.target.value)}
                    placeholder="不过期"
                  />
                </FieldRow>
                <FieldRow label="新 webshell 名称" hint="留空自动命名">
                  <Input value={ppName} onChange={(e) => setPpName(e.target.value)} placeholder="留空自动" />
                </FieldRow>
              </div>
              <FieldRow label="落地物描述">
                <Textarea
                  rows={2}
                  value={ppDescription}
                  onChange={(e) => setPpDescription(e.target.value)}
                  placeholder="留空自动生成"
                />
              </FieldRow>
              <label className="flex items-center gap-2 text-sm">
                <input
                  type="checkbox"
                  className="size-4 accent-emerald-600"
                  checked={ppForce}
                  onChange={(e) => setPpForce(e.target.checked)}
                />
                强制覆盖目标已有的 auto_prepend_file 配置（force）
              </label>
              {ppError ? <p className="text-red-600 text-sm dark:text-red-400">{ppError}</p> : null}
              <DialogFooter>
                <Button type="submit" disabled={ppDeploying}>
                  {ppDeploying ? <Loader2Icon className="size-4 animate-spin" /> : <PinIcon className="size-4" />}
                  部署半持久化
                </Button>
              </DialogFooter>
            </form>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}
