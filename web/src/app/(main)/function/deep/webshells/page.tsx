"use client";

import * as React from "react";

import { Loader2Icon, PencilIcon, PlusIcon, ServerCogIcon, TerminalIcon, Trash2Icon } from "lucide-react";
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
import { ScrollArea } from "@/components/ui/scroll-area";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Textarea } from "@/components/ui/textarea";
import { api } from "@/lib/api";
import type { Webshell } from "@/lib/types";

import { FieldRow, fmtTime } from "../_components/deep-ui";

const SHELL_TYPES = [
  { value: "php", label: "PHP" },
  { value: "jsp", label: "JSP" },
  { value: "aspx", label: "ASPX" },
];

function statusBadge(status: string) {
  switch (status) {
    case "alive":
      return { label: "存活", className: "border-emerald-500/30 bg-emerald-500/10 text-emerald-600" };
    case "dead":
      return { label: "失效", className: "border-red-500/30 bg-red-500/10 text-red-600 dark:text-red-400" };
    default:
      return { label: "未检测", className: "border-slate-500/30 bg-slate-500/10 text-slate-600 dark:text-slate-400" };
  }
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
    password: "",
    target: "",
    note: "",
  });

  const [execShell, setExecShell] = React.useState<Webshell | null>(null);
  const [command, setCommand] = React.useState("id");
  const [output, setOutput] = React.useState("");
  const [running, setRunning] = React.useState(false);

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
    setForm({ name: "", url: "", shell_type: "php", password: "", target: "", note: "" });
    setEditOpen(true);
  }

  function openEdit(shell: Webshell) {
    setEditing(shell);
    setForm({
      name: shell.name,
      url: shell.url,
      shell_type: shell.shell_type || "php",
      password: shell.password,
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
        password: form.password,
        target: form.target.trim(),
        note: form.note,
      };
      if (editing) {
        await api.updateWebshell(editing.id, payload);
        toast.success("已保存");
      } else {
        await api.createWebshell(payload);
        toast.success("已添加");
      }
      setEditOpen(false);
      setRefreshKey((k) => k + 1);
    } catch (e) {
      toast.error((e as Error).message);
    } finally {
      setSaving(false);
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

  async function runCommand() {
    if (!execShell) return;
    const cmd = command.trim();
    if (!cmd) {
      toast.error("请输入要执行的命令");
      return;
    }
    setRunning(true);
    setOutput("");
    try {
      const r = await api.execWebshell(execShell.id, cmd);
      setOutput(r.output ?? "");
      setRefreshKey((k) => k + 1);
    } catch (e) {
      setOutput((e as Error).message);
      toast.error((e as Error).message);
    } finally {
      setRunning(false);
    }
  }

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
              <TableHead className="w-24">状态</TableHead>
              <TableHead className="w-36">最近检测</TableHead>
              <TableHead className="w-44 text-right">操作</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {shells.map((s) => {
              const badge = statusBadge(s.status);
              return (
                <TableRow key={s.id}>
                  <TableCell className="max-w-40 truncate font-medium" title={s.name}>
                    {s.name || "—"}
                  </TableCell>
                  <TableCell className="max-w-72 truncate font-mono text-xs" title={s.url}>
                    {s.url || "—"}
                  </TableCell>
                  <TableCell>
                    <Badge variant="outline">{s.shell_type?.toUpperCase() || "PHP"}</Badge>
                  </TableCell>
                  <TableCell>
                    <Badge variant="outline" className={badge.className}>
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
                        onClick={() => {
                          setExecShell(s);
                          setOutput(s.last_output ?? "");
                          setCommand("id");
                        }}
                      >
                        <TerminalIcon className="size-3.5" />
                        执行
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
            <DialogDescription>登记一个已获取的 webshell 地址</DialogDescription>
          </DialogHeader>
          <form
            className="flex flex-col gap-4"
            onSubmit={(e) => {
              e.preventDefault();
              void save();
            }}
          >
            <FieldRow label="地址">
              <Input
                value={form.url}
                onChange={(e) => setForm({ ...form, url: e.target.value })}
                placeholder="http://example.com/shell.php"
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
              <Select value={form.shell_type} onValueChange={(v) => setForm({ ...form, shell_type: v })}>
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
            <FieldRow label="密码">
              <Input
                value={form.password}
                onChange={(e) => setForm({ ...form, password: e.target.value })}
                placeholder="webshell 口令"
              />
            </FieldRow>
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

      <Dialog open={Boolean(execShell)} onOpenChange={(o) => !o && setExecShell(null)}>
        <DialogContent className="sm:max-w-3xl">
          <DialogHeader>
            <DialogTitle>命令执行</DialogTitle>
            <DialogDescription className="font-mono text-xs">{execShell?.url}</DialogDescription>
          </DialogHeader>
          <div className="flex flex-col gap-3">
            <div className="flex gap-2">
              <Input
                value={command}
                onChange={(e) => setCommand(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") void runCommand();
                }}
                placeholder="要执行的命令，例如 id"
                className="font-mono"
              />
              <Button onClick={() => void runCommand()} disabled={running}>
                {running ? <Loader2Icon className="size-4 animate-spin" /> : <TerminalIcon className="size-4" />}
                执行
              </Button>
            </div>
            <ScrollArea className="h-72 rounded-md border">
              <pre className="whitespace-pre-wrap break-all p-3 font-mono text-xs">{output || "（无输出）"}</pre>
            </ScrollArea>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}
