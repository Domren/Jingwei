"use client";

import * as React from "react";

import {
  ArrowLeftIcon,
  ArrowUpIcon,
  DownloadIcon,
  FileIcon,
  FilePlusIcon,
  FolderIcon,
  FolderPlusIcon,
  LinkIcon,
  Loader2Icon,
  PencilIcon,
  RefreshCwIcon,
  SaveIcon,
  Trash2Icon,
  UploadIcon,
} from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Textarea } from "@/components/ui/textarea";
import { api } from "@/lib/api";
import type { ShellFileAction, ShellFileEntry, ShellFileList, Webshell } from "@/lib/types";

const DEFAULT_CHUNK = 256 << 10;
const DEFAULT_MAX_READ = 512 << 10;
const EDIT_MAX_BYTES = 1 << 20;

function joinRemote(dir: string, name: string) {
  if (!dir) return name;
  const sep = dir.includes("\\") && !dir.includes("/") ? "\\" : "/";
  return dir.endsWith("/") || dir.endsWith("\\") ? `${dir}${name}` : `${dir}${sep}${name}`;
}

function fmtSize(n: number) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KiB`;
  if (n < 1024 * 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(1)} MiB`;
  return `${(n / (1024 * 1024 * 1024)).toFixed(2)} GiB`;
}

function fmtMTime(sec: number) {
  if (!sec) return "—";
  return new Date(sec * 1000).toLocaleString();
}

function bytesToB64(bytes: Uint8Array) {
  let binary = "";
  const step = 0x8000;
  for (let i = 0; i < bytes.length; i += step) {
    binary += String.fromCharCode(...bytes.subarray(i, i + step));
  }
  return btoa(binary);
}

function b64ToBytes(b64: string) {
  const binary = atob(b64);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

function entryIcon(type: ShellFileEntry["type"]) {
  if (type === "dir") return <FolderIcon className="size-4 text-amber-500" />;
  if (type === "link") return <LinkIcon className="size-4 text-sky-500" />;
  return <FileIcon className="size-4 text-muted-foreground" />;
}

export function WebshellFilesPanel({
  shell,
  listHeight = "h-[52vh]",
}: {
  shell: Webshell | null;
  listHeight?: string;
}) {
  const [list, setList] = React.useState<ShellFileList | null>(null);
  const [pathInput, setPathInput] = React.useState("");
  const [selected, setSelected] = React.useState<ShellFileEntry | null>(null);
  const [loading, setLoading] = React.useState(false);
  const [busy, setBusy] = React.useState(false);
  const [busyLabel, setBusyLabel] = React.useState("");
  const [chunkSize, setChunkSize] = React.useState(DEFAULT_CHUNK);
  const [maxRead, setMaxRead] = React.useState(DEFAULT_MAX_READ);
  const uploadRef = React.useRef<HTMLInputElement | null>(null);

  const [editorOpen, setEditorOpen] = React.useState(false);
  const [editorPath, setEditorPath] = React.useState("");
  const [editorText, setEditorText] = React.useState("");

  const shellId = shell?.id ?? 0;

  React.useEffect(() => {
    setList(null);
    setSelected(null);
    setEditorOpen(false);
    setEditorPath("");
    setEditorText("");
    setPathInput("");
    setBusy(false);
    setBusyLabel("");
    if (!shellId) return;
    let alive = true;
    setLoading(true);
    void (async () => {
      try {
        const r = await api.webshellFiles(shellId);
        if (!alive) return;
        setList(r);
        setPathInput(r.path);
        setChunkSize(r.chunk_size || DEFAULT_CHUNK);
        setMaxRead(r.max_read || DEFAULT_MAX_READ);
      } catch (e) {
        if (alive) toast.error((e as Error).message);
      } finally {
        if (alive) setLoading(false);
      }
    })();
    return () => {
      alive = false;
    };
  }, [shellId]);

  async function load(path?: string) {
    if (!shell) return;
    setLoading(true);
    try {
      const r = await api.webshellFiles(shell.id, path);
      setList(r);
      setPathInput(r.path);
      setChunkSize(r.chunk_size || DEFAULT_CHUNK);
      setMaxRead(r.max_read || DEFAULT_MAX_READ);
      setSelected(null);
    } catch (e) {
      toast.error((e as Error).message);
    } finally {
      setLoading(false);
    }
  }

  function currentPath(name: string) {
    return joinRemote(list?.path ?? "", name);
  }

  async function readAll(path: string, limit: number) {
    if (!shell) throw new Error("webshell 不存在");
    const parts: Uint8Array[] = [];
    let offset = 0;
    let total = 0;
    for (;;) {
      const c = await api.webshellFileRead(shell.id, path, offset, maxRead);
      const bytes = b64ToBytes(c.data);
      parts.push(bytes);
      total += bytes.length;
      offset += bytes.length;
      if (c.eof || bytes.length === 0 || total >= limit) break;
    }
    const out = new Uint8Array(total);
    let at = 0;
    for (const part of parts) {
      out.set(part, at);
      at += part.length;
    }
    return out;
  }

  async function openEditor(entry: ShellFileEntry) {
    if (!shell || entry.type === "dir") return;
    if (entry.size > EDIT_MAX_BYTES) {
      toast.error("文本编辑仅支持 1 MiB 以内的文件，请先下载后处理");
      return;
    }
    setBusy(true);
    setBusyLabel("读取文件…");
    try {
      const bytes = await readAll(currentPath(entry.name), EDIT_MAX_BYTES);
      if (bytes.includes(0)) {
        toast.error("检测到二进制内容，已阻止文本编辑（可下载后处理）");
        return;
      }
      setEditorPath(currentPath(entry.name));
      setEditorText(new TextDecoder().decode(bytes));
      setEditorOpen(true);
    } catch (e) {
      toast.error((e as Error).message);
    } finally {
      setBusy(false);
      setBusyLabel("");
    }
  }

  async function saveEditor() {
    if (!shell || !editorPath) return;
    setBusy(true);
    setBusyLabel("保存中…");
    try {
      const bytes = new TextEncoder().encode(editorText);
      if (bytes.length === 0) {
        await api.webshellFileWrite(shell.id, { path: editorPath, offset: 0, start: true, data: "" });
      } else {
        for (let off = 0; off < bytes.length; off += chunkSize) {
          const slice = bytes.subarray(off, Math.min(off + chunkSize, bytes.length));
          await api.webshellFileWrite(shell.id, {
            path: editorPath,
            offset: off,
            start: off === 0,
            data: bytesToB64(slice),
          });
        }
      }
      toast.success("已保存");
      setEditorOpen(false);
      await load(list?.path);
    } catch (e) {
      toast.error((e as Error).message);
    } finally {
      setBusy(false);
      setBusyLabel("");
    }
  }

  async function uploadFile(file: File) {
    if (!shell) return;
    const target = joinRemote(list?.path ?? "", file.name);
    setBusy(true);
    setBusyLabel(`上传 ${file.name}…`);
    try {
      let offset = 0;
      for (;;) {
        const end = Math.min(offset + chunkSize, file.size);
        const buf = new Uint8Array(await file.slice(offset, end).arrayBuffer());
        await api.webshellFileWrite(shell.id, {
          path: target,
          offset,
          start: offset === 0,
          data: bytesToB64(buf),
        });
        offset = end;
        if (offset >= file.size) break;
      }
      toast.success(`已上传 ${file.name}（${fmtSize(file.size)}）`);
      await load(list?.path);
    } catch (e) {
      toast.error((e as Error).message);
    } finally {
      setBusy(false);
      setBusyLabel("");
    }
  }

  async function downloadFile(entry: ShellFileEntry) {
    if (!shell || entry.type === "dir") return;
    setBusy(true);
    setBusyLabel(`下载 ${entry.name}…`);
    try {
      const path = currentPath(entry.name);
      const parts: Uint8Array[] = [];
      let offset = 0;
      for (;;) {
        const c = await api.webshellFileRead(shell.id, path, offset, maxRead);
        const bytes = b64ToBytes(c.data);
        parts.push(bytes);
        offset += bytes.length;
        if (c.eof || bytes.length === 0) break;
      }
      const blob = new Blob(parts as BlobPart[]);
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = entry.name || "download.bin";
      a.click();
      URL.revokeObjectURL(url);
      toast.success(`已下载 ${entry.name}（${fmtSize(offset)}）`);
    } catch (e) {
      toast.error((e as Error).message);
    } finally {
      setBusy(false);
      setBusyLabel("");
    }
  }

  async function runAction(
    action: ShellFileAction,
    path: string,
    extra?: { target?: string; recursive?: boolean; mode?: string },
  ) {
    if (!shell) return;
    setBusy(true);
    setBusyLabel("执行操作…");
    try {
      await api.webshellFileAction(shell.id, { action, path, ...extra });
      toast.success("操作完成");
      await load(list?.path);
    } catch (e) {
      toast.error((e as Error).message);
    } finally {
      setBusy(false);
      setBusyLabel("");
    }
  }

  function newDirectory() {
    const name = window.prompt("新目录名称");
    if (!name?.trim()) return;
    void runAction("mkdir", joinRemote(list?.path ?? "", name.trim()));
  }

  function newFile() {
    const name = window.prompt("新文件名称");
    if (!name?.trim()) return;
    if (!shell) return;
    setBusy(true);
    setBusyLabel("创建文件…");
    void (async () => {
      try {
        await api.webshellFileWrite(shell.id, {
          path: joinRemote(list?.path ?? "", name.trim()),
          offset: 0,
          start: true,
          data: "",
        });
        toast.success("已创建空文件");
        await load(list?.path);
      } catch (e) {
        toast.error((e as Error).message);
      } finally {
        setBusy(false);
        setBusyLabel("");
      }
    })();
  }

  function renameSelected() {
    if (!selected) return;
    const next = window.prompt(`将「${selected.name}」重命名为`, selected.name);
    if (!next?.trim() || next.trim() === selected.name) return;
    void runAction("rename", currentPath(selected.name), { target: joinRemote(list?.path ?? "", next.trim()) });
  }

  function deleteSelected() {
    if (!selected) return;
    const kind = selected.type === "dir" ? "目录（含全部内容，递归删除）" : "文件";
    if (!window.confirm(`删除${kind}「${currentPath(selected.name)}」？此操作不可恢复。`)) return;
    void runAction("delete", currentPath(selected.name), { recursive: selected.type === "dir" });
  }

  function chmodSelected() {
    if (!selected) return;
    const initial = selected.mode && selected.mode !== "-" ? selected.mode : "0644";
    const mode = window.prompt(`权限模式（3–4 位八进制，当前 ${selected.mode || "—"}）`, initial);
    if (!mode?.trim()) return;
    if (!/^[0-7]{3,4}$/.test(mode.trim())) {
      toast.error("权限模式必须是 3 到 4 位八进制");
      return;
    }
    void runAction("chmod", currentPath(selected.name), { mode: mode.trim() });
  }

  const canPick = Boolean(selected) && !busy;
  const isFile = selected?.type === "file" || selected?.type === "link";

  return (
    <div className="flex min-w-0 flex-col gap-3">
      <p className="text-muted-foreground text-xs">
        通过加密 v2 通道读写目标文件；部署的 shell 文件与密钥缓存受保护，不能在此修改或删除。
      </p>
      {editorOpen ? (
        <div className="flex flex-col gap-3">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="flex min-w-0 items-center gap-2">
              <Button variant="ghost" size="sm" disabled={busy} onClick={() => setEditorOpen(false)}>
                <ArrowLeftIcon className="size-4" />
                返回
              </Button>
              <span className="truncate font-mono text-xs" title={editorPath}>
                {editorPath}
              </span>
              <Badge variant="outline">UTF-8</Badge>
            </div>
            <Button size="sm" disabled={busy} onClick={() => void saveEditor()}>
              {busy ? <Loader2Icon className="size-4 animate-spin" /> : <SaveIcon className="size-4" />}
              保存
            </Button>
          </div>
          <Textarea
            className="h-[52vh] resize-none font-mono text-xs"
            value={editorText}
            onChange={(e) => setEditorText(e.target.value)}
            spellCheck={false}
          />
          <p className="text-muted-foreground text-xs">
            保存会按 {fmtSize(chunkSize)} 分块覆盖远端文件；仅支持 1 MiB 以内的 UTF-8 文本。
          </p>
        </div>
      ) : (
        <div className="flex flex-col gap-3">
          <div className="flex flex-wrap items-center gap-2">
            <Button
              variant="ghost"
              size="sm"
              disabled={!list || loading || busy}
              title="上级目录"
              onClick={() => {
                if (list && list.parent !== list.path) void load(list.parent);
              }}
            >
              <ArrowUpIcon className="size-4" />
            </Button>
            <Button
              variant="ghost"
              size="sm"
              disabled={loading || busy}
              title="刷新"
              onClick={() => void load(list?.path)}
            >
              <RefreshCwIcon className="size-4" />
            </Button>
            <form
              className="flex min-w-0 flex-1 gap-2"
              onSubmit={(e) => {
                e.preventDefault();
                void load(pathInput);
              }}
            >
              <Input
                value={pathInput}
                onChange={(e) => setPathInput(e.target.value)}
                placeholder="目录绝对路径；留空使用 shell 当前目录"
                className="font-mono text-xs"
              />
              <Button type="submit" variant="outline" size="sm" disabled={loading || busy}>
                跳转
              </Button>
            </form>
          </div>

          <div className="flex flex-wrap items-center gap-1">
            <Button variant="outline" size="sm" disabled={!list || busy} onClick={() => uploadRef.current?.click()}>
              <UploadIcon className="size-3.5" />
              上传
            </Button>
            <Button variant="outline" size="sm" disabled={!list || busy} onClick={newFile}>
              <FilePlusIcon className="size-3.5" />
              新建文件
            </Button>
            <Button variant="outline" size="sm" disabled={!list || busy} onClick={newDirectory}>
              <FolderPlusIcon className="size-3.5" />
              新建目录
            </Button>
            <Button
              variant="outline"
              size="sm"
              disabled={!canPick || !isFile}
              onClick={() => selected && void downloadFile(selected)}
            >
              <DownloadIcon className="size-3.5" />
              下载
            </Button>
            <Button
              variant="outline"
              size="sm"
              disabled={!canPick || !isFile}
              onClick={() => selected && void openEditor(selected)}
            >
              <PencilIcon className="size-3.5" />
              编辑
            </Button>
            <Button variant="outline" size="sm" disabled={!canPick} onClick={renameSelected}>
              重命名
            </Button>
            <Button variant="outline" size="sm" disabled={!canPick} onClick={chmodSelected}>
              权限
            </Button>
            <Button variant="outline" size="sm" disabled={!canPick} onClick={deleteSelected}>
              <Trash2Icon className="size-3.5" />
              删除
            </Button>
            {busy ? (
              <span className="ml-auto flex items-center gap-1 text-muted-foreground text-xs">
                <Loader2Icon className="size-3.5 animate-spin" />
                {busyLabel || "处理中…"}
              </span>
            ) : null}
            <input
              ref={uploadRef}
              type="file"
              className="hidden"
              onChange={(e) => {
                const f = e.target.files?.[0];
                e.currentTarget.value = "";
                if (f) void uploadFile(f);
              }}
            />
          </div>

          {list?.truncated ? (
            <div className="rounded-md border border-amber-500/30 bg-amber-500/5 p-2 text-amber-700 text-xs dark:text-amber-400">
              目录条目超过上限，仅展示前 3000 项。
            </div>
          ) : null}

          {loading ? (
            <div className="flex items-center justify-center py-16 text-muted-foreground text-sm">
              <Loader2Icon className="mr-2 size-4 animate-spin" />
              读取目录…
            </div>
          ) : (
            <ScrollArea className={`${listHeight} rounded-md border`}>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>名称</TableHead>
                    <TableHead className="w-28">大小</TableHead>
                    <TableHead className="w-24">权限</TableHead>
                    <TableHead className="w-44">修改时间</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {(list?.entries ?? []).map((entry) => (
                    <TableRow
                      key={entry.name}
                      data-state={selected?.name === entry.name ? "selected" : undefined}
                      className="cursor-pointer"
                      onClick={() => setSelected(entry)}
                      onDoubleClick={() => {
                        if (entry.type === "dir") void load(currentPath(entry.name));
                        else void openEditor(entry);
                      }}
                    >
                      <TableCell className="max-w-0">
                        <div className="flex min-w-0 items-center gap-2">
                          {entryIcon(entry.type)}
                          <span className="truncate font-mono text-xs" title={entry.name}>
                            {entry.name}
                          </span>
                          {entry.type === "link" ? (
                            <Badge variant="outline" className="text-[10px]">
                              链接
                            </Badge>
                          ) : null}
                        </div>
                      </TableCell>
                      <TableCell className="font-mono text-muted-foreground text-xs">
                        {entry.type === "dir" ? "—" : fmtSize(entry.size)}
                      </TableCell>
                      <TableCell className="font-mono text-muted-foreground text-xs">{entry.mode || "—"}</TableCell>
                      <TableCell className="text-muted-foreground text-xs">{fmtMTime(entry.modified)}</TableCell>
                    </TableRow>
                  ))}
                  {!loading && (list?.entries ?? []).length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={4} className="py-10 text-center text-muted-foreground text-sm">
                        空目录
                      </TableCell>
                    </TableRow>
                  ) : null}
                </TableBody>
              </Table>
            </ScrollArea>
          )}

          <div className="flex items-center justify-between gap-2">
            <span className="truncate text-left font-mono text-muted-foreground text-xs" title={list?.path}>
              {list?.path || "—"}
            </span>
            <span className="text-muted-foreground text-xs">
              双击目录进入、双击文件编辑；单块 {fmtSize(chunkSize)}，单次读取上限 {fmtSize(maxRead)}。
            </span>
          </div>
        </div>
      )}
    </div>
  );
}
