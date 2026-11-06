"use client";

import * as React from "react";

import { ArrowRightIcon, CopyIcon, Loader2Icon, TerminalIcon, Trash2Icon } from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import type { ShellExecResult } from "@/lib/types";

import { ExecFormDialog } from "./exec-form-dialog";

/**
 * One terminal turn, delivered by the caller.
 *
 * Delivery stays outside this component on purpose: a landed webshell, an
 * injected memory horse and an intranet SSH session all speak the same
 * cwd/exit-code marker protocol on the server side, so the terminal is the part
 * worth sharing and the transport is the part that must vary.
 */
export type ShellRun = (input: {
  command: string;
  cwd: string;
  /**
   * The shell family the terminal last saw on this channel. A landed webshell
   * has it cached server-side and ignores this; a memory horse has no ledger
   * row of its own, so echoing it back is what saves a probe per command.
   */
  osKind: string;
  timeoutSeconds: number;
}) => Promise<ShellExecResult>;

const HISTORY_CAP = 100;
const TIMEOUT_CHOICES = [15, 30, 60, 120, 300];

const POSIX_QUICK = ["id", "uname -a", "pwd", "ls -la", "cat /etc/passwd", "ip -a", "netstat -lntp", "ps aux", "env"];
const WINDOWS_QUICK = [
  "whoami",
  "ver",
  "cd",
  "dir",
  "set",
  "ipconfig /all",
  "netstat -ano",
  "tasklist",
  "echo %USERPROFILE%",
];

interface TermLine {
  id: number;
  command: string;
  at: number;
  cwd: string;
  result: ShellExecResult;
}

export function fmtDuration(ms: number) {
  if (ms < 1000) return `${ms} ms`;
  if (ms < 60000) return `${(ms / 1000).toFixed(1)} s`;
  return `${Math.floor(ms / 60000)}m${Math.round((ms % 60000) / 1000)}s`;
}

/**
 * Quotes a pasted directory for the target's shell. Only spaces need quoting
 * here — a command the operator types freely goes through unquoted — so the
 * rules are the same ones the server applies before splicing a stored cwd into
 * a wrapper: reject the metacharacters that could end the quote.
 */
function quotePath(path: string, osKind: string): string | null {
  if (osKind === "windows") {
    if (/[">|&^%]/.test(path)) return null;
    return `"${path}"`;
  }
  if (path.includes("'")) return null;
  return `'${path}'`;
}

// shellExitBadge is exported because the intranet dialog's upload tab shows the
// same turn outcome outside a terminal; one badge rule, two renderers.
export function shellExitBadge(result: ShellExecResult) {
  if (result.timed_out) return { label: "超时", className: "border-amber-500/40 bg-amber-500/10 text-amber-600" };
  if (!result.marker_ok)
    return { label: "无结束标记", className: "border-amber-500/40 bg-amber-500/10 text-amber-600" };
  if (result.exit_code === 0)
    return { label: "0", className: "border-emerald-500/40 bg-emerald-500/10 text-emerald-600" };
  if (result.exit_code < 0) return { label: "未知", className: "border-slate-500/40 bg-slate-500/10 text-slate-600" };
  return {
    label: String(result.exit_code),
    className: "border-red-500/40 bg-red-500/10 text-red-600 dark:text-red-400",
  };
}

export function ShellTerminal({
  run,
  historyKey,
  osKind: osKindProp,
  initialCwd = "",
  heightClass = "h-[46vh]",
  onCwdChange,
}: {
  run: ShellRun;
  /** Stable identity for the command history, e.g. `webshell-12`. */
  historyKey: string;
  osKind?: string;
  initialCwd?: string;
  heightClass?: string;
  onCwdChange?: (cwd: string) => void;
}) {
  const [lines, setLines] = React.useState<TermLine[]>([]);
  const [input, setInput] = React.useState("");
  const [cwdInput, setCwdInput] = React.useState("");
  const [cwd, setCwd] = React.useState(initialCwd);
  const [osKind, setOsKind] = React.useState(osKindProp ?? "");
  const [busy, setBusy] = React.useState(false);
  const [timeoutSeconds, setTimeoutSeconds] = React.useState(30);
  const [follow, setFollow] = React.useState(true);
  const [history, setHistory] = React.useState<string[]>([]);
  const [histIdx, setHistIdx] = React.useState<number | null>(null);
  // 非空表示正在看这条命令的 exec() 语境形式（E4）。
  const [formCmd, setFormCmd] = React.useState("");

  const nextId = React.useRef(1);
  const boxRef = React.useRef<HTMLDivElement | null>(null);
  const inputRef = React.useRef<HTMLInputElement | null>(null);

  const storageKey = `jingwei.shellTerm.${historyKey}`;

  React.useEffect(() => {
    try {
      const raw = window.localStorage.getItem(storageKey);
      if (raw) setHistory(JSON.parse(raw) as string[]);
    } catch {
      // A corrupt or unavailable store only costs the operator their ↑ history.
    }
  }, [storageKey]);

  const lastLine = lines[lines.length - 1];
  React.useEffect(() => {
    if (!follow || !lastLine) return;
    const box = boxRef.current;
    if (box) box.scrollTop = box.scrollHeight;
  }, [follow, lastLine]);

  function pushHistory(command: string) {
    setHistory((prev) => {
      const next = [command, ...prev.filter((c) => c !== command)].slice(0, HISTORY_CAP);
      try {
        window.localStorage.setItem(storageKey, JSON.stringify(next));
      } catch {
        // ignore
      }
      return next;
    });
  }

  function appendLine(command: string, atCwd: string, result: ShellExecResult) {
    setLines((prev) => [...prev, { id: nextId.current++, command, at: Date.now(), cwd: atCwd, result }]);
    if (result.cwd) {
      setCwd(result.cwd);
      onCwdChange?.(result.cwd);
    }
    if (result.os_kind) setOsKind(result.os_kind);
  }

  async function submit(command: string) {
    const cmd = command.trim();
    if (!cmd || busy) return;
    setBusy(true);
    pushHistory(cmd);
    try {
      const res = await run({ command: cmd, cwd, osKind, timeoutSeconds });
      appendLine(cmd, cwd, res);
      setInput("");
      setHistIdx(null);
    } catch (e) {
      // Keep the failure in the scrollback: a terminal that swallows its own
      // errors teaches the operator to distrust it.
      const message = (e as Error).message;
      appendLine(cmd, cwd, {
        output: message,
        exit_code: -1,
        duration_ms: 0,
        timed_out: false,
        marker_ok: false,
        is_error: true,
        note: message,
      });
      toast.error(message);
    } finally {
      setBusy(false);
      inputRef.current?.focus();
    }
  }

  function onKeyDown(e: React.KeyboardEvent<HTMLInputElement>) {
    if (e.key === "Enter") {
      e.preventDefault();
      void submit(input);
      return;
    }
    if (e.key === "ArrowUp") {
      if (history.length === 0) return;
      e.preventDefault();
      const idx = histIdx === null ? 0 : Math.min(histIdx + 1, history.length - 1);
      setHistIdx(idx);
      setInput(history[idx]);
      return;
    }
    if (e.key === "ArrowDown") {
      if (histIdx === null) return;
      e.preventDefault();
      if (histIdx === 0) {
        setHistIdx(null);
        setInput("");
        return;
      }
      const idx = histIdx - 1;
      setHistIdx(idx);
      setInput(history[idx]);
    }
  }

  function jumpCwd() {
    const path = cwdInput.trim();
    if (!path) return;
    const quoted = quotePath(path, osKind);
    if (!quoted) {
      toast.error("路径包含与目标 shell 冲突的字符，请直接在命令行里处理");
      return;
    }
    setCwdInput("");
    void submit(`cd ${quoted}`);
  }

  function copySession() {
    const text = lines.map((l) => `$ ${l.command}\n${l.result.output || ""}\n`).join("\n");
    void navigator.clipboard
      .writeText(text)
      .then(() => toast.success("已复制会话文本"))
      .catch(() => toast.error("复制失败"));
  }

  const quick = osKind === "windows" ? WINDOWS_QUICK : POSIX_QUICK;

  return (
    <div className="flex min-w-0 flex-col gap-2">
      <div className="flex flex-wrap items-center gap-2 text-xs">
        {/* 探测不到（chroot、受限 shell、目标当时没答）时人工指定；选「自动」把判断
            交回服务端重新探测。指定值是决定，不是猜测，所以会被记进台账。 */}
        <Select value={osKind || "auto"} onValueChange={(v) => setOsKind(v === "auto" ? "" : String(v))}>
          <SelectTrigger className="w-32" size="sm">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="auto">自动探测系统族</SelectItem>
            <SelectItem value="posix">POSIX sh</SelectItem>
            <SelectItem value="windows">Windows cmd</SelectItem>
          </SelectContent>
        </Select>
        <span className="text-muted-foreground">当前目录</span>
        <span
          className="max-w-[22rem] truncate rounded bg-muted px-1.5 py-0.5 font-mono"
          title={cwd || "（执行首条命令后由目标回传）"}
        >
          {cwd || "（执行首条命令后由目标回传）"}
        </span>
        <form
          className="flex min-w-0 flex-1 items-center gap-1"
          onSubmit={(e) => {
            e.preventDefault();
            jumpCwd();
          }}
        >
          <Input
            value={cwdInput}
            onChange={(e) => setCwdInput(e.target.value)}
            placeholder={
              osKind === "windows" ? "粘贴目录后回车跳转，例如 C:\\inetpub" : "粘贴目录后回车跳转，例如 /etc"
            }
            className="h-7 min-w-0 flex-1 font-mono text-xs"
          />
          <Button type="submit" variant="outline" size="sm" className="h-7" disabled={busy || !cwdInput.trim()}>
            <ArrowRightIcon className="size-3.5" />
            跳转
          </Button>
        </form>
      </div>

      <div
        ref={boxRef}
        className={`${heightClass} min-w-0 overflow-auto rounded-md border bg-muted/30 p-3 font-mono text-xs`}
      >
        {lines.length === 0 ? (
          <div className="flex h-full flex-col items-center justify-center gap-1 text-muted-foreground">
            <TerminalIcon className="size-5" />
            <span>目录与退出码由命令通道逐条回传；↑/↓ 翻历史，cd 直接改目录</span>
          </div>
        ) : (
          <div className="flex flex-col gap-3">
            {lines.map((line) => {
              const badge = shellExitBadge(line.result);
              return (
                <div key={line.id} className="flex min-w-0 flex-col gap-1">
                  <div className="flex flex-wrap items-center gap-2 text-muted-foreground">
                    <span className="text-emerald-600 dark:text-emerald-400">$</span>
                    <span className="break-all text-foreground">{line.command}</span>
                    <span className="ml-auto flex shrink-0 items-center gap-2">
                      <span className="max-w-[14rem] truncate" title={line.cwd}>
                        {line.cwd || "/"}
                      </span>
                      <span>{new Date(line.at).toLocaleTimeString()}</span>
                      <span>{fmtDuration(line.result.duration_ms)}</span>
                      <Badge variant="outline" className={`h-4 px-1.5 text-[10px] ${badge.className}`}>
                        exit {badge.label}
                      </Badge>
                    </span>
                  </div>
                  <pre
                    className={`whitespace-pre-wrap break-all rounded bg-background/60 p-2 ${
                      line.result.is_error ? "text-red-600 dark:text-red-400" : ""
                    }`}
                  >
                    {line.result.output || "（无输出）"}
                  </pre>
                  {line.result.note && line.result.note !== line.result.output ? (
                    <div className="text-amber-600 dark:text-amber-400">{line.result.note}</div>
                  ) : null}
                </div>
              );
            })}
          </div>
        )}
      </div>

      <div className="flex flex-wrap items-center gap-1">
        {quick.map((cmd) => (
          <Button
            key={cmd}
            variant="outline"
            size="sm"
            className="h-6 px-2 font-mono text-[11px]"
            disabled={busy}
            onClick={() => void submit(cmd)}
          >
            {cmd}
          </Button>
        ))}
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <Input
          ref={inputRef}
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={onKeyDown}
          placeholder="命令，例如 id；cd 会保留在当前会话"
          className="min-w-0 flex-1 font-mono"
          disabled={busy}
        />
        <Select value={String(timeoutSeconds)} onValueChange={(v) => setTimeoutSeconds(Number(v))}>
          <SelectTrigger className="w-24" size="sm">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {TIMEOUT_CHOICES.map((t) => (
              <SelectItem key={t} value={String(t)}>
                {t}s 超时
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Button onClick={() => void submit(input)} disabled={busy || !input.trim()}>
          {busy ? <Loader2Icon className="size-4 animate-spin" /> : <TerminalIcon className="size-4" />}
          执行
        </Button>
      </div>

      <div className="flex flex-wrap items-center gap-3 text-muted-foreground text-xs">
        <div className="flex items-center gap-2">
          <Switch aria-label="自动跟随输出" checked={follow} onCheckedChange={(c) => setFollow(Boolean(c))} />
          <span>自动跟随输出</span>
        </div>
        <Button variant="ghost" size="sm" className="h-6" onClick={copySession} disabled={lines.length === 0}>
          <CopyIcon className="size-3.5" />
          复制会话
        </Button>
        {/* 贴给 Java exec(String) / 内存马命令口之前先问一句：这条命令在那个语境里会被切成什么、
            该写成什么形式。换算在这里做是因为只有平台知道命令通道的解释器族。 */}
        <Button
          variant="ghost"
          size="sm"
          className="h-6"
          disabled={!input.trim()}
          onClick={() => setFormCmd(input.trim())}
        >
          exec() 语境形式
        </Button>
        <Button
          variant="ghost"
          size="sm"
          className="h-6"
          onClick={() => {
            setLines([]);
            setHistIdx(null);
          }}
          disabled={lines.length === 0}
        >
          <Trash2Icon className="size-3.5" />
          清屏
        </Button>
        <span>超时只停止本地等待，目标上的命令可能仍在继续。</span>
      </div>

      {formCmd ? (
        <ExecFormDialog command={formCmd} osKind={osKind} onOpenChange={(open) => !open && setFormCmd("")} />
      ) : null}
    </div>
  );
}
