"use client";

import * as React from "react";

import { InfoIcon, Loader2Icon, RefreshCwIcon, TerminalIcon } from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { api } from "@/lib/api";
import type { ShellInfoResult, ShellRuntimeInfo, Webshell } from "@/lib/types";

import { shellStatusMeta } from "../_components/deep-ui";
import { ShellTerminal } from "../_components/shell-terminal";
import { WebshellFilesPanel } from "./webshell-files-panel";

const RUNTIME_ROWS: { label: string; value: (r: ShellRuntimeInfo) => string }[] = [
  { label: "系统", value: (r) => r.os },
  { label: "SAPI", value: (r) => r.sapi },
  { label: "PHP 版本", value: (r) => r.php },
  { label: "运行用户", value: (r) => r.user },
  { label: "服务器", value: (r) => r.server },
  { label: "脚本", value: (r) => r.script },
  { label: "所在目录", value: (r) => r.dir },
  { label: "网站根目录", value: (r) => r.document_root },
  { label: "临时目录", value: (r) => r.tmp },
  { label: "open_basedir", value: (r) => r.open_basedir || "未限制" },
  { label: "disable_functions", value: (r) => r.disable_functions || "未限制" },
  { label: "auto_prepend_file", value: (r) => r.auto_prepend_file || "未设置" },
  { label: ".user.ini", value: (r) => r.user_ini_filename || "不支持" },
  { label: ".user.ini 缓存", value: (r) => `${r.user_ini_cache_ttl} 秒` },
];

function RuntimeRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex min-w-0 items-start gap-2 border-b py-1 last:border-b-0">
      <span className="w-36 shrink-0 text-muted-foreground">{label}</span>
      <span className="min-w-0 flex-1 break-all">{value || "—"}</span>
    </div>
  );
}

function ShellInfoPanel({ shell, cwd }: { shell: Webshell; cwd: string }) {
  const [data, setData] = React.useState<ShellInfoResult | null>(null);
  const [loading, setLoading] = React.useState(false);

  // The probe follows the terminal's directory, but a cd must not re-fire a
  // dozen remote commands, so the value is read through a ref instead of being
  // an effect dependency.
  const cwdRef = React.useRef(cwd);
  React.useEffect(() => {
    cwdRef.current = cwd;
  }, [cwd]);

  const load = React.useCallback(async () => {
    setLoading(true);
    try {
      setData(await api.webshellInfo(shell.id, cwdRef.current));
    } catch (e) {
      toast.error((e as Error).message);
    } finally {
      setLoading(false);
    }
  }, [shell.id]);

  // Radix unmounts an inactive tab, so this fires when the operator opens 信息:
  // one encrypted round trip that runs a dozen commands on the target.
  React.useEffect(() => {
    void load();
  }, [load]);

  const runtime = data?.runtime ?? null;

  return (
    <div className="flex min-w-0 flex-col gap-2">
      <div className="flex flex-wrap items-center gap-2 text-xs">
        <Button variant="outline" size="sm" disabled={loading} onClick={() => void load()}>
          {loading ? <Loader2Icon className="size-3.5 animate-spin" /> : <RefreshCwIcon className="size-3.5" />}
          {data ? "重新收集" : "开始收集"}
        </Button>
        {data ? (
          <span className="text-muted-foreground">
            一次往返采集 {data.sections.length} 项，用时 {data.duration_ms} ms
            {data.os_kind === "windows" ? " · Windows cmd" : " · POSIX sh"}
          </span>
        ) : null}
        {data?.note ? <span className="text-amber-600 dark:text-amber-400">{data.note}</span> : null}
      </div>

      <ScrollArea className="h-[56vh] rounded-md border">
        <div className="flex flex-col gap-2 p-3">
          {runtime ? (
            <div className="flex flex-col gap-1">
              <div className="flex items-center gap-2 font-medium text-xs">
                <InfoIcon className="size-3.5" />
                PHP 运行时自检（v2 I 操作）
              </div>
              <div className="rounded-md border bg-muted/30 p-2 font-mono text-xs">
                {RUNTIME_ROWS.map((row) => (
                  <RuntimeRow key={row.label} label={row.label} value={row.value(runtime)} />
                ))}
              </div>
            </div>
          ) : null}
          {data?.runtime_note ? (
            <div className="rounded-md border border-amber-500/30 bg-amber-500/5 p-2 text-amber-700 text-xs dark:text-amber-400">
              {data.runtime_note}
            </div>
          ) : null}
          {(data?.sections ?? []).map((section) => (
            <div key={section.label} className="flex min-w-0 flex-col gap-1">
              <span className="font-medium text-xs">{section.label}</span>
              <pre className="whitespace-pre-wrap break-all rounded-md bg-muted/40 p-2 font-mono text-xs">
                {section.output || "（无输出）"}
              </pre>
            </div>
          ))}
          {!loading && !data ? <div className="p-6 text-center text-muted-foreground text-sm">尚未收集</div> : null}
          {loading && !data ? (
            <div className="flex items-center justify-center py-16 text-muted-foreground text-sm">
              <Loader2Icon className="mr-2 size-4 animate-spin" />
              正在目标上执行信息收集…
            </div>
          ) : null}
        </div>
      </ScrollArea>
    </div>
  );
}

export function WebshellWorkbench({
  shell,
  initialTab = "term",
  onOpenChange,
}: {
  shell: Webshell | null;
  initialTab?: "term" | "files" | "info";
  onOpenChange: (open: boolean) => void;
}) {
  const [tab, setTab] = React.useState<string>(initialTab);
  const [cwd, setCwd] = React.useState("");

  // The caller keys this dialog by shell id, so the terminal's scrollback and
  // directory die with the shell it belongs to; this only follows the button the
  // operator clicked (终端 / 文件 / 信息) on the same shell.
  React.useEffect(() => {
    setTab(initialTab);
  }, [initialTab]);

  if (!shell) return null;
  const badge = shellStatusMeta(shell.status);
  return (
    <Dialog open onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-6xl">
        <DialogHeader>
          <DialogTitle className="flex flex-wrap items-center gap-2">
            <TerminalIcon className="size-4" />
            {shell.name || shell.url}
            <Badge variant="outline" className={badge.className} title={badge.hint}>
              {badge.label}
            </Badge>
            <Badge variant="outline">{(shell.shell_type || "?").toUpperCase()}</Badge>
            {/* The wire protocol and the sealed key's rotation counter are different
                numbers; 「加密 v1」 here read as legacy protocol, which is exactly
                the thing that decides whether 文件管理 is offered. */}
            <Badge variant="outline" title={`密钥 v${shell.key_version || 1}`}>
              {shell.protocol === "v2" ? "加密 v2" : "明文"}
            </Badge>
          </DialogTitle>
          <DialogDescription className="flex flex-wrap items-center gap-2 font-mono text-xs">
            <span className="break-all">{shell.url}</span>
            {shell.target ? <span className="rounded bg-muted px-1.5 py-0.5">目标 {shell.target}</span> : null}
          </DialogDescription>
        </DialogHeader>
        <Tabs value={tab} onValueChange={setTab}>
          <TabsList className="w-fit">
            <TabsTrigger value="term">虚拟终端</TabsTrigger>
            <TabsTrigger value="files" disabled={shell.protocol !== "v2"}>
              文件管理
            </TabsTrigger>
            <TabsTrigger value="info">系统信息</TabsTrigger>
          </TabsList>
          {/* A disabled tab tells you something is unavailable and nothing about
              why, and a greyed-out 文件管理 reads as a broken feature. */}
          {shell.protocol !== "v2" ? (
            <p className="text-muted-foreground text-xs">
              文件管理（大马）走加密 v2 的文件操作字节；这条记录是
              {shell.protocol === "legacy" ? "旧版明文载荷" : "未登记协议的载荷"}，用最新载荷重新投放后才可用。
            </p>
          ) : null}
          {/* Only the terminal is forceMount: peeking at the file manager must not
              wipe the scrollback, while the other tabs stay lazy so opening the
              workbench never fires a probe on its own. */}
          <TabsContent value="term" forceMount className={tab === "term" ? "" : "hidden"}>
            <ShellTerminal
              historyKey={`webshell-${shell.id}`}
              osKind={shell.os_kind}
              initialCwd={cwd}
              heightClass="h-[56vh]"
              run={({ command, cwd: at, osKind: family, timeoutSeconds }) =>
                api.execWebshell(shell.id, { command, cwd: at, os_kind: family, timeout_seconds: timeoutSeconds })
              }
              onCwdChange={setCwd}
            />
          </TabsContent>
          <TabsContent value="files">
            <WebshellFilesPanel shell={shell} listHeight="h-[56vh]" />
          </TabsContent>
          <TabsContent value="info">
            <ShellInfoPanel shell={shell} cwd={cwd} />
          </TabsContent>
        </Tabs>
      </DialogContent>
    </Dialog>
  );
}
