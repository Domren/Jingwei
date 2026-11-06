"use client";

import * as React from "react";

import { CopyIcon, Loader2Icon } from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { api } from "@/lib/api";
import type { ShellExecForm } from "@/lib/types";

/**
 * 一条命令在 shell / argv / 单串三种执行语境下各自该有的形式（E4）。
 *
 * 存在的原因：`Runtime.exec(String)` 那类执行口没有 shell——Java 按空白把整串切成 argv，
 * 于是 `cat /etc/passwd | grep root` 变成「给 cat 传四个参数」，管道成了一个文件名。进程
 * 起来了、退出码也可能是 0，输出却是错的，而人会把「执行成功」记进报告。这里把该长成的
 * 样子算出来，并且**在表达不了的时候明说表达不了**，不给一个语义已经变了的近似形式。
 */
export function ExecFormDialog({
  command,
  osKind,
  onOpenChange,
}: {
  command: string;
  osKind: string;
  onOpenChange: (open: boolean) => void;
}) {
  const [form, setForm] = React.useState<ShellExecForm | null>(null);
  const [error, setError] = React.useState("");
  const [loading, setLoading] = React.useState(true);

  React.useEffect(() => {
    let alive = true;
    setLoading(true);
    setError("");
    api
      .execForm(command, osKind)
      .then((f) => {
        if (alive) setForm(f);
      })
      .catch((e: Error) => {
        if (alive) setError(e.message || "换算失败");
      })
      .finally(() => {
        if (alive) setLoading(false);
      });
    return () => {
      alive = false;
    };
  }, [command, osKind]);

  function copy(text: string, label: string) {
    navigator.clipboard
      .writeText(text)
      .then(() => toast.success(`${label}已复制`))
      .catch(() => toast.error("复制失败"));
  }

  return (
    <Dialog open onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-3xl">
        <DialogHeader>
          <DialogTitle>exec() 语境的命令形式</DialogTitle>
          <DialogDescription className="break-all font-mono text-xs">
            原命令：{command}（换算只做静态分析，不发任何请求、不接触目标）
          </DialogDescription>
        </DialogHeader>

        {loading ? (
          <div className="flex items-center gap-2 text-muted-foreground text-xs">
            <Loader2Icon className="size-4 animate-spin" />
            正在按 shell 语法解析…
          </div>
        ) : null}
        {error ? <div className="text-red-600 text-xs dark:text-red-400">{error}</div> : null}

        {form ? (
          <div className="flex flex-col gap-4 text-xs">
            {!form.command ? (
              // 演示模式对没有编目的接口回一个空对象。这里不猜数据：与其渲染四个空栏位让人
              // 以为「换算出来就是空的」，不如直说这条路在演示模式里不通。真实形式由后端算。
              <p className="text-muted-foreground">
                演示模式没有接上命令换算接口，因此下面这些形式是不可用的（不是「算出来为空」）。
                换算发生在真实实例的
                <span className="font-mono"> POST /api/deep/exec-form </span>上。
              </p>
            ) : null}
            <section className="flex flex-col gap-1.5">
              <div className="flex flex-wrap items-center gap-2">
                <span className="text-muted-foreground">这条命令</span>
                {form.needs_shell ? (
                  <Badge className="bg-amber-500/15 text-amber-700 dark:text-amber-400">需要 shell 才解释得了</Badge>
                ) : (
                  <Badge className="bg-emerald-500/15 text-emerald-700 dark:text-emerald-400">
                    不需要 shell：参数可以直接是 argv
                  </Badge>
                )}
                {(form.constructs ?? []).map((c) => (
                  <Badge key={c} variant="outline" className="font-mono">
                    {c}
                  </Badge>
                ))}
              </div>
              <p className="text-muted-foreground">
                带空格的参数不算「需要 shell」——引号只是分组，任何 exec 都能表达；管道、重定向、变量展开、
                通配才算，它们只能由解释器完成。
              </p>
            </section>

            <Field label="原样贴进 exec(String) 会被切成" hint="Java 的分词只看空白，不看引号">
              <div className="flex flex-wrap gap-1">
                {(form.typed_tokens ?? []).map((t, i) => (
                  <span key={`${t}-${i}`} className="rounded bg-muted px-1.5 py-0.5 font-mono">
                    {t}
                  </span>
                ))}
              </div>
            </Field>

            <Field
              label="argv 语境（ProcessBuilder(列表) / proc_open(数组)）"
              hint="每一行一个参数，按顺序传进去"
              onCopy={() => copy((form.argv ?? []).join("\n"), "argv ")}
            >
              <pre className="whitespace-pre-wrap break-all rounded bg-background/60 p-2">
                {(form.argv ?? []).map((a) => JSON.stringify(a)).join(",\n")}
              </pre>
            </Field>

            <section className="flex flex-col gap-1.5">
              <div className="flex flex-wrap items-center gap-2">
                <span className="text-muted-foreground">单串语境（只能贴一整串、且会被按空白切碎）</span>
                {form.needs_bash ? (
                  <Badge className="bg-amber-500/15 text-amber-700 dark:text-amber-400">要求目标上有 bash</Badge>
                ) : null}
              </div>
              {form.single ? (
                <div className="flex flex-col gap-1">
                  <pre className="whitespace-pre-wrap break-all rounded bg-background/60 p-2 font-mono">
                    {form.single}
                  </pre>
                  <Button variant="ghost" size="sm" className="h-6 self-start" onClick={() => copy(form.single, "单串形式")}>
                    <CopyIcon className="size-3.5" />
                    复制单串形式
                  </Button>
                </div>
              ) : (
                <div className="rounded bg-muted/50 p-2 text-muted-foreground">{form.reason || "这条命令无法编码成单串形式"}</div>
              )}
              {form.needs_bash ? (
                <p className="text-muted-foreground">
                  POSIX sh（dash 等）没有 `$'\x20'` 这种「不带空白字节的空格」写法，会把它当字面量输出一串
                  <span className="font-mono"> $\x20 </span>却仍然返回 0。目标上没有 bash 时，请用上面的 argv 形式。
                </p>
              ) : null}
            </section>
          </div>
        ) : null}
      </DialogContent>
    </Dialog>
  );
}

function Field({
  label,
  hint,
  onCopy,
  children,
}: {
  label: string;
  hint?: string;
  onCopy?: () => void;
  children: React.ReactNode;
}) {
  return (
    <section className="flex flex-col gap-1.5">
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-muted-foreground">{label}</span>
        {hint ? <span className="text-muted-foreground/70">{hint}</span> : null}
        {onCopy ? (
          <Button variant="ghost" size="sm" className="h-6" onClick={onCopy}>
            <CopyIcon className="size-3.5" />
            复制
          </Button>
        ) : null}
      </div>
      {children}
    </section>
  );
}
