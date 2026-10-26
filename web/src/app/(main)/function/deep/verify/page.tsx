"use client";

import * as React from "react";

import { Loader2Icon, PlayIcon, ShieldCheckIcon } from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Switch } from "@/components/ui/switch";
import { api } from "@/lib/api";

import {
  DeepDetailDialog,
  DeepTaskTable,
  FieldRow,
  JavaChainsHint,
  PocPicker,
  TaskFormShell,
  useDeepTasks,
} from "../_components/deep-ui";

export default function DeepVerifyPage() {
  const { tasks, total, loading, refresh } = useDeepTasks("verify");
  const [createOpen, setCreateOpen] = React.useState(false);
  const [submitting, setSubmitting] = React.useState(false);
  const [detailId, setDetailId] = React.useState<number | null>(null);
  const [detailOpen, setDetailOpen] = React.useState(false);

  const [name, setName] = React.useState("");
  const [target, setTarget] = React.useState("");
  const [repeats, setRepeats] = React.useState("1");
  const [writeFinding, setWriteFinding] = React.useState(false);
  const [selectedPocs, setSelectedPocs] = React.useState<Set<number>>(new Set());
  const [autoJavaChains, setAutoJavaChains] = React.useState(true);
  const [javaCmd, setJavaCmd] = React.useState("id");

  function openCreate() {
    setName("");
    setTarget("");
    setRepeats("1");
    setWriteFinding(false);
    setSelectedPocs(new Set());
    setAutoJavaChains(true);
    setJavaCmd("id");
    setCreateOpen(true);
  }

  async function submit() {
    const t = target.trim();
    if (!t) {
      toast.error("请填写目标地址");
      return;
    }
    setSubmitting(true);
    try {
      const task = await api.createDeepTask({
        name: name.trim() || undefined,
        kind: "verify",
        target: t,
        params: {
          template_ids: Array.from(selectedPocs),
          repeats: Math.min(5, Math.max(1, Number(repeats) || 1)),
          write_finding: writeFinding,
          java_chains: autoJavaChains ? "auto" : "off",
          java_cmd: autoJavaChains ? javaCmd.trim() || "id" : "",
        },
      });
      toast.success(`已创建验证任务 #${task.id}`);
      setCreateOpen(false);
      refresh();
    } catch (e) {
      toast.error((e as Error).message);
    } finally {
      setSubmitting(false);
    }
  }

  const running = tasks.some((t) => t.status === "running" || t.status === "queued");

  return (
    <div className="flex min-h-0 flex-1 flex-col gap-4">
      <div className="flex items-center justify-between gap-4">
        <div className="flex items-center gap-2">
          <ShieldCheckIcon className="h-5 w-5 text-muted-foreground" />
          <h1 className="font-semibold text-xl tracking-tight">漏洞验证</h1>
          <Badge variant="secondary">{total}</Badge>
          {running && (
            <span className="flex items-center gap-1 text-muted-foreground text-xs">
              <Loader2Icon className="size-3 animate-spin" />
              验证中
            </span>
          )}
        </div>
        <Button onClick={openCreate}>
          <PlayIcon className="size-4" />
          新建验证
        </Button>
      </div>

      <div className="flex flex-col gap-1">
        <p className="text-muted-foreground text-sm">
          对目标重放 POC 模板并多次复现，记录每个漏洞是否可复现以及完整请求 / 响应证据。未指定 POC
          时按目标指纹自动匹配。
        </p>
        <JavaChainsHint />
      </div>

      {loading && tasks.length === 0 ? (
        <div className="flex items-center justify-center py-16 text-muted-foreground text-sm">
          <Loader2Icon className="mr-2 size-4 animate-spin" />
          加载中…
        </div>
      ) : (
        <DeepTaskTable
          tasks={tasks}
          onOpen={(id) => {
            setDetailId(id);
            setDetailOpen(true);
          }}
          onChanged={refresh}
          emptyHint="还没有验证任务，点击右上角「新建验证」开始。"
        />
      )}

      <Sheet open={createOpen} onOpenChange={setCreateOpen}>
        <SheetContent className="flex flex-col gap-4 overflow-y-auto sm:max-w-lg">
          <SheetHeader>
            <SheetTitle>新建漏洞验证</SheetTitle>
            <SheetDescription>重放 POC 并复现漏洞，保存证据</SheetDescription>
          </SheetHeader>

          <TaskFormShell onSubmit={submit} submitting={submitting} submitLabel="开始验证">
            <FieldRow label="目标地址">
              <Input
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                placeholder="http://example.com:8080/path"
              />
            </FieldRow>
            <FieldRow label="任务名称">
              <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="留空自动生成" />
            </FieldRow>
            <FieldRow label="复现次数" hint="同一目标重复执行，用于排除偶发命中，最多 5 次">
              <Input type="number" min={1} max={5} value={repeats} onChange={(e) => setRepeats(e.target.value)} />
            </FieldRow>
            <FieldRow label="POC 模板" hint="不选则根据目标指纹自动匹配（最多 50 个）">
              <PocPicker selected={selectedPocs} onChange={setSelectedPocs} />
            </FieldRow>
            <div className="flex items-center justify-between rounded-md border px-3 py-2">
              <Label htmlFor="verify-finding">同时写入发现列表</Label>
              <Switch id="verify-finding" checked={writeFinding} onCheckedChange={setWriteFinding} />
            </div>
            <div className="flex flex-col gap-2 rounded-md border px-3 py-2">
              <div className="flex items-center justify-between">
                <Label htmlFor="verify-java-chains">自动调用 java-chains</Label>
                <Switch id="verify-java-chains" checked={autoJavaChains} onCheckedChange={setAutoJavaChains} />
              </div>
              <p className="text-muted-foreground text-xs">
                检测到 fastjson / Shiro 等 Java 反序列化 POC 时自动选链、发布 JNDI 并投递，回调确认后自动清理。
              </p>
              <Input
                value={javaCmd}
                onChange={(e) => setJavaCmd(e.target.value)}
                disabled={!autoJavaChains}
                aria-label="java-chains 执行命令"
                placeholder="id"
              />
            </div>
          </TaskFormShell>
        </SheetContent>
      </Sheet>

      <DeepDetailDialog taskId={detailId} open={detailOpen} onOpenChange={setDetailOpen} onChanged={refresh} />
    </div>
  );
}
