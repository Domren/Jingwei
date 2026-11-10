"use client";

import * as React from "react";

import { ChevronDownIcon, Loader2Icon, PlayIcon, ShieldOffIcon } from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Textarea } from "@/components/ui/textarea";
import { api } from "@/lib/api";

import { DeepDetailDialog, DeepTaskTable, FieldRow, TaskFormShell, useDeepTasks } from "../_components/deep-ui";

export default function DeepWafBypassPage() {
  const { tasks, total, loading, refresh } = useDeepTasks("waf_bypass");
  const [createOpen, setCreateOpen] = React.useState(false);
  const [submitting, setSubmitting] = React.useState(false);
  const [detailId, setDetailId] = React.useState<number | null>(null);
  const [detailOpen, setDetailOpen] = React.useState(false);

  const [name, setName] = React.useState("");
  const [baseUrl, setBaseUrl] = React.useState("");
  const [path, setPath] = React.useState("/");
  const [param, setParam] = React.useState("id");
  const [payload, setPayload] = React.useState("' union select 1,2,3--");
  const [keywords, setKeywords] = React.useState("");
  const [bypassMode, setBypassMode] = React.useState<"adaptive" | "full">("adaptive");
  const [maxAttempts, setMaxAttempts] = React.useState("8");
  const [maxConsecBlocked, setMaxConsecBlocked] = React.useState("5");
  const [maxConsecErrors, setMaxConsecErrors] = React.useState("3");

  function openCreate() {
    setName("");
    setBaseUrl("");
    setPath("/");
    setParam("id");
    setPayload("' union select 1,2,3--");
    setKeywords("");
    setBypassMode("adaptive");
    setMaxAttempts("8");
    setMaxConsecBlocked("5");
    setMaxConsecErrors("3");
    setCreateOpen(true);
  }

  // 数字输入留空即走服务端默认值；填了就必须是正整数（服务端另有上限收口）。
  function parsePositive(value: string, label: string): number | undefined {
    const trimmed = value.trim();
    if (!trimmed) return undefined;
    const n = Number(trimmed);
    if (!Number.isInteger(n) || n <= 0) {
      throw new Error(`${label}必须是正整数`);
    }
    return n;
  }

  async function submit() {
    const base = baseUrl.trim();
    if (!base) {
      toast.error("请填写目标地址");
      return;
    }
    if (!path.trim()) {
      toast.error("请填写测试路径");
      return;
    }
    let budget: number | undefined;
    let consecBlocked: number | undefined;
    let consecErrors: number | undefined;
    try {
      budget = parsePositive(maxAttempts, "请求预算");
      consecBlocked = parsePositive(maxConsecBlocked, "连续被拦止损");
      consecErrors = parsePositive(maxConsecErrors, "连续错误止损");
    } catch (e) {
      toast.error((e as Error).message);
      return;
    }
    setSubmitting(true);
    try {
      const task = await api.createDeepTask({
        name: name.trim() || undefined,
        kind: "waf_bypass",
        target: base,
        params: {
          base_url: base,
          path: path.trim(),
          param: param.trim(),
          payload,
          keywords: keywords
            .split(/[\s,;]+/)
            .map((k) => k.trim())
            .filter(Boolean),
          bypass_mode: bypassMode,
          ...(budget !== undefined ? { max_attempts: budget } : {}),
          ...(consecBlocked !== undefined ? { max_consecutive_blocked: consecBlocked } : {}),
          ...(consecErrors !== undefined ? { max_consecutive_errors: consecErrors } : {}),
        },
      });
      toast.success(`已创建绕过测试 #${task.id}`);
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
          <ShieldOffIcon className="h-5 w-5 text-muted-foreground" />
          <h1 className="text-xl font-semibold tracking-tight">WAF 绕过</h1>
          <Badge variant="secondary">{total}</Badge>
          {running && (
            <span className="flex items-center gap-1 text-xs text-muted-foreground">
              <Loader2Icon className="size-3 animate-spin" />
              测试中
            </span>
          )}
        </div>
        <Button onClick={openCreate}>
          <PlayIcon className="size-4" />
          新建绕过测试
        </Button>
      </div>

      <p className="text-sm text-muted-foreground">
        先识别目标 WAF，再用多种变形（编码、大小写、路径、请求头等）重放攻击载荷，逐一记录是否被拦截。
      </p>

      {loading && tasks.length === 0 ? (
        <div className="flex items-center justify-center py-16 text-sm text-muted-foreground">
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
          emptyHint="还没有绕过测试，点击右上角「新建绕过测试」开始。"
        />
      )}

      <Sheet open={createOpen} onOpenChange={setCreateOpen}>
        <SheetContent className="flex flex-col gap-4 overflow-y-auto sm:max-w-lg">
          <SheetHeader>
            <SheetTitle>新建 WAF 绕过测试</SheetTitle>
            <SheetDescription>识别 WAF 并测试多种绕过变形</SheetDescription>
          </SheetHeader>

          <TaskFormShell onSubmit={submit} submitting={submitting} submitLabel="开始测试">
            <FieldRow label="目标地址">
              <Input value={baseUrl} onChange={(e) => setBaseUrl(e.target.value)} placeholder="http://example.com" />
            </FieldRow>
            <FieldRow label="测试路径">
              <Input value={path} onChange={(e) => setPath(e.target.value)} placeholder="/api/query" />
            </FieldRow>
            <FieldRow label="参数名">
              <Input value={param} onChange={(e) => setParam(e.target.value)} placeholder="id" />
            </FieldRow>
            <FieldRow label="攻击载荷">
              <Textarea
                value={payload}
                onChange={(e) => setPayload(e.target.value)}
                rows={4}
                className="font-mono text-xs"
              />
            </FieldRow>
            <FieldRow label="成功关键词" hint="响应中出现任意关键词即视为绕过成功；留空则按状态码与长度差异判断">
              <Input
                value={keywords}
                onChange={(e) => setKeywords(e.target.value)}
                placeholder="多个关键词用空格分隔"
              />
            </FieldRow>
            <Collapsible>
              <CollapsibleTrigger className="group flex w-full items-center justify-between rounded-md border border-dashed px-3 py-2 text-sm text-muted-foreground hover:text-foreground">
                高级选项（模式 / 预算 / 止损阈值）
                <ChevronDownIcon className="size-4 transition-transform group-data-[state=open]:rotate-180" />
              </CollapsibleTrigger>
              <CollapsibleContent className="flex flex-col gap-4 pt-4">
                <FieldRow
                  label="重试模式"
                  hint="自适应：被拦后按拦截特征重排变形，连续被拦即止损；全量：按序尝试全部变形直到预算耗尽，每种形态都留记录"
                >
                  <Select value={bypassMode} onValueChange={(v) => setBypassMode(v as "adaptive" | "full")}>
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="adaptive">自适应（默认）</SelectItem>
                      <SelectItem value="full">全量</SelectItem>
                    </SelectContent>
                  </Select>
                </FieldRow>
                <FieldRow label="请求预算" hint="含基线在内的最大请求数，默认 8，硬上限 64；留空用默认值">
                  <Input
                    value={maxAttempts}
                    onChange={(e) => setMaxAttempts(e.target.value)}
                    inputMode="numeric"
                    placeholder="8"
                  />
                </FieldRow>
                <FieldRow
                  label="连续被拦止损"
                  hint="自适应模式下连续这么多次被拦即停止，默认 5；全量模式不生效；留空用默认值"
                >
                  <Input
                    value={maxConsecBlocked}
                    onChange={(e) => setMaxConsecBlocked(e.target.value)}
                    inputMode="numeric"
                    placeholder="5"
                    disabled={bypassMode === "full"}
                  />
                </FieldRow>
                <FieldRow label="连续错误止损" hint="连续这么多次传输错误即停止，默认 3；留空用默认值">
                  <Input
                    value={maxConsecErrors}
                    onChange={(e) => setMaxConsecErrors(e.target.value)}
                    inputMode="numeric"
                    placeholder="3"
                  />
                </FieldRow>
              </CollapsibleContent>
            </Collapsible>
            <FieldRow label="任务名称">
              <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="留空自动生成" />
            </FieldRow>
          </TaskFormShell>
        </SheetContent>
      </Sheet>

      <DeepDetailDialog taskId={detailId} open={detailOpen} onOpenChange={setDetailOpen} onChanged={refresh} />
    </div>
  );
}
