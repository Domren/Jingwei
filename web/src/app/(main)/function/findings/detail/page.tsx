"use client";

import * as React from "react";

import Link from "next/link";
import { useSearchParams } from "next/navigation";

import { ArrowLeftIcon, ArrowUpRightIcon, CameraIcon, GlobeIcon, Loader2Icon, ShieldAlertIcon } from "lucide-react";
import { toast } from "sonner";

import { CopyButton } from "@/components/copy-button";
import { FindingRetestPanel } from "@/components/finding-retest-panel";
import { FindingTrafficPanel } from "@/components/finding-traffic-panel";
import { Markdown } from "@/components/markdown";
import { StatusBadge } from "@/components/status-badge";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectGroup, SelectItem, SelectTrigger } from "@/components/ui/select";
import { Separator } from "@/components/ui/separator";
import { SidebarTrigger } from "@/components/ui/sidebar";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { api } from "@/lib/api";
import { FindingAgentChatDrawer } from "@/components/finding-agent-chat-drawer";
import { statusMeta } from "@/lib/status";
import type { Finding, FindingReviewEvent, FindingScreenshot, FindingStatus, Severity } from "@/lib/types";

import { FindingLineageView } from "./lineage";

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low"];
const FINDING_STATUSES: FindingStatus[] = [
  "pending",
  "in_progress",
  "confirmed",
  "resolved",
  "fixed",
  "false_positive",
  "ignored",
  "duplicate",
  "risk_accepted",
];

function fmtTime(ts: string) {
  return new Date(ts).toLocaleString("zh-CN");
}

// REVIEW_ACTION_LABELS 把复核事件动作映射成中文标签。
const REVIEW_ACTION_LABELS: Record<string, string> = {
  status: "处理状态",
  severity: "严重等级",
  cvss: "CVSS 评分",
  name: "漏洞名称",
  vulnclass: "漏洞类型",
};

// fileToBase64 读取文件为纯 base64(去掉 data: 前缀)。
function fileToBase64(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const r = new FileReader();
    r.onload = () => resolve(String(r.result).split(",")[1] ?? "");
    r.onerror = () => reject(r.error);
    r.readAsDataURL(file);
  });
}

// FieldRow is one label/value line in the right-hand status panel.
function FieldRow({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex items-start justify-between gap-3 py-2.5">
      <span className="shrink-0 pt-0.5 text-xs text-muted-foreground">{label}</span>
      <div className="flex min-w-0 flex-col items-end gap-1 text-right text-sm">{children}</div>
    </div>
  );
}

// HTTPMessageBlock renders one raw HTTP message (request or response) as a
// copyable code block. Empty payloads are omitted by the caller.
function HTTPMessageBlock({ title, text }: { title: string; text?: string }) {
  if (!text) return null;
  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between gap-2">
        <span className="text-xs font-medium text-muted-foreground">{title}</span>
        <CopyButton text={text} successMessage={`已复制${title}`} />
      </div>
      <pre className="max-h-[42vh] overflow-auto rounded-md bg-muted px-3 py-2 font-mono text-xs whitespace-pre-wrap">
        {text}
      </pre>
    </div>
  );
}

// withoutCurlCommands hides the scanner's curl one-liner when the raw packets
// are already shown above it; a curl string cannot be replayed byte-for-byte.
function withoutCurlCommands(text: string) {
  return text
    .split(/\r?\n/)
    .filter((line) => !/^\s*(curl|复现命令)/.test(line))
    .join("\n")
    .replace(/\n{3,}/g, "\n\n")
    .trim();
}

function FindingDetailInner() {
  const searchParams = useSearchParams();
  const id = searchParams.get("id") ?? "";
  const contextTaskId = searchParams.get("context_task") ?? "";
  const [finding, setFinding] = React.useState<Finding | null>(null);
  const [loaded, setLoaded] = React.useState(false);
  const [tab, setTab] = React.useState("overview");
  const [events, setEvents] = React.useState<FindingReviewEvent[]>([]);
  const [screenshots, setScreenshots] = React.useState<FindingScreenshot[]>([]);
  const [shotCaption, setShotCaption] = React.useState("");
  const [autoShotting, setAutoShotting] = React.useState(false);
  const [pageShotting, setPageShotting] = React.useState(false);
  const [cvssDraft, setCvssDraft] = React.useState("");

  const load = React.useCallback(() => {
    if (!id) {
      setLoaded(true);
      return;
    }
    api
      .getFinding(id, contextTaskId || undefined)
      .then((f) => setFinding(f))
      .catch(() => setFinding(null))
      .finally(() => setLoaded(true));
    api.findingEvents(id).then(setEvents).catch(() => setEvents([]));
    api.findingScreenshots(id, true).then(setScreenshots).catch(() => setScreenshots([]));
  }, [contextTaskId, id]);
  React.useEffect(() => {
    load();
  }, [load]);

  const changeSeverity = React.useCallback(
    async (next: Severity) => {
      if (!finding || finding.inherited || next === finding.severity) return;
      const prev = finding.severity;
      setFinding({ ...finding, severity: next });
      try {
        const updated = await api.setFindingSeverity(id, next);
        setFinding(updated);
        toast.success(`严重等级已改为「${statusMeta("severity", next).label}」`);
      } catch (e) {
        setFinding((cur) => (cur ? { ...cur, severity: prev } : cur));
        toast.error("更新失败：" + (e as Error).message);
      }
    },
    [finding, id],
  );

  const changeStatus = React.useCallback(
    async (next: FindingStatus) => {
      if (!finding || finding.inherited || next === finding.status) return;
      const prev = finding.status;
      setFinding({ ...finding, status: next });
      try {
        const updated = await api.setFindingStatus(id, next);
        setFinding(updated);
        toast.success(`处理状态已改为「${statusMeta("finding", next).label}」`);
      } catch (e) {
        setFinding((cur) => (cur ? { ...cur, status: prev } : cur));
        toast.error("更新失败：" + (e as Error).message);
      }
    },
    [finding, id],
  );

  // CVSS 草稿随 finding 同步；失焦/回车时提交。
  React.useEffect(() => {
    setCvssDraft(finding?.cvss != null ? String(finding.cvss) : "");
  }, [finding?.cvss]);

  const commitCVSS = React.useCallback(async () => {
    if (!finding || finding.inherited) return;
    const num = parseFloat(cvssDraft);
    if (Number.isNaN(num) || num < 0 || num > 10) {
      setCvssDraft(finding.cvss != null ? String(finding.cvss) : "");
      if (cvssDraft !== "") toast.error("CVSS 需在 0.0-10.0 之间");
      return;
    }
    if (num === finding.cvss) return;
    try {
      const updated = await api.setFindingCvss(id, num);
      setFinding(updated);
      setEvents(await api.findingEvents(id));
      toast.success(`CVSS 已设为 ${num.toFixed(1)}`);
    } catch (e) {
      setCvssDraft(finding.cvss != null ? String(finding.cvss) : "");
      toast.error("更新失败：" + (e as Error).message);
    }
  }, [finding, cvssDraft, id]);

  const onPickShot = React.useCallback(
    async (file: File) => {
      if (!id || finding?.inherited) return;
      try {
        const b64 = await fileToBase64(file);
        await api.addFindingScreenshot(id, shotCaption.trim() || file.name, b64);
        setShotCaption("");
        setScreenshots(await api.findingScreenshots(id, true));
        toast.success("取证截图已上传");
      } catch (e) {
        toast.error("上传失败：" + (e as Error).message);
      }
    },
    [id, shotCaption, finding?.inherited],
  );

  // 自动取证:用已绑定的真实报文渲染取证面板(时钟 + 命中高亮),不用手工截屏。
  const onAutoShot = React.useCallback(async () => {
    if (!id || finding?.inherited) return;
    setAutoShotting(true);
    try {
      await api.autoFindingScreenshot(id);
      setScreenshots(await api.findingScreenshots(id, true));
      toast.success("已生成自动取证截图");
    } catch (e) {
      toast.error("自动取证失败：" + (e as Error).message);
    } finally {
      setAutoShotting(false);
    }
  }, [id, finding?.inherited]);

  // 页面取证:无头浏览器打开目标页面截真图,补"用户看到什么"这一半证据。
  const onPageShot = React.useCallback(async () => {
    if (!id || finding?.inherited) return;
    setPageShotting(true);
    try {
      await api.pageFindingScreenshot(id);
      setScreenshots(await api.findingScreenshots(id, true));
      toast.success("已生成页面取证截图");
    } catch (e) {
      toast.error("页面取证失败：" + (e as Error).message);
    } finally {
      setPageShotting(false);
    }
  }, [id, finding?.inherited]);

  if (!finding) {
    return (
      <div className="flex flex-1 flex-col items-center justify-center gap-3 p-10 text-center">
        <p className="text-muted-foreground">{loaded ? `未找到发现 ${id}` : "加载中…"}</p>
        {loaded && (
          <Button asChild variant="outline">
            <Link href="/function/findings">
              <ArrowLeftIcon /> 返回发现列表
            </Link>
          </Button>
        )}
      </div>
    );
  }

  const title = finding.name || finding.vulnclass || "未分类";

  return (
    <Tabs value={tab} onValueChange={setTab} className="flex flex-1 flex-col gap-0">
      {/* Sticky header */}
      <header className="sticky top-0 z-10 flex flex-col gap-2 border-b bg-background/95 px-4 py-2.5 backdrop-blur lg:px-6">
        <div className="flex flex-wrap items-center gap-2">
          <SidebarTrigger className="-ml-1" />
          <Button asChild variant="ghost" size="icon" className="size-7">
            <Link href="/function/findings">
              <ArrowLeftIcon />
            </Link>
          </Button>
          <ShieldAlertIcon className="size-4 text-muted-foreground" />
          {finding.case_id ? (
            <Button asChild variant="outline" size="sm">
              <Link
                href={`/function/findings/case?id=${finding.case_id}${contextTaskId ? `&context_task=${contextTaskId}` : ""}`}
              >
                所属漏洞文件夹
              </Link>
            </Button>
          ) : null}
          <h1 className="max-w-md truncate text-sm font-semibold" title={title}>
            {title}
          </h1>
          <code className="rounded bg-muted px-1.5 py-0.5 font-mono text-xs text-muted-foreground">#{finding.id}</code>
          <Separator orientation="vertical" className="mx-1 h-4" />
          <StatusBadge domain="severity" value={finding.severity} dot />
          <StatusBadge domain="finding" value={finding.status} dot />
          {finding.inherited && finding.source_task_id && (
            <Badge variant="outline">来源任务 #{finding.source_task_id} · 只读</Badge>
          )}
          <FindingAgentChatDrawer finding={finding} />
        </div>
        <TabsList>
          <TabsTrigger value="overview">概览</TabsTrigger>
          <TabsTrigger value="screenshots">取证截图</TabsTrigger>
          <TabsTrigger value="review">复核时间线</TabsTrigger>
          <TabsTrigger value="lineage">链路图</TabsTrigger>
        </TabsList>
      </header>

      {/* Tab content */}
      <div className="flex-1 p-4 lg:p-6">
        {/* 概览：左（摘要 + 证据）/ 右（状态区） */}
        <TabsContent value="overview" className="mt-0">
          <div className="grid gap-4 lg:grid-cols-3">
            {/* 左栏 */}
            <div className="flex flex-col gap-4 lg:col-span-2">
              <Card>
                <CardHeader>
                  <CardTitle className="text-sm">摘要</CardTitle>
                </CardHeader>
                <CardContent>
                  <p className="text-sm leading-relaxed whitespace-pre-wrap">{finding.summary || "（无摘要）"}</p>
                </CardContent>
              </Card>
              {/* 结构化复现过程：agent 记录漏洞时就地写下的真实步骤，每步带自己的报文 */}
              {finding.reproduction?.steps?.length ? (
                <Card>
                  <CardHeader>
                    <CardTitle className="text-sm">复现过程</CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-3">
                    <div className="space-y-2 text-sm">
                      {finding.reproduction.entry_point ? (
                        <p>
                          <span className="text-xs font-medium text-muted-foreground">入口点：</span>
                          {finding.reproduction.entry_point}
                        </p>
                      ) : null}
                      {finding.reproduction.prerequisites?.length ? (
                        <div>
                          <span className="text-xs font-medium text-muted-foreground">前置条件：</span>
                          <ul className="mt-1 list-disc pl-5">
                            {finding.reproduction.prerequisites.map((p) => (
                              <li key={p}>{p}</li>
                            ))}
                          </ul>
                        </div>
                      ) : null}
                      {finding.reproduction.provenance ? (
                        <p>
                          <span className="text-xs font-medium text-muted-foreground">攻击链来源：</span>
                          {finding.reproduction.provenance}
                        </p>
                      ) : null}
                    </div>
                    {finding.reproduction.steps.map((step, i) => (
                      <div
                        // biome-ignore lint/suspicious/noArrayIndexKey: 步骤按位置展示，无稳定 id
                        key={`${i}:${step.request.slice(0, 24)}`}
                        className="space-y-2 rounded-md border border-l-2 border-l-primary px-3 py-2"
                      >
                        <div className="flex flex-wrap items-center gap-2">
                          <span className="rounded bg-primary px-2 py-0.5 text-xs font-medium text-primary-foreground">
                            步骤 {i + 1}
                          </span>
                          {step.expected ? (
                            <span className="text-xs text-muted-foreground">预期：{step.expected}</span>
                          ) : null}
                          {step.proves ? (
                            <span className="text-xs text-muted-foreground">证明：{step.proves}</span>
                          ) : null}
                        </div>
                        <HTTPMessageBlock title="请求" text={step.request} />
                        <HTTPMessageBlock title="响应" text={step.response} />
                      </div>
                    ))}
                  </CardContent>
                </Card>
              ) : null}
              <FindingRetestPanel key={`retest:${id}`} findingId={id} readOnly={finding.inherited} onCompleted={load} />
              <Card>
                <CardHeader className="flex-row items-center justify-between gap-2">
                  <CardTitle className="text-sm">证据 / PoC</CardTitle>
                  {finding.http_request && finding.http_response ? (
                    <CopyButton
                      text={`${finding.http_request}\r\n\r\n${finding.http_response}`}
                      successMessage="已复制完整请求/响应报文"
                    />
                  ) : null}
                </CardHeader>
                <CardContent className="space-y-4">
                  {finding.http_request || finding.http_response ? (
                    <>
                      <HTTPMessageBlock title="HTTP 请求报文" text={finding.http_request} />
                      <HTTPMessageBlock title="HTTP 响应报文" text={finding.http_response} />
                    </>
                  ) : (
                    <Alert>
                      <AlertDescription>
                        未采集到原始 HTTP 请求/响应报文；该漏洞可能为 TCP/非 HTTP 类型，或执行器未返回报文。请结合下方文字证据复现。
                      </AlertDescription>
                    </Alert>
                  )}
                  <div className="space-y-2">
                    <span className="text-xs font-medium text-muted-foreground">文字证据 / 命令输出</span>
                    {finding.evidence ? (
                      <pre className="max-h-[46vh] overflow-auto rounded-md bg-muted px-3 py-2 font-mono text-xs whitespace-pre-wrap">
                        {finding.http_request || finding.http_response
                          ? withoutCurlCommands(finding.evidence)
                          : finding.evidence}
                      </pre>
                    ) : (
                      <p className="text-sm text-muted-foreground">（无证据）</p>
                    )}
                  </div>
                </CardContent>
              </Card>
              <FindingTrafficPanel
                key={`traffic:${id}`}
                findingId={id}
                contextTask={contextTaskId || undefined}
                readOnly={finding.inherited}
                onChanged={load}
              />
              {/* 证据下方：详细报告(Markdown 渲染) */}
              <Card>
                <CardHeader className="flex-row items-center justify-between">
                  <CardTitle className="text-sm">详细报告</CardTitle>
                  {finding.report && <CopyButton text={finding.report} successMessage="已复制详细报告" />}
                </CardHeader>
                <CardContent>
                  {finding.report_stale ? (
                    <Alert>
                      <AlertDescription>流量证据已变更，详细报告待更新。</AlertDescription>
                    </Alert>
                  ) : null}
                  {finding.report ? (
                    <Markdown text={finding.report} />
                  ) : (
                    <p className="text-sm text-muted-foreground">暂无详细报告。</p>
                  )}
                </CardContent>
              </Card>
            </div>

            {/* 右栏：状态区 */}
            <Card className="h-fit lg:sticky lg:top-24">
              <CardHeader>
                <CardTitle className="text-sm">状态</CardTitle>
              </CardHeader>
              <CardContent className="divide-y">
                {/* 漏洞 ID */}
                <FieldRow label="漏洞 ID">
                  <code className="rounded bg-muted px-1.5 py-0.5 font-mono text-xs text-muted-foreground">
                    #{finding.id}
                  </code>
                </FieldRow>

                {/* 严重等级 */}
                <FieldRow label="严重等级">
                  {finding.inherited ? (
                    <StatusBadge domain="severity" value={finding.severity} dot />
                  ) : (
                    <Select value={finding.severity} onValueChange={(v) => changeSeverity(v as Severity)}>
                      <SelectTrigger size="sm" className="h-7 w-auto border-none px-1 shadow-none focus-visible:ring-0">
                        <StatusBadge domain="severity" value={finding.severity} dot />
                      </SelectTrigger>
                      <SelectContent position="popper" align="end">
                        <SelectGroup>
                          {SEVERITIES.map((sv) => (
                            <SelectItem key={sv} value={sv}>
                              {statusMeta("severity", sv).label}
                            </SelectItem>
                          ))}
                        </SelectGroup>
                      </SelectContent>
                    </Select>
                  )}
                </FieldRow>

                {/* CVSS 评分 */}
                <FieldRow label="CVSS 评分">
                  {finding.inherited ? (
                    <span className="tabular-nums">{finding.cvss != null ? finding.cvss.toFixed(1) : "—"}</span>
                  ) : (
                    <Input
                      type="number"
                      min={0}
                      max={10}
                      step={0.1}
                      value={cvssDraft}
                      onChange={(e) => setCvssDraft(e.target.value)}
                      onBlur={commitCVSS}
                      onKeyDown={(e) => {
                        if (e.key === "Enter") (e.target as HTMLInputElement).blur();
                      }}
                      placeholder="0.0-10.0"
                      className="h-7 w-24 text-right text-sm"
                    />
                  )}
                </FieldRow>

                {/* 处理状态 */}
                <FieldRow label="处理状态">
                  {finding.inherited ? (
                    <StatusBadge domain="finding" value={finding.status} dot />
                  ) : (
                    <Select value={finding.status} onValueChange={(v) => changeStatus(v as FindingStatus)}>
                      <SelectTrigger size="sm" className="h-7 w-auto border-none px-1 shadow-none focus-visible:ring-0">
                        <StatusBadge domain="finding" value={finding.status} dot />
                      </SelectTrigger>
                      <SelectContent position="popper" align="end">
                        <SelectGroup>
                          {FINDING_STATUSES.map((st) => (
                            <SelectItem key={st} value={st}>
                              {statusMeta("finding", st).label}
                            </SelectItem>
                          ))}
                        </SelectGroup>
                      </SelectContent>
                    </Select>
                  )}
                </FieldRow>

                {/* 漏洞类型 */}
                <FieldRow label="漏洞类型">
                  {finding.vulnclass ? (
                    <code className="rounded bg-muted px-1.5 py-0.5 font-mono text-xs">{finding.vulnclass}</code>
                  ) : (
                    <span className="text-muted-foreground">—</span>
                  )}
                </FieldRow>

                {/* 涉及资产 */}
                <FieldRow label="涉及资产">
                  {finding.assets && finding.assets.length > 0 ? (
                    <div className="flex flex-wrap justify-end gap-1">
                      {finding.assets.map((a) => (
                        <code
                          key={a.id}
                          className="max-w-[16rem] truncate rounded bg-muted px-1.5 py-0.5 font-mono text-xs"
                          title={`${a.type} · ${a.label}`}
                        >
                          {a.label}
                        </code>
                      ))}
                    </div>
                  ) : (
                    <span className="text-muted-foreground">—</span>
                  )}
                </FieldRow>

                {/* 所属任务 */}
                <FieldRow label="所属任务">
                  {finding.task_id ? (
                    <Link
                      href={`/function/tasks/detail?id=${finding.task_id}`}
                      className="inline-flex max-w-[16rem] items-center gap-1 text-primary hover:underline"
                      title={finding.task_description}
                    >
                      <span className="truncate">{finding.task_description || `#${finding.task_id}`}</span>
                      <ArrowUpRightIcon className="size-3 shrink-0" />
                    </Link>
                  ) : (
                    <span className="text-muted-foreground">—（任务已删除）</span>
                  )}
                </FieldRow>

                {/* 发现时间 */}
                <FieldRow label="发现时间">
                  <span className="tabular-nums">{fmtTime(finding.ts)}</span>
                </FieldRow>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* 取证截图：重放/现场截图证据 + 上传 */}
        <TabsContent value="screenshots" className="mt-0">
          <Card>
            <CardHeader className="flex-row items-center justify-between gap-2">
              <CardTitle className="text-sm">取证截图</CardTitle>
              {!finding.inherited ? (
                <div className="flex items-center gap-2">
                  <Button size="sm" variant="outline" disabled={autoShotting} onClick={() => void onAutoShot()}>
                    {autoShotting ? <Loader2Icon className="size-3.5 animate-spin" /> : <CameraIcon className="size-3.5" />}
                    报文取证
                  </Button>
                  <Button size="sm" variant="outline" disabled={pageShotting} onClick={() => void onPageShot()}>
                    {pageShotting ? <Loader2Icon className="size-3.5 animate-spin" /> : <GlobeIcon className="size-3.5" />}
                    页面取证
                  </Button>
                  <label className="flex cursor-pointer items-center gap-1.5 rounded-md border px-3 py-1.5 text-xs hover:bg-muted">
                    <CameraIcon className="size-3.5" /> 上传截图
                    <input
                      type="file"
                      accept="image/png,image/jpeg"
                      className="hidden"
                      onChange={(e) => {
                        const f = e.target.files?.[0];
                        if (f) onPickShot(f);
                        e.target.value = "";
                      }}
                    />
                  </label>
                </div>
              ) : null}
            </CardHeader>
            <CardContent className="space-y-4">
              {!finding.inherited ? (
                <Input
                  value={shotCaption}
                  onChange={(e) => setShotCaption(e.target.value)}
                  placeholder="截图说明（可选，如：重放请求后响应含特征串）"
                  className="max-w-md"
                />
              ) : null}
              {screenshots.length === 0 ? (
                <p className="text-sm text-muted-foreground">暂无取证截图。</p>
              ) : (
                <div className="grid gap-4 md:grid-cols-2">
                  {screenshots.map((s) => (
                    <figure key={s.id} className="space-y-1">
                      <img
                        src={s.data?.startsWith("data:") ? s.data : `data:image/png;base64,${s.data ?? ""}`}
                        alt={s.caption}
                        className="w-full rounded-md border"
                      />
                      <figcaption className="text-xs text-muted-foreground">
                        {s.caption || "未命名截图"} · {fmtTime(s.created_at)}
                      </figcaption>
                    </figure>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* 复核时间线：操作员处置留痕 */}
        <TabsContent value="review" className="mt-0">
          <Card>
            <CardHeader>
              <CardTitle className="text-sm">复核时间线</CardTitle>
            </CardHeader>
            <CardContent>
              {events.length === 0 ? (
                <p className="text-sm text-muted-foreground">暂无复核记录。</p>
              ) : (
                <ol className="space-y-0 border-l pl-4">
                  {events.map((ev) => (
                    <li key={ev.id} className="relative pb-4 pl-4">
                      <span className="absolute -left-[7px] top-1.5 size-2.5 rounded-full bg-primary" />
                      <div className="flex flex-wrap items-center gap-2 text-sm">
                        <span className="font-medium">{REVIEW_ACTION_LABELS[ev.action] ?? ev.action}</span>
                        {ev.from_val || ev.to_val ? (
                          <span className="text-muted-foreground">
                            {ev.from_val || "—"} → {ev.to_val || "—"}
                          </span>
                        ) : null}
                      </div>
                      <div className="mt-0.5 text-xs text-muted-foreground">
                        {ev.actor || "操作员"} · {fmtTime(ev.created_at)}
                        {ev.note ? ` · ${ev.note}` : ""}
                      </div>
                    </li>
                  ))}
                </ol>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* 链路图：从任务初始节点回溯到本漏洞节点的攻击链路 */}
        <TabsContent value="lineage" className="mt-0">
          <FindingLineageView findingId={finding.id} />
        </TabsContent>
      </div>
    </Tabs>
  );
}

// useSearchParams must sit under a Suspense boundary for static export.
export default function FindingDetailPage() {
  return (
    <React.Suspense fallback={null}>
      <FindingDetailInner />
    </React.Suspense>
  );
}
