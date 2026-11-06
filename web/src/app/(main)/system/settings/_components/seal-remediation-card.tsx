"use client";

import { useCallback, useEffect, useState } from "react";

import { KeyRoundIcon, Loader2Icon } from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { api } from "@/lib/api";
import type { SealAudit, SealRemediation } from "@/lib/types";

/**
 * 签名密钥轮换后的自检与补救（G3）。
 *
 * 换过平台签名根密钥之后，库里所有密封值都解不开，但**看起来一切正常**：shell 的「检测」只问
 * 它答不答话。所以这里先给出一份按条列出的自检，再给一条能执行的补救流程。
 *
 * 边界要说清楚：平台能自己做完的是 webshell 那一半（重发密钥、重出载荷、把台账改成「等待重新
 * 投放」）；内存马必须经父壳重新注入，凭据与模型密钥的旧值平台已经读不出来——这三类只能列出
 * 具体的人工步骤。「全部已修复」是这里最不该出现的一句话。
 */
export function SealRemediationCard() {
  const [audit, setAudit] = useState<SealAudit | null>(null);
  const [summary, setSummary] = useState("");
  const [result, setResult] = useState<SealRemediation | null>(null);
  const [loading, setLoading] = useState(true);
  const [running, setRunning] = useState<"dry" | "run" | "">("");
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const res = await api.sealAudit();
      setAudit(res.audit);
      setSummary(res.summary);
    } catch (e) {
      setError(`自检失败：${(e as Error).message}`);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const run = async (dryRun: boolean) => {
    if (!dryRun && !window.confirm("执行补救会给解不开的 webshell 重新发密钥并重出载荷。目标上的文件不会被改动——投放仍需人工完成。继续？")) {
      return;
    }
    setRunning(dryRun ? "dry" : "run");
    setError("");
    try {
      const res = await api.sealRemediation(dryRun);
      setResult(res);
      if (!dryRun) {
        toast.success(res.note);
        await load();
      }
    } catch (e) {
      setError(`补救失败：${(e as Error).message}`);
    } finally {
      setRunning("");
    }
  };

  const download = (item: { payload?: string; payload_filename?: string }) => {
    if (!item.payload || !item.payload_filename) return;
    const url = URL.createObjectURL(new Blob([item.payload], { type: "text/plain;charset=utf-8" }));
    const a = document.createElement("a");
    a.href = url;
    a.download = item.payload_filename;
    a.click();
    URL.revokeObjectURL(url);
  };

  const broken = audit?.categories.filter((c) => c.unreadable > 0) ?? [];

  return (
    <Card className="mb-4 break-inside-avoid md:mb-6">
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <KeyRoundIcon className="size-4" />
          签名密钥自检与补救
        </CardTitle>
        <CardDescription>
          平台签名根密钥换过之后，落库密封的 webshell 密钥、内存马密钥、内网凭据口令与模型 API
          密钥都会解不开，而每条记录看起来都还「正常」。这里按条列出，并把平台能自己做的那一半做掉。
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-3 text-sm">
        {loading ? (
          <div className="flex items-center gap-2 text-muted-foreground">
            <Loader2Icon className="size-4 animate-spin" />
            正在自检…
          </div>
        ) : null}
        {error ? <div className="text-red-600 dark:text-red-400">{error}</div> : null}
        {audit && !loading ? (
          <>
            <div className={audit.unreadable_total > 0 ? "text-amber-600 dark:text-amber-400" : "text-muted-foreground"}>
              {summary}
            </div>
            {(audit.query_errors ?? []).map((e) => (
              <div key={e} className="text-red-600 dark:text-red-400">
                {e}
              </div>
            ))}
            {broken.length > 0 ? (
              <div className="flex flex-col gap-2">
                {broken.map((c) => (
                  <div key={c.key} className="flex flex-col gap-1 rounded border bg-muted/30 p-2">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="font-medium">{c.name}</span>
                      <Badge variant="outline">{c.unreadable} / {c.total} 条</Badge>
                      <Badge
                        className={
                          c.automatable
                            ? "bg-emerald-500/15 text-emerald-700 dark:text-emerald-400"
                            : "bg-amber-500/15 text-amber-700 dark:text-amber-400"
                        }
                      >
                        {c.automatable ? "平台可自动重发" : "需人工补一步"}
                      </Badge>
                      <span className="text-muted-foreground">{c.fix}</span>
                    </div>
                    <div className="flex flex-col gap-0.5 text-xs text-muted-foreground">
                      {c.rows.slice(0, 20).map((r) => (
                        <span key={r.id} className="break-all font-mono">
                          #{r.id} {r.label || "（无名称）"}
                        </span>
                      ))}
                      {c.rows.length > 20 ? <span>…其余 {c.rows.length - 20} 条</span> : null}
                    </div>
                  </div>
                ))}
              </div>
            ) : null}
          </>
        ) : null}

        {result ? (
          <div className="flex flex-col gap-2">
            <div className="text-muted-foreground">
              {result.dry_run ? "演练结果（库里未做任何改动）：" : "执行结果："}
              {result.note}
            </div>
            {(result.items ?? []).map((item) => (
              <div
                key={`${item.category}-${item.id}`}
                className="flex flex-col gap-1 rounded border bg-muted/20 p-2 text-xs"
              >
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-mono">#{item.id}</span>
                  <span className="break-all">{item.label || "（无名称）"}</span>
                  <Badge
                    className={
                      item.error
                        ? "bg-red-500/15 text-red-700 dark:text-red-400"
                        : item.done
                          ? "bg-emerald-500/15 text-emerald-700 dark:text-emerald-400"
                          : "bg-amber-500/15 text-amber-700 dark:text-amber-400"
                    }
                  >
                    {item.error ? "失败" : item.done ? "平台已做完" : "待人工"}
                  </Badge>
                  {item.key_version ? <span className="text-muted-foreground">密钥 v{item.key_version}</span> : null}
                  {item.payload_filename ? (
                    <Button variant="outline" size="sm" className="h-6" onClick={() => download(item)}>
                      下载 {item.payload_filename}
                    </Button>
                  ) : null}
                </div>
                <div className="text-muted-foreground">{item.action}</div>
                {item.error ? <div className="text-red-600 dark:text-red-400">{item.error}</div> : null}
                {item.next ? <div className="break-all">{item.next}</div> : null}
                {item.payload_sha256 ? (
                  <div className="text-muted-foreground">载荷指纹 {item.payload_sha256.slice(0, 16)}…</div>
                ) : null}
              </div>
            ))}
          </div>
        ) : null}
      </CardContent>
      <CardFooter className="flex flex-wrap items-center gap-2">
        <Button variant="outline" size="sm" disabled={loading || !!running} onClick={() => void run(true)}>
          {running === "dry" ? <Loader2Icon className="size-4 animate-spin" /> : null}
          演练（不改任何东西）
        </Button>
        <Button
          size="sm"
          disabled={loading || !!running || (audit?.unreadable_total ?? 0) === 0}
          onClick={() => void run(false)}
        >
          {running === "run" ? <Loader2Icon className="size-4 animate-spin" /> : null}
          执行补救
        </Button>
        <Button variant="ghost" size="sm" disabled={loading || !!running} onClick={() => void load()}>
          重新自检
        </Button>
        <span className="text-muted-foreground text-xs">
          补救只动平台侧的密钥与台账；目标上的文件与 JVM 里的注入物要靠重新投放/重新注入。
        </span>
      </CardFooter>
    </Card>
  );
}
