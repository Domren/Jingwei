"use client";

import * as React from "react";

import { CopyIcon, Loader2Icon, SendIcon, Trash2Icon } from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Textarea } from "@/components/ui/textarea";
import { api } from "@/lib/api";

// 请求重发：把改过的原始报文按字节发给目标，拿回原始响应。
//
// 版面刻意只留「报文 + 响应」两栏：重发是高频动作，多一个下拉就多一次犹豫。
// 目标地址默认从请求行的 Host 头推出来，允许手改——同一个包换站重发是常态。

const SAMPLE = `GET / HTTP/1.1
Host: example.com
User-Agent: jingwei-repeater/1.0
Accept: */*

`;

type ParsedRequest = {
  method: string;
  path: string;
  host: string;
  headers: Record<string, string>;
  body: string;
  version: string;
};

type SendResult = {
  status: number;
  status_text: string;
  proto: string;
  headers: Record<string, string[]>;
  body: string;
  body_truncated: boolean;
  body_bytes: number;
  elapsed_ms: number;
  url: string;
  error?: string;
};

/** 把一段原始报文拆成方法、路径、头与正文（宽容解析，不追求协议严谨）。 */
function parseRaw(raw: string): ParsedRequest | null {
  const text = raw.replace(/\r\n/g, "\n");
  const sep = text.indexOf("\n\n");
  const head = sep >= 0 ? text.slice(0, sep) : text;
  const body = sep >= 0 ? text.slice(sep + 2) : "";
  const lines = head.split("\n").filter((line, i) => i === 0 || line.trim() !== "");
  if (lines.length === 0) return null;
  const first = lines[0].trim().split(/\s+/);
  if (first.length < 2) return null;
  const method = first[0].toUpperCase();
  const path = first[1];
  const version = first[2] || "HTTP/1.1";
  const headers: Record<string, string> = {};
  let host = "";
  for (const line of lines.slice(1)) {
    const idx = line.indexOf(":");
    if (idx <= 0) continue;
    const name = line.slice(0, idx).trim();
    const value = line.slice(idx + 1).trim();
    if (!name) continue;
    headers[name] = value;
    if (name.toLowerCase() === "host") host = value;
  }
  return { method, path, host, headers, body, version };
}

function headersToText(headers: Record<string, string[]>): string {
  return Object.entries(headers)
    .map(([k, v]) => `${k}: ${v.join(", ")}`)
    .join("\n");
}

export default function RepeaterPage() {
  const [raw, setRaw] = React.useState(SAMPLE);
  const [target, setTarget] = React.useState("http://example.com");
  const [insecure, setInsecure] = React.useState(true);
  const [viaProxy, setViaProxy] = React.useState(false);
  const [sending, setSending] = React.useState(false);
  const [result, setResult] = React.useState<SendResult | null>(null);

  // 报文里的 Host 变了就同步目标地址——除非用户手动改过。
  const targetTouched = React.useRef(false);
  const parsed = React.useMemo(() => parseRaw(raw), [raw]);
  React.useEffect(() => {
    if (targetTouched.current || !parsed?.host) return;
    const scheme = /:(443)$/.test(parsed.host) ? "https" : "http";
    setTarget(`${scheme}://${parsed.host}`);
  }, [parsed?.host]);

  const send = React.useCallback(async () => {
    const req = parseRaw(raw);
    if (!req) {
      toast.error("报文解析失败：第一行需要是「方法 路径 HTTP/1.1」");
      return;
    }
    let base = target.trim().replace(/\/+$/, "");
    if (!/^https?:\/\//i.test(base)) base = `http://${base}`;
    const url = req.path.startsWith("http://") || req.path.startsWith("https://") ? req.path : `${base}${req.path}`;
    setSending(true);
    try {
      const res = await api.repeaterSend({
        method: req.method,
        url,
        headers: req.headers,
        body: req.body,
        insecure_skip_verify: insecure,
        use_recording_proxy: viaProxy,
      });
      setResult(res);
      if (res.error) toast.error(res.error);
    } catch (e) {
      toast.error("发送失败：" + (e as Error).message);
    } finally {
      setSending(false);
    }
  }, [raw, target, insecure, viaProxy]);

  return (
    <div className="flex flex-1 flex-col gap-4 p-4 lg:p-6">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-lg font-semibold">请求重发</h1>
          <p className="mt-1 text-sm text-muted-foreground">
            改动原始报文后直接发给目标；响应只在本页显示，需要留证请到「流量」或漏洞详情里生成取证图。
          </p>
        </div>
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2">
            <Switch id="insecure" checked={insecure} onCheckedChange={setInsecure} />
            <Label htmlFor="insecure" className="text-xs text-muted-foreground">
              跳过证书校验
            </Label>
          </div>
          <div className="flex items-center gap-2">
            <Switch id="via-proxy" checked={viaProxy} onCheckedChange={setViaProxy} />
            <Label htmlFor="via-proxy" className="text-xs text-muted-foreground">
              走抓包代理（自动留档）
            </Label>
          </div>
        </div>
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <Label htmlFor="target" className="text-xs text-muted-foreground">
          目标地址
        </Label>
        <Input
          id="target"
          value={target}
          onChange={(e) => {
            targetTouched.current = true;
            setTarget(e.target.value);
          }}
          className="h-8 w-[320px] font-mono text-xs"
          placeholder="http://host:port"
        />
        {parsed ? (
          <Badge variant="outline" className="font-mono text-xs">
            {parsed.method} {parsed.path}
          </Badge>
        ) : null}
        <div className="ml-auto flex items-center gap-2">
          <Button size="sm" variant="ghost" onClick={() => setRaw(SAMPLE)}>
            示例
          </Button>
          <Button
            size="sm"
            variant="ghost"
            onClick={() => {
              setRaw("");
              setResult(null);
            }}
          >
            <Trash2Icon className="size-4" /> 清空
          </Button>
          <Button size="sm" onClick={() => void send()} disabled={sending}>
            {sending ? <Loader2Icon className="size-4 animate-spin" /> : <SendIcon className="size-4" />}
            发送
          </Button>
        </div>
      </div>

      <div className="grid flex-1 gap-4 lg:grid-cols-2">
        <Card className="flex min-h-[420px] flex-col">
          <CardHeader className="flex-row items-center justify-between gap-2">
            <CardTitle className="text-sm">请求报文</CardTitle>
            <span className="text-xs text-muted-foreground">第一行：方法 路径 HTTP/1.1</span>
          </CardHeader>
          <CardContent className="flex flex-1 flex-col">
            <Textarea
              value={raw}
              onChange={(e) => setRaw(e.target.value)}
              spellCheck={false}
              className="flex-1 resize-none font-mono text-xs leading-relaxed"
              placeholder={"GET /api/user?id=1 HTTP/1.1\nHost: target.example\n\n"}
            />
          </CardContent>
        </Card>

        <Card className="flex min-h-[420px] flex-col">
          <CardHeader className="flex-row items-center justify-between gap-2">
            <CardTitle className="text-sm">响应</CardTitle>
            {result ? (
              <div className="flex items-center gap-2">
                <Badge variant={result.status >= 400 ? "destructive" : "outline"} className="font-mono text-xs">
                  {result.status} {result.status_text}
                </Badge>
                <span className="text-xs text-muted-foreground tabular-nums">
                  {result.elapsed_ms} ms · {result.body_bytes} B
                </span>
                <Button
                  size="sm"
                  variant="ghost"
                  onClick={() => {
                    void navigator.clipboard.writeText(
                      `${result.proto} ${result.status} ${result.status_text}\n${headersToText(result.headers)}\n\n${result.body}`,
                    );
                    toast.success("已复制完整响应");
                  }}
                >
                  <CopyIcon className="size-3.5" />
                </Button>
              </div>
            ) : null}
          </CardHeader>
          <CardContent className="flex flex-1 flex-col gap-2">
            {result ? (
              <>
                <pre className="rounded-md bg-muted px-3 py-2 font-mono text-xs whitespace-pre-wrap break-all">
                  {headersToText(result.headers)}
                </pre>
                <pre className="max-h-[46vh] flex-1 overflow-auto rounded-md bg-muted px-3 py-2 font-mono text-xs whitespace-pre-wrap break-all">
                  {result.body || "（空响应体）"}
                </pre>
                {result.body_truncated ? (
                  <p className="text-xs text-muted-foreground">响应过大，仅显示前 2 MiB。</p>
                ) : null}
              </>
            ) : (
              <p className="text-sm text-muted-foreground">发送后这里显示状态行、响应头与正文。</p>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
