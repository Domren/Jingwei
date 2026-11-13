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
// 唯一的例外是报文上方那行时钟——判时间盲注、看限速窗口都要手边有个走秒的表；
// 它是个带边框的整块，默认居中，按住可以左右拖到不挡字的地方，位置记在浏览器里。
// 目标地址默认从请求行的 Host 头推出来，允许手改——同一个包换站重发是常态。

const CLOCK_PREF_KEY = "jingwei.repeater.clock";
// R17：流量页「按原始字节发到重发」的交接键（base64 的完整原始报文）。
const RAW_B64_KEY = "jingwei.repeater.raw_b64";

/** 公历带秒的时刻，例：2026年11月03日 13:45:09。 */
function formatCivilClock(d: Date): string {
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}年${pad(d.getMonth() + 1)}月${pad(d.getDate())}日 ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

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

/** 把一段原始报文拆成方法、路径、头与正文（宽容解析，不追求协议严谨）。
 *  R17：不再全局把 CRLF 折成 LF——multipart 正文要求 CRLF，折叠会让重发正文
 *  与原报文不等价（yakit 能过而重发失败的第二个根因）。头部按 \r?\n 切，
 *  正文从首个空行（\r\n\r\n 优先）原样截取。 */
function parseRaw(raw: string): ParsedRequest | null {
  let sep = raw.indexOf("\r\n\r\n");
  let sepLen = 4;
  if (sep < 0) {
    sep = raw.indexOf("\n\n");
    sepLen = 2;
  }
  const head = sep >= 0 ? raw.slice(0, sep) : raw;
  const body = sep >= 0 ? raw.slice(sep + sepLen) : "";
  const lines = head.split(/\r?\n/).filter((line, i) => i === 0 || line.trim() !== "");
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

  // 时钟走的是浏览器本地时间：先空着，挂载后才填，静态导出的首屏与服务端渲染不比对错。
  const [clock, setClock] = React.useState<Date | null>(null);
  // 位置只有一个数：相对正文区中心的水平偏移，0 就是居中，左右各拖到行边缘为止。
  const [clockOffset, setClockOffset] = React.useState(0);
  const clockDrag = React.useRef<{ startX: number; startOffset: number; room: number } | null>(null);

  React.useEffect(() => {
    const tick = () => setClock(new Date());
    tick();
    const timer = window.setInterval(tick, 1000);
    return () => window.clearInterval(timer);
  }, []);

  // 位置是偏好，存在浏览器里；读的时候容错，坏了或形状不对就当没存过。
  React.useEffect(() => {
    try {
      const saved = JSON.parse(localStorage.getItem(CLOCK_PREF_KEY) || "") as { offset?: number };
      if (Number.isFinite(saved.offset)) {
        setClockOffset(Math.max(-2000, Math.min(2000, Math.round(saved.offset as number))));
      }
    } catch {
      // 没有存档或存档不是 JSON：用默认位置
    }
  }, []);

  React.useEffect(() => {
    localStorage.setItem(CLOCK_PREF_KEY, JSON.stringify({ offset: clockOffset }));
  }, [clockOffset]);

  // R17：从流量页「按原始字节发到重发」带入的报文——base64 解成字节字符串；
  // 二进制正文在编辑器里显示为乱码，但按原字节发送。
  React.useEffect(() => {
    const b64 = sessionStorage.getItem(RAW_B64_KEY);
    if (!b64) return;
    sessionStorage.removeItem(RAW_B64_KEY);
    try {
      const bin = atob(b64);
      setRaw(bin);
      const req = parseRaw(bin);
      if (req?.host) setTarget(`${/:(443)$/.test(req.host) ? "https" : "http"}://${req.host}`);
      toast.success("已按原始字节载入流量报文；二进制正文按原字节发送");
    } catch {
      toast.error("原始报文 base64 解码失败");
    }
  }, []);

  const clampClockOffset = (px: number, room: number) => Math.max(-room, Math.min(room, px));

  function onClockPointerDown(e: React.PointerEvent<HTMLSpanElement>) {
    const row = e.currentTarget.parentElement;
    if (!row) return;
    const room = Math.max(0, row.getBoundingClientRect().width / 2 - e.currentTarget.getBoundingClientRect().width / 2);
    clockDrag.current = { startX: e.clientX, startOffset: clockOffset, room };
    e.currentTarget.setPointerCapture(e.pointerId);
  }

  function onClockPointerMove(e: React.PointerEvent<HTMLSpanElement>) {
    const drag = clockDrag.current;
    if (!drag) return;
    setClockOffset(clampClockOffset(drag.startOffset + (e.clientX - drag.startX), drag.room));
  }

  function onClockPointerEnd(e: React.PointerEvent<HTMLSpanElement>) {
    if (!clockDrag.current) return;
    clockDrag.current = null;
    if (e.currentTarget.hasPointerCapture(e.pointerId)) {
      e.currentTarget.releasePointerCapture(e.pointerId);
    }
  }

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
      // R17：正文按字节发——latin1 可表示（含二进制与 CRLF）时走 base64 无损通道；
      // 手改出非 latin1 字符（如直接输入中文）时退回文本通道（此时正文已是文本语义）。
      let latin1 = true;
      for (let i = 0; i < req.body.length; i++) {
        if (req.body.charCodeAt(i) > 0xff) {
          latin1 = false;
          break;
        }
      }
      const payload: Parameters<typeof api.repeaterSend>[0] = {
        method: req.method,
        url,
        headers: req.headers,
        insecure_skip_verify: insecure,
        use_recording_proxy: viaProxy,
      };
      if (req.body && latin1) payload.body_base64 = btoa(req.body);
      else payload.body = req.body;
      const res = await api.repeaterSend(payload);
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

      <div className="relative flex h-10 items-center">
        {clock ? (
          <span
            className="absolute left-1/2 cursor-grab touch-none select-none rounded-md border bg-card/70 px-2.5 py-1 font-mono text-sm tabular-nums text-muted-foreground active:cursor-grabbing"
            style={{ transform: `translate(calc(-50% + ${clockOffset}px), 0)` }}
            title="按住左右拖动可挪位置"
            onPointerDown={onClockPointerDown}
            onPointerMove={onClockPointerMove}
            onPointerUp={onClockPointerEnd}
            onPointerCancel={onClockPointerEnd}
          >
            {formatCivilClock(clock)}
          </span>
        ) : null}
      </div>

      <div className="mt-3 grid flex-1 gap-4 lg:grid-cols-2">
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
