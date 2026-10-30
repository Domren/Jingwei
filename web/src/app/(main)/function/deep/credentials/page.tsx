"use client";

import * as React from "react";

import { CopyIcon, EyeIcon, EyeOffIcon, KeyRoundIcon, Loader2Icon, RefreshCwIcon, SearchIcon } from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { api } from "@/lib/api";
import type { IntelligencePage, TaskIntelligence } from "@/lib/types";

// 凭据库：把所有任务里采集到的凭据集中展示，带掩码和筛选。
// 凭据是内网渗透的钥匙——拿一个密码打多个服务是常规操作，所以要有一个
// 全局视图而不是散在各任务的情报里。

type CredentialRow = {
  intelId: number;
  taskId: number;
  label: string;
  username: string;
  password: string;
  token: string;
  cookie: string;
  endpoint: string;
  protocol: string;
  status: string;
  createdAt: string;
};

function maskValue(v: string): string {
  if (!v) return "";
  if (v.length <= 4) return "****";
  return v.slice(0, 2) + "****" + v.slice(-2);
}

function extractRows(items: TaskIntelligence[]): CredentialRow[] {
  const rows: CredentialRow[] = [];
  for (const item of items) {
    if (item.kind !== "credential") continue;
    const accounts = item.credentials?.accounts;
    if (!accounts || accounts.length === 0) {
      // 没有结构化账号也展示一条（原始情报）
      rows.push({
        intelId: item.id,
        taskId: item.task_id,
        label: item.title || "(未解析)",
        username: "",
        password: "",
        token: "",
        cookie: "",
        endpoint: "",
        protocol: "",
        status: item.status,
        createdAt: item.created_at,
      });
      continue;
    }
    for (const a of accounts) {
      rows.push({
        intelId: item.id,
        taskId: item.task_id,
        label: a.label || item.title || "",
        username: a.username || "",
        password: a.password || "",
        token: a.token || "",
        cookie: a.cookie || "",
        endpoint: a.endpoint || "",
        protocol: a.protocol || "",
        status: item.status,
        createdAt: item.created_at,
      });
    }
  }
  return rows;
}

export default function CredentialsPage() {
  const [rows, setRows] = React.useState<CredentialRow[]>([]);
  const [loading, setLoading] = React.useState(false);
  const [search, setSearch] = React.useState("");
  const [revealed, setRevealed] = React.useState<Set<string>>(new Set());

  const load = React.useCallback(async () => {
    setLoading(true);
    try {
      const page = await api.globalCredentials();
      setRows(extractRows(page.items ?? []));
    } catch (e) {
      toast.error("加载凭据失败：" + (e as Error).message);
    } finally {
      setLoading(false);
    }
  }, []);

  React.useEffect(() => {
    void load();
  }, [load]);

  const filtered = React.useMemo(() => {
    if (!search.trim()) return rows;
    const q = search.toLowerCase();
    return rows.filter(
      (r) =>
        r.label.toLowerCase().includes(q) ||
        r.username.toLowerCase().includes(q) ||
        r.endpoint.toLowerCase().includes(q) ||
        r.protocol.toLowerCase().includes(q),
    );
  }, [rows, search]);

  const toggleReveal = (key: string) => {
    setRevealed((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  };

  const copyValue = (v: string) => {
    if (!v) return;
    void navigator.clipboard.writeText(v);
    toast.success("已复制");
  };

  return (
    <div className="flex flex-1 flex-col gap-4 p-4 lg:p-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="flex items-center gap-2 text-lg font-semibold">
            <KeyRoundIcon className="size-5" /> 凭据库
          </h1>
          <p className="mt-1 text-sm text-muted-foreground">
            所有任务采集到的凭据集中展示。密码/Token 默认掩码，点击眼睛图标可临时查看。
          </p>
        </div>
        <div className="flex items-center gap-2">
          <div className="relative">
            <SearchIcon className="absolute left-2.5 top-2.5 size-4 text-muted-foreground" />
            <Input
              placeholder="搜索用户名 / 标签 / 端点…"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="h-8 w-[220px] pl-8 text-xs"
            />
          </div>
          <Button size="sm" variant="outline" disabled={loading} onClick={() => void load()}>
            {loading ? <Loader2Icon className="size-4 animate-spin" /> : <RefreshCwIcon className="size-4" />}
            刷新
          </Button>
        </div>
      </div>

      <Card>
        <CardHeader className="flex-row items-center justify-between">
          <CardTitle className="text-sm">
            共 {filtered.length} 条凭据
            {search && <span className="ml-2 text-muted-foreground">（筛选自 {rows.length} 条）</span>}
          </CardTitle>
        </CardHeader>
        <CardContent>
          {loading ? (
            <div className="flex items-center gap-2 py-8 text-sm text-muted-foreground">
              <Loader2Icon className="size-4 animate-spin" /> 加载中…
            </div>
          ) : filtered.length === 0 ? (
            <p className="py-8 text-center text-sm text-muted-foreground">
              暂无凭据。任务 Agent 发现凭据后会自动入库。
            </p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>标签</TableHead>
                  <TableHead>用户名</TableHead>
                  <TableHead>密码</TableHead>
                  <TableHead>Token</TableHead>
                  <TableHead>端点</TableHead>
                  <TableHead>协议</TableHead>
                  <TableHead>状态</TableHead>
                  <TableHead>来源任务</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filtered.map((r, i) => {
                  const key = `${r.intelId}-${i}`;
                  const isRevealed = revealed.has(key);
                  return (
                    <TableRow key={key}>
                      <TableCell className="max-w-[160px] truncate text-xs">{r.label}</TableCell>
                      <TableCell className="font-mono text-xs">{r.username || "-"}</TableCell>
                      <TableCell>
                        {r.password ? (
                          <span className="flex items-center gap-1">
                            <code className="text-xs">{isRevealed ? r.password : maskValue(r.password)}</code>
                            <Button size="icon" variant="ghost" className="size-5" onClick={() => toggleReveal(key)}>
                              {isRevealed ? <EyeOffIcon className="size-3" /> : <EyeIcon className="size-3" />}
                            </Button>
                            <Button size="icon" variant="ghost" className="size-5" onClick={() => copyValue(r.password)}>
                              <CopyIcon className="size-3" />
                            </Button>
                          </span>
                        ) : (
                          <span className="text-xs text-muted-foreground">-</span>
                        )}
                      </TableCell>
                      <TableCell>
                        {r.token ? (
                          <span className="flex items-center gap-1">
                            <code className="text-xs">{isRevealed ? r.token : maskValue(r.token)}</code>
                            <Button size="icon" variant="ghost" className="size-5" onClick={() => copyValue(r.token)}>
                              <CopyIcon className="size-3" />
                            </Button>
                          </span>
                        ) : (
                          <span className="text-xs text-muted-foreground">-</span>
                        )}
                      </TableCell>
                      <TableCell className="max-w-[180px] truncate font-mono text-xs">{r.endpoint || "-"}</TableCell>
                      <TableCell>
                        {r.protocol ? (
                          <Badge variant="outline" className="text-xs">
                            {r.protocol}
                          </Badge>
                        ) : (
                          <span className="text-xs text-muted-foreground">-</span>
                        )}
                      </TableCell>
                      <TableCell>
                        <Badge variant={r.status === "verified" ? "default" : r.status === "invalid" ? "destructive" : "secondary"} className="text-xs">
                          {r.status}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-xs text-muted-foreground">#{r.taskId}</TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
