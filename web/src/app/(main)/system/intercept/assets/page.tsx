"use client";

import * as React from "react";

import { BanIcon, PencilIcon, PlusIcon, Trash2Icon } from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Separator } from "@/components/ui/separator";
import { Sheet, SheetContent, SheetDescription, SheetFooter, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Switch } from "@/components/ui/switch";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Textarea } from "@/components/ui/textarea";
import { api } from "@/lib/api";
import type { AssetInterceptKind, AssetInterceptRule, Authorization } from "@/lib/types";

// ---- kind 元信息 ----

const KIND_OPTIONS: { value: AssetInterceptKind; label: string; group: string; placeholder: string }[] = [
  { value: "exact_domain", label: "域名（全等）", group: "全等匹配", placeholder: "example.gov.cn" },
  { value: "exact_ip", label: "IP（全等）", group: "全等匹配", placeholder: "203.0.113.10" },
  { value: "exact_url", label: "URL（全等）", group: "全等匹配", placeholder: "https://example.gov.cn/login" },
  { value: "fuzzy_domain", label: "域名（模糊）", group: "模糊匹配", placeholder: ".gov.cn" },
  { value: "fuzzy_ip", label: "IP（模糊）", group: "模糊匹配", placeholder: "203.0.113." },
  { value: "fuzzy_url", label: "URL（模糊）", group: "模糊匹配", placeholder: "/admin" },
  { value: "cidr", label: "CIDR 网段", group: "网段", placeholder: "192.168.0.0/16" },
];

const KIND_LABEL: Record<AssetInterceptKind, string> = Object.fromEntries(
  KIND_OPTIONS.map((o) => [o.value, o.label]),
) as Record<AssetInterceptKind, string>;

const KIND_GROUPS = ["全等匹配", "模糊匹配", "网段"];

function KindBadge({ kind }: { kind: AssetInterceptKind }) {
  const fuzzy = kind.startsWith("fuzzy_");
  const cidr = kind === "cidr";
  return (
    <Badge
      variant="outline"
      className={
        cidr
          ? "border-sky-400 text-sky-600"
          : fuzzy
            ? "border-amber-400 text-amber-600"
            : "border-emerald-400 text-emerald-600"
      }
    >
      {KIND_LABEL[kind]}
    </Badge>
  );
}

function Field({ label, hint, children }: { label: string; hint?: string; children: React.ReactNode }) {
  return (
    <div className="space-y-1.5">
      <Label className="text-xs font-medium text-muted-foreground uppercase tracking-wide">{label}</Label>
      {children}
      {hint && <p className="text-[11px] text-muted-foreground">{hint}</p>}
    </div>
  );
}

// ---- form state ----

type RuleForm = {
  enabled: boolean;
  kind: AssetInterceptKind;
  pattern: string;
  note: string;
};

const defaultForm = (): RuleForm => ({ enabled: true, kind: "fuzzy_domain", pattern: "", note: "" });

// 前端轻校验（与后端一致：仅 exact_ip / cidr 做格式校验，其余交后端）。
function frontValidate(form: RuleForm): string | null {
  const p = form.pattern.trim();
  if (!p) return "匹配内容不能为空";
  if (form.kind === "cidr" && !/^[0-9a-fA-F:.]+\/\d{1,3}$/.test(p)) {
    return "CIDR 格式无效，形如 192.168.0.0/16";
  }
  return null;
}

// ---- page ----

export default function AssetInterceptPage() {
  const [rules, setRules] = React.useState<AssetInterceptRule[]>([]);
  const [loading, setLoading] = React.useState(true);
  const [open, setOpen] = React.useState(false);
  const [editing, setEditing] = React.useState<AssetInterceptRule | null>(null);
  const [form, setForm] = React.useState<RuleForm>(defaultForm());
  const [saving, setSaving] = React.useState(false);
  const [authzList, setAuthzList] = React.useState<Authorization[]>([]);
  const [authzOpen, setAuthzOpen] = React.useState(false);
  const [authzSaving, setAuthzSaving] = React.useState(false);
  const [authzForm, setAuthzForm] = React.useState({
    name: "",
    targets: "",
    exclusions: "",
    starts: "",
    ends: "",
    note: "",
  });

  const load = React.useCallback(async () => {
    try {
      setRules(await api.assetInterceptRules());
    } catch {
      toast.error("加载资产拦截规则失败");
    } finally {
      setLoading(false);
    }
  }, []);

  const loadAuthz = React.useCallback(async () => {
    try {
      setAuthzList(await api.authorizations());
    } catch {
      toast.error("加载客户授权清单失败");
    }
  }, []);

  React.useEffect(() => {
    load();
    void loadAuthz();
  }, [load, loadAuthz]);

  async function saveAuthz() {
    setAuthzSaving(true);
    try {
      await api.createAuthorization({
        name: authzForm.name,
        targets: authzForm.targets.split(/[\n,，\s]+/).filter(Boolean),
        exclusions: authzForm.exclusions.split(/[\n,，\s]+/).filter(Boolean),
        starts_at: authzForm.starts || undefined,
        ends_at: authzForm.ends || undefined,
        note: authzForm.note,
      });
      toast.success("授权已登记");
      setAuthzOpen(false);
      setAuthzForm({ name: "", targets: "", exclusions: "", starts: "", ends: "", note: "" });
      await loadAuthz();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "登记失败");
    } finally {
      setAuthzSaving(false);
    }
  }

  async function removeAuthz(a: Authorization) {
    if (!window.confirm(`删除授权「${a.name}」？删除后该范围不再自动放行。`)) return;
    try {
      await api.deleteAuthorization(a.id);
      toast.success("已删除");
      await loadAuthz();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "删除失败");
    }
  }

  function set(patch: Partial<RuleForm>) {
    setForm((f) => ({ ...f, ...patch }));
  }

  function openNew() {
    setEditing(null);
    setForm(defaultForm());
    setOpen(true);
  }

  function openEdit(rule: AssetInterceptRule) {
    setEditing(rule);
    setForm({ enabled: rule.enabled, kind: rule.kind, pattern: rule.pattern, note: rule.note });
    setOpen(true);
  }

  async function handleSave() {
    const err = frontValidate(form);
    if (err) {
      toast.error(err);
      return;
    }
    const payload = { ...form, pattern: form.pattern.trim() };
    setSaving(true);
    try {
      if (editing) {
        await api.updateAssetInterceptRule(editing.id, payload);
        toast.success("规则已更新");
      } else {
        await api.createAssetInterceptRule(payload);
        toast.success("规则已创建");
      }
      setOpen(false);
      load();
    } catch (e) {
      toast.error((e as Error).message);
    } finally {
      setSaving(false);
    }
  }

  async function handleDelete(rule: AssetInterceptRule) {
    if (!window.confirm(`确定删除资产拦截规则「${rule.pattern}」？`)) return;
    try {
      await api.deleteAssetInterceptRule(rule.id);
      toast.success("规则已删除");
      load();
    } catch (e) {
      toast.error((e as Error).message);
    }
  }

  async function handleToggle(rule: AssetInterceptRule) {
    try {
      await api.toggleAssetInterceptRule(rule.id, !rule.enabled);
      load();
    } catch (e) {
      toast.error((e as Error).message);
    }
  }

  const placeholder = KIND_OPTIONS.find((o) => o.value === form.kind)?.placeholder ?? "";

  return (
    <div className="flex flex-1 flex-col gap-5 p-6">
      {/* header */}
      <div className="flex items-center gap-2.5">
        <BanIcon className="h-5 w-5 shrink-0" />
        <div>
          <h1 className="text-lg font-semibold leading-tight">资产拦截</h1>
          <p className="text-sm text-muted-foreground mt-0.5">
            全局资产黑名单：命中的域名 / IP / URL / 网段将被拦截，不对其执行任何操作
          </p>
        </div>
      </div>

      <div className="flex items-center justify-between gap-3">
        <p className="text-xs text-muted-foreground">
          支持全等与模糊匹配的域名 / IP / URL，以及 CIDR 网段；默认内置模糊拦截政府（.gov / .gov.cn）与教育（.edu /
          .edu.cn）网站
        </p>
        <Button onClick={openNew} size="sm" className="shrink-0">
          <PlusIcon className="h-4 w-4" />
          新建规则
        </Button>
      </div>

      <Card>
        <CardContent className="p-0">
          {loading ? (
            <p className="p-6 text-sm text-muted-foreground">加载中…</p>
          ) : rules.length === 0 ? (
            <div className="flex flex-col items-center justify-center gap-2 py-16 text-center">
              <BanIcon className="h-8 w-8 text-muted-foreground/40" />
              <p className="text-sm text-muted-foreground">暂无资产拦截规则</p>
              <Button size="sm" variant="outline" onClick={openNew}>
                <PlusIcon className="h-4 w-4" />
                新建第一条规则
              </Button>
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="w-[130px]">类型</TableHead>
                  <TableHead>匹配内容</TableHead>
                  <TableHead>备注</TableHead>
                  <TableHead className="w-[64px] text-center">启用</TableHead>
                  <TableHead className="w-[80px]" />
                </TableRow>
              </TableHeader>
              <TableBody>
                {rules.map((rule) => (
                  <TableRow key={rule.id} className={!rule.enabled ? "opacity-40" : ""}>
                    <TableCell>
                      <KindBadge kind={rule.kind} />
                    </TableCell>
                    <TableCell className="max-w-[280px]">
                      <code className="block truncate rounded bg-muted px-1.5 py-0.5 text-xs font-mono">
                        {rule.pattern}
                      </code>
                    </TableCell>
                    <TableCell className="text-sm text-muted-foreground">
                      <div className="flex items-center gap-1.5">
                        {rule.builtin && (
                          <Badge variant="secondary" className="shrink-0 px-1 py-0 text-[10px]">
                            内置
                          </Badge>
                        )}
                        <span className="truncate">{rule.note}</span>
                      </div>
                    </TableCell>
                    <TableCell className="text-center">
                      <Switch checked={rule.enabled} onCheckedChange={() => handleToggle(rule)} />
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center justify-end gap-0.5">
                        <Button size="icon" variant="ghost" className="h-7 w-7" onClick={() => openEdit(rule)}>
                          <PencilIcon className="h-3.5 w-3.5" />
                        </Button>
                        <Button
                          size="icon"
                          variant="ghost"
                          className="h-7 w-7 text-destructive hover:text-destructive"
                          onClick={() => handleDelete(rule)}
                        >
                          <Trash2Icon className="h-3.5 w-3.5" />
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      {/* editor sheet */}
      <Sheet open={open} onOpenChange={setOpen}>
        <SheetContent side="right" className="flex flex-col gap-0 p-0 sm:max-w-md">
          <SheetHeader className="border-b px-6 py-4">
            <SheetTitle>{editing ? "编辑资产拦截规则" : "新建资产拦截规则"}</SheetTitle>
            <SheetDescription className="text-xs">命中此规则的目标资产会被全局拦截</SheetDescription>
          </SheetHeader>

          <div className="flex-1 min-h-0 overflow-y-auto px-6 py-5 space-y-5">
            <Field label="匹配类型">
              <Select value={form.kind} onValueChange={(v) => set({ kind: v as AssetInterceptKind })}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {KIND_GROUPS.map((g) => (
                    <React.Fragment key={g}>
                      <div className="px-2 py-1 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
                        {g}
                      </div>
                      {KIND_OPTIONS.filter((o) => o.group === g).map((o) => (
                        <SelectItem key={o.value} value={o.value}>
                          {o.label}
                        </SelectItem>
                      ))}
                    </React.Fragment>
                  ))}
                </SelectContent>
              </Select>
            </Field>

            <Field
              label="匹配内容"
              hint={
                form.kind === "cidr"
                  ? "CIDR 网段，形如 192.168.0.0/16"
                  : form.kind.startsWith("fuzzy_")
                    ? "模糊匹配：目标包含此内容即命中"
                    : "全等匹配：目标需与此内容完全一致"
              }
            >
              <Input
                placeholder={placeholder}
                value={form.pattern}
                onChange={(e) => set({ pattern: e.target.value })}
              />
            </Field>

            <Field label="备注（可选）">
              <Textarea
                placeholder="说明这条规则的用途"
                value={form.note}
                onChange={(e) => set({ note: e.target.value })}
                rows={2}
                className="resize-none"
              />
            </Field>

            <Separator />

            <div className="flex items-center gap-3">
              <Switch id="asset-rule-enabled" checked={form.enabled} onCheckedChange={(v) => set({ enabled: v })} />
              <Label htmlFor="asset-rule-enabled" className="cursor-pointer">
                启用此规则
              </Label>
            </div>
          </div>

          <SheetFooter className="border-t px-6 py-4 flex-row justify-end gap-2">
            <Button variant="outline" onClick={() => setOpen(false)}>
              取消
            </Button>
            <Button onClick={handleSave} disabled={saving}>
              {saving ? "保存中…" : "保存"}
            </Button>
          </SheetFooter>
        </SheetContent>
      </Sheet>

      <Card>
        <CardContent className="space-y-3 p-4">
          <div className="flex items-start justify-between gap-3">
            <div>
              <h2 className="text-sm font-medium">客户授权清单</h2>
              <p className="mt-1 text-xs text-muted-foreground">
                存在任何一条<strong>有效</strong>授权时，agent 与任务的目标必须落在某条授权内且不命中排除项；没有有效授权时不强制。
                范围支持 IP / CIDR / 域名（裸域名同时匹配其子域），排除项优先。
              </p>
            </div>
            <Button size="sm" onClick={() => setAuthzOpen(true)}>
              <PlusIcon className="h-4 w-4" />
              新增授权
            </Button>
          </div>
          {authzList.length === 0 ? (
            <p className="py-6 text-center text-xs text-muted-foreground">暂无授权清单</p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>名称</TableHead>
                  <TableHead>范围</TableHead>
                  <TableHead>排除</TableHead>
                  <TableHead className="w-44">有效期</TableHead>
                  <TableHead className="w-20">启用</TableHead>
                  <TableHead className="w-16" />
                </TableRow>
              </TableHeader>
              <TableBody>
                {authzList.map((a) => (
                  <TableRow key={a.id}>
                    <TableCell className="text-sm">{a.name}</TableCell>
                    <TableCell className="max-w-64 truncate font-mono text-xs" title={a.targets.join(" ")}>
                      {a.targets.join("、")}
                    </TableCell>
                    <TableCell className="max-w-48 truncate font-mono text-xs" title={a.exclusions.join(" ")}>
                      {a.exclusions.length ? a.exclusions.join("、") : "—"}
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground">
                      {(a.starts_at ? new Date(a.starts_at).toLocaleDateString("zh-CN") : "长期") +
                        " → " +
                        (a.ends_at ? new Date(a.ends_at).toLocaleDateString("zh-CN") : "长期")}
                    </TableCell>
                    <TableCell>
                      <Badge variant="outline">{a.enabled ? "启用" : "停用"}</Badge>
                    </TableCell>
                    <TableCell>
                      <Button size="sm" variant="ghost" onClick={() => void removeAuthz(a)}>
                        <Trash2Icon className="size-4" />
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      <Dialog open={authzOpen} onOpenChange={setAuthzOpen}>
        <DialogContent className="sm:max-w-xl">
          <DialogHeader>
            <DialogTitle>新增客户授权</DialogTitle>
            <DialogDescription>范围一行一个（也可用逗号/空格分隔）。</DialogDescription>
          </DialogHeader>
          <div className="space-y-3">
            <div className="space-y-1.5">
              <Label htmlFor="authz-name">名称</Label>
              <Input id="authz-name" value={authzForm.name} onChange={(e) => setAuthzForm((f) => ({ ...f, name: e.target.value }))} />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="authz-targets">授权范围</Label>
              <Textarea
                id="authz-targets"
                value={authzForm.targets}
                onChange={(e) => setAuthzForm((f) => ({ ...f, targets: e.target.value }))}
                placeholder={"10.0.0.0/8\ncorp.com\n203.0.113.10"}
                className="min-h-20 font-mono text-xs"
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="authz-exclusions">排除项</Label>
              <Textarea
                id="authz-exclusions"
                value={authzForm.exclusions}
                onChange={(e) => setAuthzForm((f) => ({ ...f, exclusions: e.target.value }))}
                placeholder={"10.9.9.9"}
                className="min-h-16 font-mono text-xs"
              />
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1.5">
                <Label htmlFor="authz-start">开始日期</Label>
                <Input id="authz-start" type="date" value={authzForm.starts} onChange={(e) => setAuthzForm((f) => ({ ...f, starts: e.target.value }))} />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="authz-end">结束日期</Label>
                <Input id="authz-end" type="date" value={authzForm.ends} onChange={(e) => setAuthzForm((f) => ({ ...f, ends: e.target.value }))} />
              </div>
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="authz-note">备注</Label>
              <Input id="authz-note" value={authzForm.note} onChange={(e) => setAuthzForm((f) => ({ ...f, note: e.target.value }))} />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setAuthzOpen(false)}>取消</Button>
            <Button onClick={() => void saveAuthz()} disabled={authzSaving}>{authzSaving ? "保存中…" : "保存"}</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
