"use client";

import * as React from "react";

import { Loader2Icon, PlayIcon, UploadIcon } from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { api } from "@/lib/api";

import { DeepDetailDialog, DeepTaskTable, FieldRow, TaskFormShell, useDeepTasks } from "../_components/deep-ui";

const SHELL_TYPES = [
  { value: "php", label: "PHP" },
  { value: "jsp", label: "JSP" },
  { value: "aspx", label: "ASPX" },
];

export default function DeepWebshellInjectPage() {
  const { tasks, total, loading, refresh } = useDeepTasks("webshell_inject");
  const [createOpen, setCreateOpen] = React.useState(false);
  const [submitting, setSubmitting] = React.useState(false);
  const [detailId, setDetailId] = React.useState<number | null>(null);
  const [detailOpen, setDetailOpen] = React.useState(false);

  const [name, setName] = React.useState("");
  const [uploadUrl, setUploadUrl] = React.useState("");
  const [landUrl, setLandUrl] = React.useState("");
  const [shellType, setShellType] = React.useState("php");
  const [password, setPassword] = React.useState("");
  const [fieldName, setFieldName] = React.useState("");
  const [fileName, setFileName] = React.useState("");
  const [extraField, setExtraField] = React.useState("");
  const [extraValue, setExtraValue] = React.useState("");

  function openCreate() {
    setName("");
    setUploadUrl("");
    setLandUrl("");
    setShellType("php");
    setPassword("");
    setFieldName("");
    setFileName("");
    setExtraField("");
    setExtraValue("");
    setCreateOpen(true);
  }

  async function submit() {
    if (!uploadUrl.trim()) {
      toast.error("请填写上传地址");
      return;
    }
    setSubmitting(true);
    try {
      const extra: Record<string, string> = {};
      if (extraField.trim()) extra[extraField.trim()] = extraValue;
      const task = await api.createDeepTask({
        name: name.trim() || undefined,
        kind: "webshell_inject",
        target: landUrl.trim() || uploadUrl.trim(),
        params: {
          upload_url: uploadUrl.trim(),
          land_url: landUrl.trim(),
          shell_type: shellType,
          password,
          field_name: fieldName.trim(),
          file_name: fileName.trim(),
          extra,
        },
      });
      toast.success(`已创建注入任务 #${task.id}`);
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
          <UploadIcon className="h-5 w-5 text-muted-foreground" />
          <h1 className="text-xl font-semibold tracking-tight">Webshell 注入</h1>
          <Badge variant="secondary">{total}</Badge>
          {running && (
            <span className="flex items-center gap-1 text-xs text-muted-foreground">
              <Loader2Icon className="size-3 animate-spin" />
              注入中
            </span>
          )}
        </div>
        <Button onClick={openCreate}>
          <PlayIcon className="size-4" />
          新建注入
        </Button>
      </div>

      <p className="text-sm text-muted-foreground">
        向目标上传 webshell 并验证落地地址；注入成功的 shell 会自动登记到 Webshell 管理，便于后续存活检测与命令执行。
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
          emptyHint="还没有注入任务，点击右上角「新建注入」开始。"
        />
      )}

      <Sheet open={createOpen} onOpenChange={setCreateOpen}>
        <SheetContent className="flex flex-col gap-4 overflow-y-auto sm:max-w-lg">
          <SheetHeader>
            <SheetTitle>新建 Webshell 注入</SheetTitle>
            <SheetDescription>上传 webshell 并验证落地地址</SheetDescription>
          </SheetHeader>

          <TaskFormShell onSubmit={submit} submitting={submitting} submitLabel="开始注入">
            <FieldRow label="上传地址" hint="接收上传请求的接口地址">
              <Input
                value={uploadUrl}
                onChange={(e) => setUploadUrl(e.target.value)}
                placeholder="http://example.com/upload.php"
              />
            </FieldRow>
            <FieldRow label="落地地址" hint="上传后 webshell 的实际访问地址，留空则跳过存活验证">
              <Input
                value={landUrl}
                onChange={(e) => setLandUrl(e.target.value)}
                placeholder="http://example.com/uploads/shell.php"
              />
            </FieldRow>
            <FieldRow label="Shell 类型">
              <Select value={shellType} onValueChange={setShellType}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {SHELL_TYPES.map((s) => (
                    <SelectItem key={s.value} value={s.value}>
                      {s.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </FieldRow>
            <FieldRow label="密码" hint="webshell 的访问口令，留空则不校验口令">
              <Input value={password} onChange={(e) => setPassword(e.target.value)} placeholder="可留空" />
            </FieldRow>
            <FieldRow label="上传字段名" hint="multipart 表单的字段名，留空则以原始请求体发送">
              <Input value={fieldName} onChange={(e) => setFieldName(e.target.value)} placeholder="file" />
            </FieldRow>
            <FieldRow label="文件名" hint="留空则自动生成">
              <Input value={fileName} onChange={(e) => setFileName(e.target.value)} placeholder="shell.php" />
            </FieldRow>
            <FieldRow label="附加字段" hint="额外的表单字段，例如提交表单名">
              <div className="flex gap-2">
                <Input value={extraField} onChange={(e) => setExtraField(e.target.value)} placeholder="字段名" />
                <Input value={extraValue} onChange={(e) => setExtraValue(e.target.value)} placeholder="字段值" />
              </div>
            </FieldRow>
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
