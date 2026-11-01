"use client";

import { useCallback, useEffect, useState } from "react";

import { useRouter } from "next/navigation";

import { JingweiFooter } from "@/components/jingwei-footer";
import { SliderCaptcha } from "@/components/slider-captcha";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { api, type SliderCaptchaChallenge } from "@/lib/api";

export default function SetupPage() {
  const router = useRouter();
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [checking, setChecking] = useState(true);
  const [captcha, setCaptcha] = useState<SliderCaptchaChallenge | null>(null);
  const [captchaX, setCaptchaX] = useState(0);
  const [captchaMoved, setCaptchaMoved] = useState(false);
  const [captchaLoading, setCaptchaLoading] = useState(false);
  // 查不到初始化状态时不能默认当成"未初始化"——那样会把初始化表单摆给一个
  // 其实已经设过密码的实例，用户照着填就会覆盖掉原密码。此时关闭入口。
  const [unavailable, setUnavailable] = useState(false);

  const loadCaptcha = useCallback(async () => {
    setCaptchaLoading(true);
    setCaptchaMoved(false);
    setCaptchaX(0);
    try {
      setCaptcha(await api.authCaptcha());
    } catch (err) {
      setCaptcha(null);
      setError(err instanceof Error ? err.message : "验证码加载失败");
    } finally {
      setCaptchaLoading(false);
    }
  }, []);

  useEffect(() => {
    let cancelled = false;
    api
      .authStatus()
      .then(({ initialized }) => {
        if (initialized) {
          router.replace("/login");
          return;
        }
        void loadCaptcha();
      })
      .catch((err) => {
        setError(err instanceof Error ? err.message : "无法连接到后端服务");
        setUnavailable(true);
      })
      .finally(() => {
        if (!cancelled) setChecking(false);
      });
    return () => {
      cancelled = true;
    };
  }, [router, loadCaptcha]);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (password !== confirm) {
      setError("两次输入的密码不一致");
      return;
    }
    if (password.length < 8) {
      setError("密码长度至少 8 位");
      return;
    }
    if (!captcha) {
      setError("验证码尚未加载，请刷新后重试");
      return;
    }
    if (!captchaMoved) {
      setError("请先拖动滑块完成验证");
      return;
    }
    setLoading(true);
    setError("");
    try {
      await api.initPassword(password, { id: captcha.id, x: captchaX });
      window.location.replace("/function/tasks");
    } catch (err) {
      setError(err instanceof Error ? err.message : "初始化失败");
      // 验证码是一次性的，提交后必须换一张。
      await loadCaptcha();
    } finally {
      setLoading(false);
    }
  }

  if (checking) return null;

  return (
    <div className="flex min-h-dvh">
      {/* Left panel */}
      <div className="hidden flex-col items-center justify-center bg-primary p-12 text-center lg:flex lg:w-1/3">
        <div className="relative flex items-center justify-center">
          <div className="absolute size-80 rounded-full border border-primary-foreground/10" />
          <div className="absolute size-60 rounded-full border border-primary-foreground/15" />
          <div className="absolute size-40 rounded-full border border-primary-foreground/20" />
          {/* eslint-disable-next-line @next/next/no-img-element */}
          <img src="/logo.svg" alt="Jingwei" width={160} height={160} className="relative" />
        </div>
      </div>

      {/* Right panel */}
      <div className="flex w-full flex-col bg-background lg:w-2/3">
        <div className="flex flex-1 items-center justify-center p-8">
          <div className="w-full max-w-md space-y-10 py-16 lg:py-24">
            <div className="space-y-4 text-center">
              <h2 className="text-2xl font-medium tracking-tight">{unavailable ? "无法确认初始化状态" : "初始化密码"}</h2>
              <p className="mx-auto max-w-xl text-muted-foreground">
                {unavailable
                  ? "后端或数据库暂时不可用。为避免覆盖实例上已有的密码，初始化入口已临时关闭——请恢复服务后重试。"
                  : "首次使用 Jingwei（精卫），请为账户设置一个登录密码（至少 8 位）"}
              </p>
            </div>
            {unavailable ? (
              <div className="flex flex-col gap-4">
                {error && <p className="text-center text-sm text-destructive">{error}</p>}
                <Button type="button" className="w-full" onClick={() => window.location.reload()}>
                  重试
                </Button>
              </div>
            ) : (
              <form onSubmit={handleSubmit} className="flex flex-col gap-4">
                <div className="space-y-1.5">
                  <Label htmlFor="password">新密码</Label>
                  <Input
                    id="password"
                    type="password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="至少 8 位"
                    autoFocus
                    autoComplete="new-password"
                  />
                </div>
                <div className="space-y-1.5">
                  <Label htmlFor="confirm">确认密码</Label>
                  <Input
                    id="confirm"
                    type="password"
                    value={confirm}
                    onChange={(e) => setConfirm(e.target.value)}
                    placeholder="再次输入密码"
                    autoComplete="new-password"
                  />
                </div>
                <div className="space-y-1.5">
                  <Label>安全验证</Label>
                  <SliderCaptcha
                    challenge={captcha}
                    value={captchaX}
                    onValueChange={setCaptchaX}
                    onInteract={() => setCaptchaMoved(true)}
                    onRefresh={() => {
                      setError("");
                      void loadCaptcha();
                    }}
                    disabled={loading}
                    refreshing={captchaLoading}
                  />
                </div>
                {error && <p className="text-sm text-destructive">{error}</p>}
                <Button
                  type="submit"
                  className="w-full"
                  disabled={loading || !password || !confirm || !captcha || !captchaMoved}
                >
                  {loading ? "保存中..." : "设置密码并登录"}
                </Button>
              </form>
            )}
          </div>
        </div>
        <JingweiFooter className="shrink-0 px-8 pb-6" />
      </div>
    </div>
  );
}
