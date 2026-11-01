"use client";

import { RefreshCw } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Slider } from "@/components/ui/slider";
import type { SliderCaptchaChallenge } from "@/lib/api";
import { cn } from "@/lib/utils";

export function SliderCaptcha({
  challenge,
  value,
  onValueChange,
  onInteract,
  onRefresh,
  disabled,
  refreshing,
}: {
  readonly challenge: SliderCaptchaChallenge | null;
  readonly value: number;
  readonly onValueChange: (value: number) => void;
  readonly onInteract: () => void;
  readonly onRefresh: () => void;
  readonly disabled?: boolean;
  readonly refreshing?: boolean;
}) {
  const pieceWidth = challenge ? (challenge.piece_size / challenge.width) * 100 : 0;
  const maxX = challenge?.max_x ?? 100;
  const ratio = challenge ? Math.min(1, Math.max(0, value / maxX)) : 0;

  return (
    <div className="space-y-2">
      <div
        className={cn(
          "relative overflow-hidden rounded-lg border bg-muted",
          challenge ? "aspect-[2/1]" : "flex aspect-[2/1] items-center justify-center",
        )}
      >
        {challenge ? (
          <>
            {/* eslint-disable-next-line @next/next/no-img-element */}
            <img
              src={challenge.background}
              alt="滑块验证码背景"
              className="block h-full w-full select-none"
              draggable={false}
            />
            {/* eslint-disable-next-line @next/next/no-img-element */}
            <img
              src={challenge.piece}
              alt=""
              aria-hidden="true"
              className="pointer-events-none absolute select-none drop-shadow-md"
              draggable={false}
              style={{
                width: `${pieceWidth}%`,
                top: `${(challenge.piece_y / challenge.height) * 100}%`,
                left: `calc((100% - ${pieceWidth}%) * ${ratio})`,
              }}
            />
            <span className="absolute right-2 bottom-2 rounded bg-black/35 px-1.5 py-0.5 text-[10px] text-white/80">
              拖动下方滑块对齐缺口
            </span>
          </>
        ) : (
          <span className="text-sm text-muted-foreground">正在加载验证码…</span>
        )}
      </div>
      <div className="flex items-center gap-3">
        <Slider
          aria-label="滑块验证码"
          value={[value]}
          max={maxX}
          step={1}
          disabled={challenge ? Boolean(disabled) : true}
          onValueChange={([next]) => {
            onInteract();
            onValueChange(next ?? 0);
          }}
          className="flex-1"
        />
        <Button
          type="button"
          variant="ghost"
          size="icon"
          onClick={onRefresh}
          disabled={refreshing}
          aria-label="换一张验证码"
          title="换一张"
        >
          <RefreshCw className={cn("size-4", refreshing && "animate-spin")} />
        </Button>
      </div>
    </div>
  );
}
