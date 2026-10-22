import { cn } from "@/lib/utils";

export function JingweiFooter({ className }: { className?: string }) {
  return (
    <footer className={cn("text-center leading-relaxed text-muted-foreground", className)}>
      <p className="text-xs font-medium text-foreground/80">🛡️ Jingwei — 精卫填海，虽微木，终将沧海填平</p>
      <p className="mt-1 text-xs">Built with ❤️ by Domren · 持续不懈地消除安全隐患</p>
      <p className="mt-1.5 text-[11px] text-muted-foreground/70">
        Copyright © 2026 Jingwei Team · 基于 ARTEX 项目二次开发 · AGPL-3.0
      </p>
    </footer>
  );
}
