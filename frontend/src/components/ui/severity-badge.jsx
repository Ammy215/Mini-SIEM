import { cn } from "@/lib/utils";

const STYLES = {
  low: "bg-siem-green/15 text-siem-green border-siem-green/30",
  medium: "bg-amber/15 text-amber border-amber/30",
  high: "bg-siem-red/15 text-siem-red border-siem-red/30",
  critical: "bg-siem-red/20 text-siem-red border-siem-red/40 animate-pulse-critical",
};

const FALLBACK = "bg-muted text-muted-foreground border-border";

export function SeverityBadge({ severity, className }) {
  const style = STYLES[severity] ?? FALLBACK;
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-mono font-medium uppercase tracking-wide",
        style,
        className
      )}
    >
      {severity ?? "unknown"}
    </span>
  );
}
