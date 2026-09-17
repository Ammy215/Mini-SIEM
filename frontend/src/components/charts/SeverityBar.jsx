import { SEVERITY_COLORS } from "@/lib/colors";

const ORDER = ["critical", "high", "medium", "low"];

/**
 * How a count of open alerts splits by severity, as one bar.
 *
 * A stat card that reads "6 open" says nothing about whether that is six
 * low-severity notes or six criticals. Worst-first, so the part that decides
 * what an analyst does next is the part at the left edge.
 */
export function SeverityBar({ counts, height = 5, className }) {
  const entries = ORDER.map((severity) => [severity, counts?.[severity] ?? 0]).filter(([, n]) => n > 0);
  const total = entries.reduce((sum, [, n]) => sum + n, 0);
  if (!total) return <div className={className} style={{ height }} aria-hidden="true" />;

  return (
    <div className={className}>
      <div className="flex overflow-hidden rounded-full" style={{ height }}>
        {entries.map(([severity, n]) => (
          <div
            key={severity}
            style={{ width: `${(n / total) * 100}%`, background: SEVERITY_COLORS[severity] }}
            title={`${n} ${severity}`}
          />
        ))}
      </div>
      <div className="mt-1.5 flex flex-wrap gap-x-3 gap-y-0.5">
        {entries.map(([severity, n]) => (
          <span key={severity} className="flex items-center gap-1 text-[11px] text-muted-foreground">
            <span
              className="h-1.5 w-1.5 rounded-full"
              style={{ background: SEVERITY_COLORS[severity] }}
            />
            <span className="font-mono tabular-nums">{n}</span> {severity}
          </span>
        ))}
      </div>
    </div>
  );
}
