import { SEVERITY_COLORS, tint } from "@/lib/colors";
import { LogText } from "@/components/LogText";
import { cn } from "@/lib/utils";

const MINUTE = 60_000;

function duration(ms) {
  if (ms < MINUTE) return `${Math.max(1, Math.round(ms / 1000))}s`;
  if (ms < 60 * MINUTE) return `${Math.round(ms / MINUTE)} min`;
  const hours = ms / (60 * MINUTE);
  if (hours < 48) return `${hours.toFixed(hours < 10 ? 1 : 0)} h`;
  return `${Math.round(hours / 24)} days`;
}

const clock = (d) =>
  d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });

/**
 * When each alert in a campaign happened, on one shared scale.
 *
 * An incident is a sequence — a scan, then a brute force, then a success — and
 * a list of alerts sorted by time hides the shape of it: whether they arrived
 * in one burst or were spread across an hour. Each alert is drawn as a bar
 * spanning its own first to last event, positioned across the incident's span.
 */
export function IncidentTimeline({ alerts, onSelect, selectedId }) {
  const spans = alerts
    .map((alert) => {
      const start = new Date(alert.first_event_time ?? alert.created_at).getTime();
      const end = new Date(alert.last_event_time ?? alert.first_event_time ?? alert.created_at).getTime();
      return { alert, start, end: Math.max(end, start) };
    })
    .sort((a, b) => a.start - b.start);

  if (!spans.length) return null;

  const first = Math.min(...spans.map((s) => s.start));
  const last = Math.max(...spans.map((s) => s.end));
  const total = last - first;
  // An instantaneous incident still needs a scale to draw on.
  const scale = total || 1;
  const pct = (t) => ((t - first) / scale) * 100;

  return (
    <div>
      <div className="mb-2 flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1">
        <h4 className="font-mono text-[10px] font-semibold uppercase tracking-[0.14em] text-muted-foreground">
          Timeline
        </h4>
        <p className="font-mono text-[11px] text-muted-foreground">
          {new Date(first).toLocaleDateString()} · {clock(new Date(first))} → {clock(new Date(last))}
          {total > 0 && <span className="text-foreground"> · {duration(total)}</span>}
        </p>
      </div>

      <div className="space-y-1">
        {spans.map(({ alert, start, end }) => {
          const color = SEVERITY_COLORS[alert.severity] ?? SEVERITY_COLORS.low;
          const left = pct(start);
          // Always wide enough to see, even for an alert that fired in a second.
          const width = Math.max(pct(end) - left, 1.6);
          const isSelected = selectedId === alert.id;
          return (
            <button
              type="button"
              key={alert.id}
              onClick={() => onSelect?.(isSelected ? null : alert.id)}
              aria-expanded={isSelected}
              className={cn(
                "group grid w-full grid-cols-[minmax(0,19rem)_1fr] items-center gap-3 rounded px-1.5 py-1 text-left transition-colors",
                isSelected ? "bg-primary/10" : "hover:bg-muted/50",
              )}
            >
              <span className="flex min-w-0 items-center gap-2">
                <span
                  className="h-1.5 w-1.5 shrink-0 rounded-full"
                  style={{ background: color }}
                  aria-hidden="true"
                />
                {/* Start time first: one campaign often repeats the same rule, and
                    identical truncated titles would make the rows indistinguishable. */}
                <span className="shrink-0 font-mono text-[11px] tabular-nums text-muted-foreground">
                  {clock(new Date(start))}
                </span>
                <span className="truncate text-xs">
                  <LogText value={alert.title} />
                </span>
              </span>

              <span className="relative h-5">
                {/* the incident's own span, for the bar to sit against */}
                <span className="absolute inset-x-0 top-1/2 h-px -translate-y-1/2 bg-border" aria-hidden="true" />
                <span
                  className="absolute top-1/2 h-2 -translate-y-1/2 rounded-full transition-[filter]"
                  style={{
                    left: `${left}%`,
                    width: `${width}%`,
                    background: color,
                    boxShadow: isSelected ? `0 0 0 3px ${tint(color, 22)}` : undefined,
                  }}
                  title={`${clock(new Date(start))} → ${clock(new Date(end))}`}
                />
              </span>
            </button>
          );
        })}
      </div>
    </div>
  );
}
