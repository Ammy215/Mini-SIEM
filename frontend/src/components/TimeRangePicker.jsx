import { useState } from "react";
import { useSearchParams } from "react-router-dom";
import { CalendarRange } from "lucide-react";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

const PRESETS = ["1h", "24h", "7d", "30d"];
const MAX_DAYS = 90;
const PRESET_LABELS = { "1h": "last hour", "24h": "last 24 hours", "7d": "last 7 days", "30d": "last 30 days" };

// "2026-09-15T14:30" in local time, for a datetime-local input.
function toLocalInput(iso) {
  if (!iso) return "";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "";
  const pad = (n) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

/** The dashboard's time range, kept in the URL so a view can be bookmarked or shared. */
export function useTimeRange() {
  const [searchParams, setSearchParams] = useSearchParams();
  const from = searchParams.get("from");
  const to = searchParams.get("to");
  const custom = Boolean(from && to);
  const preset = PRESETS.includes(searchParams.get("range")) ? searchParams.get("range") : "24h";

  const update = (changes) =>
    setSearchParams((previous) => {
      const next = new URLSearchParams(previous);
      for (const [key, value] of Object.entries(changes)) {
        if (value == null) next.delete(key);
        else next.set(key, value);
      }
      return next;
    });

  return {
    params: custom ? { from, to } : { range: preset },
    preset: custom ? "custom" : preset,
    from,
    to,
    label: custom
      ? `${new Date(from).toLocaleString()} → ${new Date(to).toLocaleString()}`
      : PRESET_LABELS[preset],
    setPreset: (value) => update({ range: value, from: null, to: null }),
    setCustom: (fromIso, toIso) => update({ range: null, from: fromIso, to: toIso }),
  };
}

export function TimeRangePicker({ range }) {
  const [open, setOpen] = useState(range.preset === "custom");
  const [fromText, setFromText] = useState(toLocalInput(range.from));
  const [toText, setToText] = useState(toLocalInput(range.to));
  const [error, setError] = useState(null);

  const apply = () => {
    const start = new Date(fromText);
    const end = new Date(toText);
    if (Number.isNaN(start.getTime()) || Number.isNaN(end.getTime())) return setError("Pick both dates");
    if (end <= start) return setError("The end must be after the start");
    if (end - start > MAX_DAYS * 86_400_000) return setError(`At most ${MAX_DAYS} days`);
    setError(null);
    range.setCustom(start.toISOString(), end.toISOString());
  };

  const segment = (active) =>
    cn(
      "rounded px-2.5 py-1 text-xs font-mono transition-colors",
      active ? "bg-primary text-primary-foreground" : "text-muted-foreground hover:text-foreground",
    );

  return (
    <div className="flex flex-wrap items-center justify-end gap-2">
      <div className="flex rounded-md border border-border p-0.5" role="group" aria-label="Time range">
        {PRESETS.map((value) => (
          <button key={value} type="button" className={segment(range.preset === value)} onClick={() => range.setPreset(value)}>
            {value}
          </button>
        ))}
        <button type="button" className={cn(segment(range.preset === "custom"), "flex items-center gap-1")} onClick={() => setOpen((o) => !o)}>
          <CalendarRange className="h-3 w-3" /> Custom
        </button>
      </div>
      {open && (
        <div className="flex flex-wrap items-center gap-2">
          <input
            type="datetime-local"
            aria-label="From"
            className="h-8 rounded-md border border-input bg-background px-2 text-xs"
            value={fromText}
            onChange={(e) => setFromText(e.target.value)}
          />
          <span className="text-xs text-muted-foreground">to</span>
          <input
            type="datetime-local"
            aria-label="To"
            className="h-8 rounded-md border border-input bg-background px-2 text-xs"
            value={toText}
            onChange={(e) => setToText(e.target.value)}
          />
          <Button size="sm" variant="outline" onClick={apply}>Apply</Button>
          {error && <span className="text-xs text-destructive">{error}</span>}
        </div>
      )}
    </div>
  );
}
