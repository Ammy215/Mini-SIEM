import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip } from "recharts";
import { SERIES } from "@/lib/colors";

const tooltipStyle = {
  background: "hsl(216 56% 13%)",
  border: "1px solid hsl(216 48% 20%)",
  borderRadius: 8,
  fontSize: 12,
};

/** data: [{ name, value, color? }] */
export function DonutChart({ data, emptyText = "Nothing in this range" }) {
  const slices = data.filter((d) => d.value > 0);
  const total = slices.reduce((sum, d) => sum + d.value, 0);

  if (total === 0) {
    return <div className="flex h-36 items-center justify-center text-sm text-muted-foreground">{emptyText}</div>;
  }

  const colorOf = (d, i) => d.color ?? SERIES[i % SERIES.length];

  return (
    <div className="flex items-center gap-4">
      <div className="relative h-36 w-36 shrink-0">
        <div className="h-full w-full">
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie data={slices} dataKey="value" nameKey="name" innerRadius="64%" outerRadius="100%" paddingAngle={2} stroke="none" isAnimationActive={false}>
                {/* recharts gives each slice an image role, and an image with no
                    text alternative is a failure even when the list beside it says
                    the same thing. Naming each slice costs nothing and reads well. */}
                {slices.map((d, i) => (
                  <Cell key={d.name} fill={colorOf(d, i)} aria-label={`${d.name}: ${d.value}`} />
                ))}
              </Pie>
              <Tooltip contentStyle={tooltipStyle} itemStyle={{ color: "hsl(214 32% 91%)" }} />
            </PieChart>
          </ResponsiveContainer>
        </div>
        <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
          <span className="font-mono text-lg font-bold tabular-nums">{total.toLocaleString()}</span>
          <span className="text-[10px] uppercase tracking-wide text-muted-foreground">total</span>
        </div>
      </div>
      <ul className="min-w-0 flex-1 space-y-1.5 text-xs">
        {slices.map((d, i) => (
          <li key={d.name} className="flex items-center justify-between gap-2">
            <span className="flex min-w-0 items-center gap-1.5">
              <span className="h-2 w-2 shrink-0 rounded-full" style={{ background: colorOf(d, i) }} />
              <span className="truncate">{d.name}</span>
            </span>
            <span className="whitespace-nowrap font-mono tabular-nums text-muted-foreground">
              {d.value.toLocaleString()} · {Math.round((d.value / total) * 100)}%
            </span>
          </li>
        ))}
      </ul>
    </div>
  );
}
