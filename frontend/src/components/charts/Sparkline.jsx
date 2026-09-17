import { useId } from "react";
import { tint } from "@/lib/colors";

/**
 * The shape of a series, at stat-card size: no axes, no ticks, no tooltip —
 * just whether the number on the card has been climbing or flat, and where it
 * stands now. The last point is marked because "right now" is the part a stat
 * card is answering.
 */
export function Sparkline({ values, color, height = 34, className }) {
  const gradientId = useId();
  const points = values ?? [];

  // Fewer than two readings can't show a direction, and a flat run of zeros
  // would draw a misleading baseline — say nothing instead.
  if (points.length < 2 || points.every((v) => v === 0)) {
    return <div className={className} style={{ height }} aria-hidden="true" />;
  }

  const max = Math.max(...points);
  const min = Math.min(...points);
  const span = max - min || 1;
  const w = 100;
  const pad = 3;
  const usable = height - pad * 2;
  const x = (i) => (i / (points.length - 1)) * w;
  const y = (v) => pad + usable - ((v - min) / span) * usable;

  const line = points.map((v, i) => `${i === 0 ? "M" : "L"}${x(i).toFixed(2)},${y(v).toFixed(2)}`).join(" ");
  const area = `${line} L${w},${height} L0,${height} Z`;
  const lastX = x(points.length - 1);
  const lastY = y(points[points.length - 1]);

  return (
    // The end marker is HTML, not an SVG circle: preserveAspectRatio="none"
    // stretches circles into smears, and vectorEffect only protects strokes.
    <div className={`relative ${className ?? ""}`} style={{ height }} aria-hidden="true">
      <svg viewBox={`0 0 ${w} ${height}`} preserveAspectRatio="none" className="h-full w-full">
        <defs>
          <linearGradient id={gradientId} x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor={color} stopOpacity="0.28" />
            <stop offset="100%" stopColor={color} stopOpacity="0" />
          </linearGradient>
        </defs>
        <path d={area} fill={`url(#${gradientId})`} />
        {/* vectorEffect keeps the stroke 1.5px after preserveAspectRatio stretches
            the 100-unit viewBox across whatever width the card gives it */}
        <path
          d={line}
          fill="none"
          stroke={color}
          strokeWidth="1.5"
          strokeLinecap="round"
          strokeLinejoin="round"
          vectorEffect="non-scaling-stroke"
        />
      </svg>
      <span
        className="absolute h-2 w-2 -translate-x-1/2 -translate-y-1/2 rounded-full"
        style={{
          left: `${(lastX / w) * 100}%`,
          top: `${(lastY / height) * 100}%`,
          background: color,
          boxShadow: `0 0 0 3px ${tint(color, 25)}`,
        }}
      />
    </div>
  );
}
