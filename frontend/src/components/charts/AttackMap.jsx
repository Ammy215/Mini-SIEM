import { useMemo, useState } from "react";
import { geoNaturalEarth1, geoPath } from "d3-geo";
import { feature } from "topojson-client";
// Bundled with the app (no CDN): world outlines at 1:110m, ~100 KB.
import world from "world-atlas/countries-110m.json";
import { COLORS, SEVERITY_COLORS, tint } from "@/lib/colors";
import { alpha2ForFeature, countryName } from "@/lib/countryCodes";

const WIDTH = 960;
const HEIGHT = 480;
const LAND = "hsl(216 48% 15%)";
const BORDER = "hsl(216 48% 24%)";

const projection = geoNaturalEarth1().fitExtent([[8, 8], [WIDTH - 8, HEIGHT - 8]], { type: "Sphere" });
const path = geoPath(projection);
const SPHERE = path({ type: "Sphere" });

// Where a country's bubble goes: the middle of its largest landmass, so the US
// bubble sits on the mainland instead of being pulled toward Alaska.
function anchor(shape) {
  if (shape.geometry.type !== "MultiPolygon") return path.centroid(shape);
  let largest = null;
  let largestArea = -1;
  for (const coordinates of shape.geometry.coordinates) {
    const polygon = { type: "Polygon", coordinates };
    const area = path.area(polygon);
    if (area > largestArea) {
      largestArea = area;
      largest = polygon;
    }
  }
  return path.centroid(largest);
}

const SHAPES = feature(world, world.objects.countries).features.map((shape) => ({
  code: alpha2ForFeature(shape),
  d: path(shape),
  anchor: anchor(shape),
}));
const ON_MAP = new Set(SHAPES.map((s) => s.code).filter(Boolean));

export default function AttackMap({ countries, metric }) {
  const [hovered, setHovered] = useState(null);
  const byCode = useMemo(() => new Map(countries.map((c) => [c.country, c])), [countries]);
  const max = Math.max(1, ...countries.map((c) => c.count));
  const accent = metric === "alerts" ? COLORS.red : COLORS.cyan;
  const share = (count) => Math.sqrt(count / max);
  const bubbleColor = (c) => (metric === "alerts" && c.max_severity ? SEVERITY_COLORS[c.max_severity] : COLORS.cyan);
  const hoveredCountry = hovered ? byCode.get(hovered) : null;

  return (
    <div className="grid gap-4 lg:grid-cols-[minmax(0,3fr)_minmax(12rem,1fr)]">
      <div className="relative">
        <svg viewBox={`0 0 ${WIDTH} ${HEIGHT}`} className="h-auto w-full" role="img" aria-label={`Attack map: ${metric} by source country`}>
          <path d={SPHERE} style={{ fill: "hsl(217 68% 7%)", stroke: "hsl(216 48% 20%)" }} />
          {SHAPES.map((shape, i) => {
            const c = shape.code ? byCode.get(shape.code) : null;
            return (
              <path
                key={i}
                d={shape.d}
                style={{ fill: c ? tint(accent, 25 + 55 * share(c.count)) : LAND, stroke: BORDER, strokeWidth: 0.5 }}
                onMouseEnter={() => c && setHovered(shape.code)}
                onMouseLeave={() => setHovered(null)}
              />
            );
          })}
          {SHAPES.filter((shape) => shape.code && byCode.has(shape.code)).map((shape) => {
            const c = byCode.get(shape.code);
            const color = bubbleColor(c);
            return (
              <circle
                key={`bubble-${shape.code}`}
                cx={shape.anchor[0]}
                cy={shape.anchor[1]}
                r={3 + 13 * share(c.count)}
                style={{ fill: tint(color, 55), stroke: color, strokeWidth: 1 }}
                onMouseEnter={() => setHovered(shape.code)}
                onMouseLeave={() => setHovered(null)}
              />
            );
          })}
        </svg>
        {hoveredCountry && (
          <div className="pointer-events-none absolute left-2 top-2 rounded-md border border-border bg-popover px-3 py-2 text-xs shadow">
            <p className="font-medium">
              {countryName(hovered)} <span className="font-mono text-muted-foreground">{hovered}</span>
            </p>
            <p className="font-mono tabular-nums">{hoveredCountry.count.toLocaleString()} {metric}</p>
            {hoveredCountry.max_severity && <p className="text-muted-foreground">worst severity: {hoveredCountry.max_severity}</p>}
          </div>
        )}
      </div>

      <div className="space-y-1 text-sm">
        <p className="text-xs uppercase tracking-wide text-muted-foreground">Top countries</p>
        {countries.length === 0 && <p className="text-muted-foreground">No located {metric} in this range.</p>}
        {countries.slice(0, 12).map((c) => (
          <div
            key={c.country}
            className="flex items-center justify-between gap-2 border-b border-border py-1 last:border-0"
            onMouseEnter={() => setHovered(c.country)}
            onMouseLeave={() => setHovered(null)}
          >
            <span className="min-w-0 truncate">
              {countryName(c.country)} <span className="font-mono text-xs text-muted-foreground">{c.country}</span>
              {!ON_MAP.has(c.country) && <span className="ml-1 text-[10px] text-muted-foreground">(too small for the map)</span>}
            </span>
            <span className="font-mono tabular-nums">{c.count.toLocaleString()}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
