import { useMemo, useState } from "react";
import { geoNaturalEarth1, geoPath } from "d3-geo";
import { feature } from "topojson-client";
// Bundled with the app (no CDN): world outlines at 1:110m, ~100 KB.
import world from "world-atlas/countries-110m.json";
import { COLORS, SEVERITY_COLORS, tint } from "@/lib/colors";
import { alpha2ForFeature, countryName } from "@/lib/countryCodes";

const WIDTH = 960;
// Fitting the whole sphere left a quarter of the card as empty ocean and
// Antarctica. The extent below stops at 58°S — south of every populated place
// a source IP resolves to — and the shorter box is what removes the dead space.
const HEIGHT = 380;
const LAND = "hsl(216 48% 15%)";
const BORDER = "hsl(216 48% 24%)";

const INHABITED = {
  type: "Polygon",
  coordinates: [[[-180, 84], [180, 84], [180, -58], [-180, -58], [-180, 84]]],
};

const projection = geoNaturalEarth1().fitExtent([[8, 6], [WIDTH - 8, HEIGHT - 6]], INHABITED);
const path = geoPath(projection);

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
    // One surface: the map at a fixed height, and the country list in the width
    // the map no longer needs. An overlay list hid East Asia and Australia; a
    // separate column left the map narrow and the column mostly empty.
    <div className="flex flex-col overflow-hidden rounded-lg border border-border/60 bg-[hsl(217_68%_7%)] sm:h-[21rem] sm:flex-row">
      <div className="relative flex min-w-0 flex-1 items-center justify-center p-2">
        <svg
          viewBox={`0 0 ${WIDTH} ${HEIGHT}`}
          className="h-auto w-full sm:h-full"
          role="img"
          aria-label={`Attack map: ${metric} by source country`}
        >
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
                style={{
                  fill: tint(color, hovered === shape.code ? 75 : 55),
                  stroke: color,
                  strokeWidth: hovered === shape.code ? 2 : 1,
                }}
                onMouseEnter={() => setHovered(shape.code)}
                onMouseLeave={() => setHovered(null)}
              />
            );
          })}
        </svg>

        {hoveredCountry && (
          <div className="pointer-events-none absolute left-3 top-3 rounded-md border border-border bg-popover/95 px-3 py-2 text-xs shadow-lg">
            <p className="font-medium">
              {countryName(hovered)} <span className="font-mono text-muted-foreground">{hovered}</span>
            </p>
            <p className="font-mono tabular-nums">{hoveredCountry.count.toLocaleString()} {metric}</p>
            {hoveredCountry.max_severity && <p className="text-muted-foreground">worst severity: {hoveredCountry.max_severity}</p>}
          </div>
        )}
      </div>

      <div className="flex shrink-0 flex-col border-t border-border/60 p-3 sm:w-64 sm:border-l sm:border-t-0">
        <div className="mb-2 flex items-baseline justify-between">
          <p className="font-mono text-[10px] uppercase tracking-[0.14em] text-muted-foreground">Top countries</p>
          {countries.length > 0 && (
            <p className="font-mono text-[10px] text-muted-foreground">{metric}</p>
          )}
        </div>
        {countries.length === 0 ? (
          <p className="text-xs text-muted-foreground">No located {metric} in this range.</p>
        ) : (
          <div className="min-h-0 flex-1 space-y-px overflow-y-auto">
            {countries.slice(0, 12).map((c) => {
              const color = bubbleColor(c);
              return (
                <button
                  type="button"
                  key={c.country}
                  onMouseEnter={() => setHovered(c.country)}
                  onMouseLeave={() => setHovered(null)}
                  onFocus={() => setHovered(c.country)}
                  onBlur={() => setHovered(null)}
                  className={`flex w-full items-center gap-2 rounded px-1.5 py-1.5 text-left text-xs transition-colors ${
                    hovered === c.country ? "bg-primary/10" : "hover:bg-muted/60"
                  }`}
                >
                  <span className="h-1.5 w-1.5 shrink-0 rounded-full" style={{ background: color }} aria-hidden="true" />
                  <span className="min-w-0 flex-1 truncate">
                    {countryName(c.country)}{" "}
                    <span className="font-mono text-[10px] text-muted-foreground">{c.country}</span>
                    {!ON_MAP.has(c.country) && (
                      <span className="ml-1 text-[10px] text-muted-foreground">(too small to shade)</span>
                    )}
                  </span>
                  <span className="font-mono text-[11px] tabular-nums">{c.count.toLocaleString()}</span>
                </button>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
