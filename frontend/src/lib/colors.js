// Theme colours for charts. They're full hsl() values in CSS variables, which
// Tailwind can't apply opacity to (bg-cyan/10 generates nothing), so tints go
// through color-mix instead.

export const COLORS = {
  cyan: "var(--cyan)",
  green: "var(--siem-green)",
  amber: "var(--amber)",
  red: "var(--siem-red)",
  purple: "var(--purple)",
  muted: "var(--muted-foreground)",
};

export const SERIES = [COLORS.cyan, COLORS.purple, COLORS.amber, COLORS.green, COLORS.red, "hsl(200 70% 65%)", "hsl(28 95% 60%)", COLORS.muted];

export const SEVERITY_COLORS = {
  low: COLORS.green,
  medium: COLORS.amber,
  high: COLORS.red,
  critical: COLORS.purple,
};

export function tint(color, percent) {
  return `color-mix(in srgb, ${color} ${percent}%, transparent)`;
}
