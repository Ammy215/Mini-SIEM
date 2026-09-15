import { COLORS, tint } from "@/lib/colors";

function TechniqueCell({ technique }) {
  const alerted = technique.alert_count > 0;
  const covered = technique.enabled_rules > 0;
  const style = alerted
    ? { borderColor: tint(COLORS.red, 60), background: tint(COLORS.red, Math.min(12 + technique.alert_count * 4, 35)) }
    : covered
      ? { borderColor: tint(COLORS.cyan, 40), background: tint(COLORS.cyan, 6) }
      : undefined;

  return (
    <div
      className={`rounded-md border p-2 text-xs ${alerted || covered ? "" : "border-border opacity-50"}`}
      style={style}
      title={`${technique.id} ${technique.name}\n${technique.enabled_rules} enabled rule(s) · ${technique.alert_count} alert(s) in this range`}
    >
      <p className="font-mono text-[11px] text-muted-foreground">{technique.id}</p>
      <p className="leading-snug">{technique.name}</p>
      <p className="mt-1 font-mono text-[11px] tabular-nums">
        {alerted ? (
          <span className="text-siem-red">
            {technique.alert_count} {technique.alert_count === 1 ? "alert" : "alerts"}
          </span>
        ) : covered ? (
          <span className="text-muted-foreground">{technique.enabled_rules} {technique.enabled_rules === 1 ? "rule" : "rules"}</span>
        ) : (
          <span className="text-muted-foreground">no enabled rule</span>
        )}
      </p>
    </div>
  );
}

/** ATT&CK techniques by tactic, left to right in the matrix's order. */
export function MitreMatrix({ tactics }) {
  if (!tactics?.length) return <p className="text-sm text-muted-foreground">No techniques to show.</p>;
  return (
    <div className="overflow-x-auto pb-1">
      <div className="grid gap-3" style={{ gridTemplateColumns: `repeat(${tactics.length}, minmax(9.5rem, 1fr))` }}>
        {tactics.map((tactic) => (
          <div key={tactic.tactic} className="space-y-2">
            <p className="min-h-8 border-b border-border pb-1 text-[11px] font-semibold uppercase tracking-wide text-muted-foreground">
              {tactic.tactic}
            </p>
            {tactic.techniques.map((technique) => (
              <TechniqueCell key={`${tactic.tactic}-${technique.id}`} technique={technique} />
            ))}
          </div>
        ))}
      </div>
    </div>
  );
}
