import { useAlert } from "@/api/hooks";
import { LogText } from "@/components/LogText";
import { SeverityBadge } from "@/components/ui/severity-badge";

// What each signal means, in an analyst's words. A signal the UI doesn't know
// is shown as its raw key rather than hidden, so a new rule's signal still
// appears the day it ships.
const SIGNAL_LABELS = {
  known_bad_ip: "Known bad IP — AbuseIPDB score over the threshold",
  otx_pulse_match: "Reported in OTX threat pulses",
  foreign_geo: "Source country is not a home country",
  after_hours: "Happened outside business hours",
  brute_force_confirmed: "Repeated failed logins from one IP",
  credential_stuffing: "Many usernames tried from one IP",
  password_spray_confirmed: "One username tried from many IPs",
  brute_force_success: "A login succeeded after repeated failures",
  port_scan: "Many destination ports touched from one IP",
  host_sweep: "Many destination hosts touched from one IP",
  sqli_pattern: "SQL injection pattern in the request",
  xss_pattern: "Cross-site scripting pattern in the request",
  path_traversal: "Path traversal pattern in the request",
  scanner_user_agent: "Scanner tool named in the user agent",
  account_created: "A Windows account was created",
  privileged_logon: "A privileged logon",
  audit_log_cleared: "An event log was cleared",
  admin_group_change: "An account was added to a privileged group",
};

// enrichment_observed holds exactly what the providers said, so name the
// provider each value came from rather than showing bare keys.
const OBSERVED_ROWS = [
  ["abuse_confidence_score", "AbuseIPDB", "Abuse confidence", (v) => `${v} / 100`],
  ["is_whitelisted", "AbuseIPDB", "Whitelisted infrastructure", (v) => (v ? "yes" : "no")],
  ["country", "Location", "Country", (v) => String(v)],
  ["otx_pulse_count", "OTX", "Threat pulses", (v) => String(v)],
];

// Threshold and signature rules write these; each is the count or the sample
// that made the rule fire.
const TRIGGER_ROWS = [
  ["failed_count", "Failed logins"],
  ["distinct_usernames", "Distinct usernames"],
  ["distinct_ports", "Distinct ports"],
  ["distinct_ips", "Distinct source IPs"],
  ["distinct_hosts", "Distinct hosts"],
  ["hit_count", "Matching requests"],
  ["field", "Matched field"],
  ["value_snippet", "Matched value"],
  ["matched_patterns", "Matched patterns"],
  ["usernames", "Usernames"],
  ["ports", "Ports"],
  ["source_ips", "Source IPs"],
  ["username", "Username"],
];

const time = (v) => (v ? new Date(v).toLocaleString() : null);

function Row({ label, hint, children }) {
  return (
    <div className="grid grid-cols-[minmax(8.5rem,auto)_1fr] gap-x-3 gap-y-0.5 py-1 items-baseline">
      <dt className="text-xs text-muted-foreground">
        {label}
        {hint && <span className="ml-1.5 text-[10px] uppercase tracking-wide opacity-70">{hint}</span>}
      </dt>
      <dd className="text-sm font-mono tabular-nums break-words">{children}</dd>
    </div>
  );
}

// `min-w-0` matters: a grid item defaults to min-width:auto, which lets a long
// note push past the card's edge instead of wrapping inside its column.
function Section({ title, children, notes }) {
  return (
    <section className="space-y-0.5 min-w-0">
      <h4 className="text-[10px] font-semibold uppercase tracking-[0.14em] text-muted-foreground mb-1.5">
        {title}
      </h4>
      <dl>{children}</dl>
      {notes}
    </section>
  );
}

function listValue(value) {
  if (!Array.isArray(value)) return <LogText value={String(value)} />;
  if (value.length === 0) return "—";
  return value.map((item, i) => (
    <span key={i}>
      {i > 0 && <span className="text-muted-foreground">, </span>}
      <LogText value={String(item)} />
    </span>
  ));
}

export function AlertEvidence({ alert }) {
  const { data, isLoading, isError } = useAlert(alert.id);

  if (isLoading) {
    return <p className="text-xs text-muted-foreground">Loading evidence…</p>;
  }
  if (isError || !data) {
    return <p className="text-xs text-destructive">Could not load this alert&apos;s evidence.</p>;
  }

  const e = data.evidence ?? {};
  const score = data.threat_score ?? 0;
  const base = e.enrichment_base_score;
  const bonus = base == null ? null : score - base;

  const signals = e.enrichment_signals ?? [];
  const contextSignals = e.context_signals ?? [];
  const suppressed = e.enrichment_suppressed ?? [];
  const skipped = [...(e.context_skipped ?? []), ...(e.enrichment_context_skipped ?? [])];
  const observed = e.enrichment_observed ?? {};
  const pending = e.enrichment_pending_providers ?? [];
  const unconfigured = e.enrichment_unconfigured ?? [];

  const observedRows = OBSERVED_ROWS.filter(
    ([key]) => observed[key] !== undefined && observed[key] !== null,
  );
  const triggerRows = TRIGGER_ROWS.filter(
    ([key]) => e[key] !== undefined && e[key] !== null && !(Array.isArray(e[key]) && !e[key].length),
  );
  const eventIds = e.event_ids ?? [];
  const firstSeen = time(e.first_seen ?? data.first_event_time);
  const lastSeen = time(e.last_seen ?? data.last_event_time);

  const enrichmentRan = signals.length || observedRows.length || pending.length
    || suppressed.length || unconfigured.length || e.enrichment_skipped_reason;

  return (
    // `whitespace-normal` resets the `whitespace-nowrap` every TableCell sets:
    // inherited here it stops prose from wrapping, pushing it past the card.
    <div className="rounded-md border border-border bg-card/60 p-3 space-y-4 whitespace-normal">
      <div className="flex items-baseline justify-between gap-3 flex-wrap">
        <h3 className="text-xs font-semibold uppercase tracking-[0.14em] text-primary">Evidence</h3>
        <span className="text-[11px] text-muted-foreground">
          Everything the detection engine recorded for this alert.
        </span>
      </div>

      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {/* ---------------------------------------------- why this score */}
        <Section title="Why this score">
          {bonus == null ? (
            <Row label="Threat score">
              {score} <SeverityBadge severity={data.severity} />
            </Row>
          ) : (
            <>
              <Row label="From the rule">{base}</Row>
              <Row label="From threat intel">{bonus > 0 ? `+${bonus}` : bonus}</Row>
              <Row label="Total">
                <span className="font-semibold">{score}</span>{" "}
                <SeverityBadge severity={data.severity} />
              </Row>
            </>
          )}
          {data.mitre_technique && <Row label="MITRE">{data.mitre_technique}</Row>}
        </Section>

        {/* ---------------------------------------------- what triggered it */}
        <Section
          title="What triggered it"
          notes={
            !triggerRows.length && !eventIds.length && !firstSeen ? (
              <p className="text-xs text-muted-foreground">No rule evidence recorded.</p>
            ) : null
          }
        >
          {triggerRows.map(([key, label]) => (
            <Row key={key} label={label}>{listValue(e[key])}</Row>
          ))}
          {firstSeen && <Row label="First seen">{firstSeen}</Row>}
          {lastSeen && <Row label="Last seen">{lastSeen}</Row>}
          {eventIds.length > 0 && (
            <Row label="Events">
              {eventIds.length}
              <span className="text-muted-foreground text-xs">
                {" "}({eventIds.length > 4
                  ? `${eventIds.slice(0, 2).join(", ")} … ${eventIds[eventIds.length - 1]}`
                  : eventIds.join(", ")})
              </span>
            </Row>
          )}
        </Section>

        {/* ---------------------------------------------- threat intel */}
        <Section
          title="Threat intelligence"
          notes={
            <div className="space-y-1 mt-1">
              {!enrichmentRan && (
                <p className="text-xs text-muted-foreground">Not enriched yet.</p>
              )}
              {e.enrichment_skipped_reason && (
                <p className="text-xs text-muted-foreground">
                  Skipped — {e.enrichment_skipped_reason.replace(/_/g, " ")}.
                </p>
              )}
              {pending.length > 0 && (
                <p className="text-xs text-amber">
                  Still waiting on {pending.join(", ")}
                  {e.enrichment_attempts ? ` (attempt ${e.enrichment_attempts})` : ""} — the
                  signals below are from the providers that did answer.
                </p>
              )}
              {unconfigured.length > 0 && (
                <p className="text-xs text-muted-foreground">
                  No API key for {unconfigured.join(", ")}.
                </p>
              )}
            </div>
          }
        >
          {observedRows.map(([key, provider, label, fmt]) => (
            <Row key={key} label={label} hint={provider}>{fmt(observed[key])}</Row>
          ))}
        </Section>
      </div>

      {/* ---------------------------------------------- signals */}
      {(signals.length > 0 || contextSignals.length > 0) && (
        <div>
          <h4 className="text-[10px] font-semibold uppercase tracking-[0.14em] text-muted-foreground mb-1.5">
            Signals that added to the score
          </h4>
          <ul className="space-y-1">
            {[...contextSignals, ...signals].map((signal) => (
              <li key={signal} className="flex items-baseline gap-2 text-sm">
                <span className="mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full bg-siem-red" />
                <span className="font-mono text-xs">{signal}</span>
                <span className="text-muted-foreground text-xs">
                  {SIGNAL_LABELS[signal] ?? ""}
                </span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* ---------------------------------------------- what did NOT count */}
      {(suppressed.length > 0 || skipped.length > 0) && (
        <div>
          <h4 className="text-[10px] font-semibold uppercase tracking-[0.14em] text-muted-foreground mb-1.5">
            Considered and not counted
          </h4>
          <ul className="space-y-1">
            {[...suppressed, ...skipped].map((reason, i) => (
              <li key={i} className="flex items-baseline gap-2 text-xs text-muted-foreground">
                <span className="mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full bg-muted-foreground/50" />
                <span>{reason}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
