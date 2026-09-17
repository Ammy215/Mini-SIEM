import { lazy, Suspense, useState } from "react";
import { motion } from "framer-motion";
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from "recharts";
import { Activity, ShieldAlert, FolderOpen, Clock, Radio } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { SeverityBadge } from "@/components/ui/severity-badge";
import { LogText } from "@/components/LogText";
import { TimeRangePicker, useTimeRange } from "@/components/TimeRangePicker";
import { DonutChart } from "@/components/charts/DonutChart";
import { MitreMatrix } from "@/components/charts/MitreMatrix";
import { SeverityBar } from "@/components/charts/SeverityBar";
import { Sparkline } from "@/components/charts/Sparkline";
import { COLORS, SEVERITY_COLORS } from "@/lib/colors";
import {
  useAlerts, useBreakdown, useDashboardStats, useEvents, useGeoStats, useMitreCoverage, useTimeline, useTopAttackers,
} from "@/api/hooks";
import { cn } from "@/lib/utils";

// The map and its world outlines load only when the dashboard shows it.
const AttackMap = lazy(() => import("@/components/charts/AttackMap"));

function AttackOrigins({ range }) {
  const [metric, setMetric] = useState("alerts");
  const { data: geo } = useGeoStats(metric, range.params);

  return (
    <Card>
      <CardHeader className="flex-row flex-wrap items-start justify-between gap-2 space-y-0">
        <div className="space-y-1">
          <CardTitle className="text-base">Attack origins <span className="font-normal text-muted-foreground">· {range.label}</span></CardTitle>
          <p className="text-xs text-muted-foreground">By the location of each source IP. Private and internal addresses have none.</p>
        </div>
        <div className="flex w-fit rounded-md border border-border p-0.5" role="group" aria-label="Map shows">
          {["alerts", "events"].map((value) => (
            <button
              key={value}
              type="button"
              onClick={() => setMetric(value)}
              className={cn(
                "rounded px-2.5 py-1 text-xs capitalize transition-colors",
                metric === value ? "bg-primary text-primary-foreground" : "text-muted-foreground hover:text-foreground",
              )}
            >
              {value}
            </button>
          ))}
        </div>
      </CardHeader>
      <CardContent>
        <Suspense fallback={<div className="flex h-72 items-center justify-center text-sm text-muted-foreground">Loading map…</div>}>
          <AttackMap countries={geo?.countries ?? []} metric={metric} />
        </Suspense>
        {geo?.unlocated > 0 && (
          <p className="mt-3 text-xs text-muted-foreground">
            {geo.unlocated.toLocaleString()} {metric} from public IPs with no known location yet — they're looked up in the background.
          </p>
        )}
      </CardContent>
    </Card>
  );
}

// Each card's footer shows what that number actually is: a trend for the two
// counts over the selected range, the severity split for open alerts. Open
// incidents has neither in the API, so it gets no footer rather than a made-up one.
function StatCard({ label, value, icon: Icon, index, hint, accent = COLORS.cyan, children }) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: index * 0.05, duration: 0.3 }}
      className="h-full"
    >
      <Card className="h-full py-0 transition-colors hover:border-primary/40">
        <CardContent className="flex h-full flex-col p-5">
          <div className="flex items-start justify-between gap-3">
            <div className="min-w-0">
              <p className="text-xs font-medium uppercase tracking-wider text-muted-foreground">{label}</p>
              <p className="mt-1.5 font-mono text-3xl font-bold tabular-nums">{value?.toLocaleString() ?? "—"}</p>
              {hint && <p className="mt-0.5 truncate text-xs text-muted-foreground">{hint}</p>}
            </div>
            <Icon className="mt-0.5 h-4 w-4 shrink-0" style={{ color: accent }} />
          </div>
          {children && <div className="mt-auto pt-4">{children}</div>}
        </CardContent>
      </Card>
    </motion.div>
  );
}

function bucketLabel(iso, bucketSeconds, spanMs) {
  const d = new Date(iso);
  if (bucketSeconds >= 86_400) return d.toLocaleDateString([], { month: "short", day: "numeric" });
  if (spanMs > 86_400_000) return d.toLocaleString([], { month: "short", day: "numeric", hour: "2-digit" });
  return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

const tooltipStyle = {
  background: "hsl(216 56% 13%)",
  border: "1px solid hsl(216 48% 20%)",
  borderRadius: 8,
  fontSize: 12,
};

function Timeline({ timeline, label }) {
  const spanMs = timeline ? new Date(timeline.end) - new Date(timeline.start) : 0;
  const data = (timeline?.buckets ?? []).map((b) => ({
    time: bucketLabel(b.bucket, timeline.bucket_seconds, spanMs),
    events: b.event_count,
    alerts: b.alert_count,
  }));
  const hasActivity = data.some((d) => d.events > 0 || d.alerts > 0);

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Activity <span className="font-normal text-muted-foreground">· {label}</span></CardTitle>
      </CardHeader>
      <CardContent className="h-64">
        {!hasActivity ? (
          <div className="h-full flex flex-col items-center justify-center gap-2 text-muted-foreground">
            <Activity className="h-8 w-8 opacity-30" />
            <p className="text-sm">No activity in this range</p>
            <p className="text-xs">Ingest or upload logs to see it here</p>
          </div>
        ) : (
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={data} margin={{ top: 8, right: 8, left: -16, bottom: 0 }}>
              <defs>
                <linearGradient id="eventsGradient" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="hsl(190 100% 50%)" stopOpacity={0.45} />
                  <stop offset="95%" stopColor="hsl(190 100% 50%)" stopOpacity={0.02} />
                </linearGradient>
                <linearGradient id="alertsGradient" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="hsl(345 100% 60%)" stopOpacity={0.45} />
                  <stop offset="95%" stopColor="hsl(345 100% 60%)" stopOpacity={0.02} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 6" stroke="hsl(216 48% 20%)" vertical={false} />
              <XAxis dataKey="time" stroke="hsl(215 16% 47%)" fontSize={11} tickLine={false} axisLine={false} interval="preserveStartEnd" minTickGap={40} />
              <YAxis stroke="hsl(215 16% 47%)" fontSize={11} tickLine={false} axisLine={false} allowDecimals={false} width={32} />
              <Tooltip contentStyle={tooltipStyle} labelStyle={{ color: "hsl(214 32% 91%)" }} />
              <Area type="monotone" dataKey="events" name="Events" stroke="hsl(190 100% 50%)" strokeWidth={2} fill="url(#eventsGradient)" dot={false} activeDot={{ r: 4 }} />
              <Area type="monotone" dataKey="alerts" name="Alerts" stroke="hsl(345 100% 60%)" strokeWidth={2} fill="url(#alertsGradient)" dot={false} activeDot={{ r: 4 }} />
            </AreaChart>
          </ResponsiveContainer>
        )}
      </CardContent>
    </Card>
  );
}

function ChartCard({ title, children }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">{title}</CardTitle>
      </CardHeader>
      <CardContent>{children}</CardContent>
    </Card>
  );
}

export default function Dashboard() {
  const range = useTimeRange();
  const { data: stats } = useDashboardStats(range.params);
  const { data: timeline } = useTimeline(range.params);
  const { data: breakdown } = useBreakdown(range.params);
  const { data: mitre } = useMitreCoverage(range.params);
  const { data: attackers } = useTopAttackers(5, range.params);
  const { data: recentAlerts } = useAlerts({ limit: 5 });
  const { data: liveEvents } = useEvents({ limit: 8 }, 5000);

  const logins = [
    { name: "Failed", value: breakdown?.logins.failed ?? 0, color: COLORS.red },
    { name: "Successful", value: breakdown?.logins.success ?? 0, color: COLORS.green },
  ];
  const sources = (breakdown?.events_by_source ?? []).map((s) => ({ name: s.name, value: s.count }));
  const severities = Object.entries(breakdown?.alerts_by_severity ?? {}).map(([name, value]) => ({
    name, value, color: SEVERITY_COLORS[name],
  }));
  // The same buckets the Activity chart draws, so the card trend and the chart agree.
  const eventSeries = (timeline?.buckets ?? []).map((b) => b.event_count);
  const alertSeries = (timeline?.buckets ?? []).map((b) => b.alert_count);
  const totalTechniques = mitre?.tactics
    ? new Set(mitre.tactics.flatMap((t) => t.techniques.map((tech) => tech.id))).size
    : 0;

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h1 className="text-display text-2xl">Dashboard</h1>
        <TimeRangePicker key={range.preset} range={range} />
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard label="Events" value={stats?.events_in_range} icon={Clock} index={0} hint={range.label}>
          <Sparkline values={eventSeries} color={COLORS.cyan} className="w-full" />
        </StatCard>
        <StatCard label="Alerts" value={stats?.alerts_in_range} icon={Activity} index={1} hint={range.label} accent={COLORS.red}>
          <Sparkline values={alertSeries} color={COLORS.red} className="w-full" />
        </StatCard>
        {/* This bar replaces the old separate "open alerts by severity" row:
            the split belongs on the number it explains. */}
        <StatCard label="Open Alerts" value={stats?.open_alerts} icon={ShieldAlert} index={2} hint="right now" accent={COLORS.amber}>
          <SeverityBar counts={stats?.alerts_by_severity} />
        </StatCard>
        <StatCard label="Open Incidents" value={stats?.open_incidents} icon={FolderOpen} index={3} hint="right now" accent={COLORS.purple} />
      </div>

      <Timeline timeline={timeline} label={range.label} />

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        <ChartCard title="Logins">
          <DonutChart data={logins} emptyText="No logins in this range" />
        </ChartCard>
        <ChartCard title="Events by source">
          <DonutChart data={sources} emptyText="No events in this range" />
        </ChartCard>
        <ChartCard title={`Alerts raised by severity · ${range.label}`}>
          <DonutChart data={severities} emptyText="No alerts in this range" />
        </ChartCard>
      </div>

      <AttackOrigins range={range} />

      <Card>
        <CardHeader className="space-y-1">
          <CardTitle className="text-base">MITRE ATT&amp;CK coverage</CardTitle>
          {mitre && (
            <p className="text-xs text-muted-foreground">
              {mitre.techniques_covered} of {totalTechniques} techniques covered by enabled rules ·{" "}
              {mitre.techniques_with_alerts} with alerts in this range
            </p>
          )}
        </CardHeader>
        <CardContent>
          <MitreMatrix tactics={mitre?.tactics} />
        </CardContent>
      </Card>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Top Attackers <span className="font-normal text-muted-foreground">· {range.label}</span></CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            {(attackers?.attackers ?? []).length === 0 && (
              <p className="text-sm text-muted-foreground">No attacker activity in this range.</p>
            )}
            {(attackers?.attackers ?? []).map((a) => (
              <div key={a.source_ip} className="flex items-center justify-between text-sm py-1.5 border-b border-border last:border-0">
                <span className="font-mono">{a.source_ip}</span>
                <div className="flex items-center gap-3">
                  <span className="text-muted-foreground font-mono">{a.alert_count} alerts</span>
                  <SeverityBadge severity={a.max_severity} />
                </div>
              </div>
            ))}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">Recent Alerts</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            {(recentAlerts?.alerts ?? []).length === 0 && (
              <p className="text-sm text-muted-foreground">No alerts yet.</p>
            )}
            {(recentAlerts?.alerts ?? []).map((alert) => (
              <div key={alert.id} className="flex items-center justify-between text-sm py-1.5 border-b border-border last:border-0">
                <div className="truncate pr-3">
                  <p className="truncate"><LogText value={alert.title} /></p>
                  <p className="text-xs text-muted-foreground font-mono">{alert.mitre_technique}</p>
                </div>
                <SeverityBadge severity={alert.severity} />
              </div>
            ))}
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader className="flex-row items-center justify-between space-y-0">
          <CardTitle className="text-base">Live Feed</CardTitle>
          <span className="flex items-center gap-1.5 text-xs text-siem-green">
            <Radio className="h-3 w-3 animate-pulse" />
            polling every 5s
          </span>
        </CardHeader>
        <CardContent className="space-y-1.5">
          {(liveEvents?.events ?? []).length === 0 && (
            <p className="text-sm text-muted-foreground">No events yet.</p>
          )}
          {(liveEvents?.events ?? []).map((event) => (
            <div key={event.id} className="flex items-center gap-3 text-xs py-1 border-b border-border last:border-0">
              <span className="font-mono text-muted-foreground whitespace-nowrap">
                {new Date(event.event_time).toLocaleTimeString()}
              </span>
              <span className="uppercase text-muted-foreground w-16 shrink-0">{event.source_type}</span>
              <span className="font-mono">{event.source_ip ?? "—"}</span>
              <span className="text-muted-foreground truncate">
                <LogText value={event.action} fallback="" />
              </span>
            </div>
          ))}
        </CardContent>
      </Card>
    </div>
  );
}
