import { motion } from "framer-motion";
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from "recharts";
import { Activity, ShieldAlert, FolderOpen, Clock, Radio } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { SeverityBadge } from "@/components/ui/severity-badge";
import { useDashboardStats, useTimeline, useTopAttackers, useAlerts, useEvents } from "@/api/hooks";

function StatCard({ label, value, icon: Icon, index }) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: index * 0.05, duration: 0.3 }}
      whileHover={{ y: -2 }}
    >
      <Card className="transition-colors hover:border-primary/40">
        <CardContent className="flex items-center justify-between p-5">
          <div>
            <p className="text-xs text-muted-foreground uppercase tracking-wider font-medium">{label}</p>
            <p className="text-3xl font-bold font-mono mt-1.5 tabular-nums">{value ?? "—"}</p>
          </div>
          <div className="rounded-lg bg-primary/10 p-2.5">
            <Icon className="h-5 w-5 text-primary" />
          </div>
        </CardContent>
      </Card>
    </motion.div>
  );
}

function buildHourlyBuckets(buckets, hours) {
  const byHour = new Map(
    (buckets ?? []).map((b) => [new Date(b.bucket).toISOString().slice(0, 13), b])
  );

  const now = new Date();
  now.setUTCMinutes(0, 0, 0);

  const result = [];
  for (let i = hours - 1; i >= 0; i--) {
    const d = new Date(now.getTime() - i * 3600_000);
    const key = d.toISOString().slice(0, 13);
    const match = byHour.get(key);
    result.push({
      time: d.toLocaleTimeString([], { hour: "2-digit" }),
      events: match?.event_count ?? 0,
      alerts: match?.alert_count ?? 0,
    });
  }
  return result;
}

export default function Dashboard() {
  const { data: stats } = useDashboardStats();
  const { data: timeline } = useTimeline(24);
  const { data: attackers } = useTopAttackers(5);
  const { data: recentAlerts } = useAlerts({ limit: 5 });
  const { data: liveEvents } = useEvents({ limit: 8 }, 5000);

  const chartData = buildHourlyBuckets(timeline?.buckets, 24);
  const hasActivity = chartData.some((d) => d.events > 0 || d.alerts > 0);

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">Dashboard</h1>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard label="Total Events" value={stats?.total_events} icon={Activity} index={0} />
        <StatCard label="Events (24h)" value={stats?.events_last_24h} icon={Clock} index={1} />
        <StatCard label="Open Alerts" value={stats?.open_alerts} icon={ShieldAlert} index={2} />
        <StatCard label="Open Incidents" value={stats?.open_incidents} icon={FolderOpen} index={3} />
      </div>

      {stats?.alerts_by_severity && (
        <div className="flex gap-3 flex-wrap">
          {Object.entries(stats.alerts_by_severity).map(([severity, count]) => (
            <div key={severity} className="flex items-center gap-2">
              <SeverityBadge severity={severity} />
              <span className="text-sm font-mono text-muted-foreground">{count}</span>
            </div>
          ))}
        </div>
      )}

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Activity Timeline (24h)</CardTitle>
        </CardHeader>
        <CardContent className="h-64">
          {!hasActivity ? (
            <div className="h-full flex flex-col items-center justify-center gap-2 text-muted-foreground">
              <Activity className="h-8 w-8 opacity-30" />
              <p className="text-sm">No activity in the last 24 hours</p>
              <p className="text-xs">Ingest logs and run detection to see it here</p>
            </div>
          ) : (
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={chartData} margin={{ top: 8, right: 8, left: -16, bottom: 0 }}>
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
                <XAxis
                  dataKey="time"
                  stroke="hsl(215 16% 47%)"
                  fontSize={11}
                  tickLine={false}
                  axisLine={false}
                  interval="preserveStartEnd"
                  minTickGap={40}
                />
                <YAxis stroke="hsl(215 16% 47%)" fontSize={11} tickLine={false} axisLine={false} allowDecimals={false} width={28} />
                <Tooltip
                  contentStyle={{
                    background: "hsl(216 56% 13%)",
                    border: "1px solid hsl(216 48% 20%)",
                    borderRadius: 8,
                    fontSize: 12,
                  }}
                  labelStyle={{ color: "hsl(214 32% 91%)" }}
                />
                <Area
                  type="monotone"
                  dataKey="events"
                  name="Events"
                  stroke="hsl(190 100% 50%)"
                  strokeWidth={2}
                  fill="url(#eventsGradient)"
                  dot={false}
                  activeDot={{ r: 4 }}
                />
                <Area
                  type="monotone"
                  dataKey="alerts"
                  name="Alerts"
                  stroke="hsl(345 100% 60%)"
                  strokeWidth={2}
                  fill="url(#alertsGradient)"
                  dot={false}
                  activeDot={{ r: 4 }}
                />
              </AreaChart>
            </ResponsiveContainer>
          )}
        </CardContent>
      </Card>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Top Attackers</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            {(attackers?.attackers ?? []).length === 0 && (
              <p className="text-sm text-muted-foreground">No attacker activity yet.</p>
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
                  <p className="truncate">{alert.title}</p>
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
              <span className="uppercase text-muted-foreground w-14 shrink-0">{event.source_type}</span>
              <span className="font-mono">{event.source_ip ?? "—"}</span>
              <span className="text-muted-foreground truncate">{event.action ?? ""}</span>
            </div>
          ))}
        </CardContent>
      </Card>
    </div>
  );
}
