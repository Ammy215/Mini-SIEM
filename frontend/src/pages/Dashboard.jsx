import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from "recharts";
import { Activity, ShieldAlert, FolderOpen, Clock } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { SeverityBadge } from "@/components/ui/severity-badge";
import { useDashboardStats, useTimeline, useTopAttackers, useAlerts } from "@/api/hooks";

function StatCard({ label, value, icon: Icon }) {
  return (
    <Card>
      <CardContent className="flex items-center justify-between p-5">
        <div>
          <p className="text-xs text-muted-foreground uppercase tracking-wide">{label}</p>
          <p className="text-2xl font-bold font-mono mt-1">{value ?? "—"}</p>
        </div>
        <Icon className="h-8 w-8 text-primary/50" />
      </CardContent>
    </Card>
  );
}

export default function Dashboard() {
  const { data: stats } = useDashboardStats();
  const { data: timeline } = useTimeline(24);
  const { data: attackers } = useTopAttackers(5);
  const { data: recentAlerts } = useAlerts({ limit: 5 });

  const chartData = (timeline?.buckets ?? []).map((b) => ({
    time: new Date(b.bucket).toLocaleTimeString([], { hour: "2-digit" }),
    events: b.event_count,
    alerts: b.alert_count,
  }));

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">Dashboard</h1>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard label="Total Events" value={stats?.total_events} icon={Activity} />
        <StatCard label="Events (24h)" value={stats?.events_last_24h} icon={Clock} />
        <StatCard label="Open Alerts" value={stats?.open_alerts} icon={ShieldAlert} />
        <StatCard label="Open Incidents" value={stats?.open_incidents} icon={FolderOpen} />
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
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={chartData}>
              <defs>
                <linearGradient id="eventsGradient" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="hsl(190 100% 50%)" stopOpacity={0.4} />
                  <stop offset="95%" stopColor="hsl(190 100% 50%)" stopOpacity={0} />
                </linearGradient>
                <linearGradient id="alertsGradient" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="hsl(345 100% 60%)" stopOpacity={0.4} />
                  <stop offset="95%" stopColor="hsl(345 100% 60%)" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="hsl(216 48% 20%)" />
              <XAxis dataKey="time" stroke="hsl(215 16% 47%)" fontSize={12} />
              <YAxis stroke="hsl(215 16% 47%)" fontSize={12} allowDecimals={false} />
              <Tooltip
                contentStyle={{
                  background: "hsl(216 56% 13%)",
                  border: "1px solid hsl(216 48% 20%)",
                  borderRadius: 8,
                  fontSize: 12,
                }}
              />
              <Area type="monotone" dataKey="events" stroke="hsl(190 100% 50%)" fill="url(#eventsGradient)" />
              <Area type="monotone" dataKey="alerts" stroke="hsl(345 100% 60%)" fill="url(#alertsGradient)" />
            </AreaChart>
          </ResponsiveContainer>
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
    </div>
  );
}
