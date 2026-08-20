import { Fragment, useState } from "react";
import { ChevronDown, ChevronRight } from "lucide-react";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { SeverityBadge } from "@/components/ui/severity-badge";
import { useIncidents, useIncident } from "@/api/hooks";

function IncidentAlerts({ incidentId }) {
  const { data, isLoading } = useIncident(incidentId);
  if (isLoading) return <p className="text-sm text-muted-foreground px-4 py-3">Loading alerts...</p>;

  return (
    <div className="bg-background/50 px-4 py-3 space-y-2">
      {(data?.alerts ?? []).map((alert) => (
        <div key={alert.id} className="flex items-center justify-between text-sm py-1">
          <div className="flex items-center gap-3">
            <span className="font-mono text-xs text-muted-foreground">{alert.mitre_technique ?? "—"}</span>
            <span>{alert.title}</span>
          </div>
          <div className="flex items-center gap-3">
            <span className="font-mono text-xs text-muted-foreground">{alert.threat_score}</span>
            <SeverityBadge severity={alert.severity} />
          </div>
        </div>
      ))}
    </div>
  );
}

export default function Incidents() {
  const { data, isLoading } = useIncidents({ limit: 50 });
  const [expanded, setExpanded] = useState(null);

  const incidents = data?.incidents ?? [];

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">Incidents</h1>
      <p className="text-sm text-muted-foreground -mt-4">
        Related alerts from the same source, correlated within a 60-minute window into a single campaign.
      </p>

      <div className="rounded-lg border border-border overflow-hidden">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="w-8"></TableHead>
              <TableHead>Title</TableHead>
              <TableHead>Source IP</TableHead>
              <TableHead>Alerts</TableHead>
              <TableHead>Severity</TableHead>
              <TableHead>First Seen</TableHead>
              <TableHead>Last Seen</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {isLoading && (
              <TableRow>
                <TableCell colSpan={7} className="text-center text-muted-foreground">Loading...</TableCell>
              </TableRow>
            )}
            {!isLoading && incidents.length === 0 && (
              <TableRow>
                <TableCell colSpan={7} className="text-center text-muted-foreground">No incidents yet.</TableCell>
              </TableRow>
            )}
            {incidents.map((incident) => {
              const isOpen = expanded === incident.id;
              return (
                <Fragment key={incident.id}>
                  <TableRow
                    className="cursor-pointer"
                    onClick={() => setExpanded(isOpen ? null : incident.id)}
                  >
                    <TableCell>
                      {isOpen ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
                    </TableCell>
                    <TableCell className="max-w-xs truncate">{incident.title}</TableCell>
                    <TableCell className="font-mono">{incident.source_ip ?? "—"}</TableCell>
                    <TableCell className="font-mono">{incident.alert_count}</TableCell>
                    <TableCell><SeverityBadge severity={incident.severity} /></TableCell>
                    <TableCell className="font-mono text-xs whitespace-nowrap">
                      {incident.first_seen ? new Date(incident.first_seen).toLocaleString() : "—"}
                    </TableCell>
                    <TableCell className="font-mono text-xs whitespace-nowrap">
                      {incident.last_seen ? new Date(incident.last_seen).toLocaleString() : "—"}
                    </TableCell>
                  </TableRow>
                  {isOpen && (
                    <TableRow>
                      <TableCell colSpan={7} className="p-0">
                        <IncidentAlerts incidentId={incident.id} />
                      </TableCell>
                    </TableRow>
                  )}
                </Fragment>
              );
            })}
          </TableBody>
        </Table>
      </div>
    </div>
  );
}
