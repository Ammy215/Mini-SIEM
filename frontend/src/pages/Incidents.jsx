import { Fragment, useState } from "react";
import { motion } from "framer-motion";
import { ChevronDown, ChevronRight, FolderOpen } from "lucide-react";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { SeverityBadge } from "@/components/ui/severity-badge";
import { AiSummary } from "@/components/AiSummary";
import { AlertEvidence } from "@/components/AlertEvidence";
import { IncidentTimeline } from "@/components/IncidentTimeline";
import { LogText } from "@/components/LogText";
import { SeverityBar } from "@/components/charts/SeverityBar";
import { useIncidents, useIncident, useSummarizeIncident } from "@/api/hooks";

function IncidentDetail({ incidentId }) {
  const { data, isLoading } = useIncident(incidentId);
  const [selectedAlert, setSelectedAlert] = useState(null);

  if (isLoading) {
    return <p className="px-4 py-4 text-sm text-muted-foreground">Loading the incident…</p>;
  }
  const alerts = data?.alerts ?? [];
  const selected = alerts.find((a) => a.id === selectedAlert);

  return (
    // TableCell sets white-space: nowrap for every cell; prose in here must wrap.
    <div className="space-y-4 whitespace-normal bg-background/50 px-4 py-4">
      <div className="rounded-md border border-border bg-card/60 p-3">
        <IncidentTimeline alerts={alerts} selectedId={selectedAlert} onSelect={setSelectedAlert} />
        {!selected && alerts.length > 0 && (
          <p className="mt-2 text-[11px] text-muted-foreground">
            Select an alert to see the evidence behind it.
          </p>
        )}
      </div>

      {selected && (
        <motion.div
          key={selected.id}
          initial={{ opacity: 0, y: 4 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.18 }}
        >
          <AlertEvidence alert={selected} />
        </motion.div>
      )}

      <AiSummary kind="incident" targetId={incidentId} useSummarize={useSummarizeIncident} />
    </div>
  );
}

// Worst first, so the part that decides what to open next is read first.
function Overview({ incidents, total }) {
  const bySeverity = incidents.reduce((acc, i) => {
    acc[i.severity] = (acc[i.severity] ?? 0) + 1;
    return acc;
  }, {});
  const open = incidents.filter((i) => i.status === "open").length;
  const alerts = incidents.reduce((sum, i) => sum + (i.alert_count ?? 0), 0);
  const sources = new Set(incidents.map((i) => i.source_ip).filter(Boolean)).size;

  const figures = [
    { label: "Open", value: open },
    { label: "Alerts correlated", value: alerts },
    { label: "Distinct sources", value: sources },
  ];

  return (
    <div className="grid gap-px overflow-hidden rounded-lg border border-border bg-border sm:grid-cols-[1fr_1fr_1fr_1.6fr]">
      {figures.map((f) => (
        <div key={f.label} className="bg-card px-4 py-3">
          <p className="text-[11px] uppercase tracking-wider text-muted-foreground">{f.label}</p>
          <p className="mt-0.5 font-mono text-2xl font-semibold tabular-nums">{f.value.toLocaleString()}</p>
        </div>
      ))}
      <div className="bg-card px-4 py-3">
        <p className="text-[11px] uppercase tracking-wider text-muted-foreground">
          By severity
          {total > incidents.length && (
            <span className="normal-case tracking-normal"> · latest {incidents.length} of {total}</span>
          )}
        </p>
        <SeverityBar counts={bySeverity} className="mt-2.5" />
      </div>
    </div>
  );
}

export default function Incidents() {
  const { data, isLoading } = useIncidents({ limit: 50 });
  const [expanded, setExpanded] = useState(null);

  const incidents = data?.incidents ?? [];
  const total = data?.total ?? incidents.length;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-display text-2xl">Incidents</h1>
        <p className="mt-1 max-w-2xl text-sm text-muted-foreground">
          Alerts from the same source within 60 minutes of each other, grouped into one campaign.
          Open one to see how it unfolded.
        </p>
      </div>

      {incidents.length > 0 && <Overview incidents={incidents} total={total} />}

      {!isLoading && incidents.length === 0 ? (
        <div className="flex flex-col items-center justify-center rounded-lg border border-dashed border-border px-6 py-16 text-center">
          <FolderOpen className="h-8 w-8 text-muted-foreground/60" />
          <p className="mt-3 text-sm font-medium">No incidents yet</p>
          <p className="mt-1 max-w-sm text-xs text-muted-foreground">
            An incident opens when detection raises an alert. Upload a log or wait for the next
            detection pass.
          </p>
        </div>
      ) : (
        <div className="overflow-hidden rounded-lg border border-border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-8"></TableHead>
                <TableHead>Campaign</TableHead>
                <TableHead>Source IP</TableHead>
                <TableHead className="text-right">Alerts</TableHead>
                <TableHead>Severity</TableHead>
                <TableHead>First seen</TableHead>
                <TableHead>Last seen</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {isLoading && (
                <TableRow>
                  <TableCell colSpan={7} className="text-center text-muted-foreground">Loading…</TableCell>
                </TableRow>
              )}
              {incidents.map((incident) => {
                const isOpen = expanded === incident.id;
                return (
                  <Fragment key={incident.id}>
                    <TableRow
                      className="cursor-pointer"
                      aria-expanded={isOpen}
                      onClick={() => setExpanded(isOpen ? null : incident.id)}
                    >
                      <TableCell>
                        {isOpen ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
                      </TableCell>
                      <TableCell className="max-w-xs truncate font-medium"><LogText value={incident.title} /></TableCell>
                      <TableCell className="font-mono">{incident.source_ip ?? "—"}</TableCell>
                      <TableCell className="text-right font-mono tabular-nums">{incident.alert_count}</TableCell>
                      <TableCell><SeverityBadge severity={incident.severity} /></TableCell>
                      <TableCell className="font-mono text-xs whitespace-nowrap">
                        {incident.first_seen ? new Date(incident.first_seen).toLocaleString() : "—"}
                      </TableCell>
                      <TableCell className="font-mono text-xs whitespace-nowrap">
                        {incident.last_seen ? new Date(incident.last_seen).toLocaleString() : "—"}
                      </TableCell>
                    </TableRow>
                    {isOpen && (
                      <TableRow className="hover:bg-transparent">
                        <TableCell colSpan={7} className="p-0">
                          <IncidentDetail incidentId={incident.id} />
                        </TableCell>
                      </TableRow>
                    )}
                  </Fragment>
                );
              })}
            </TableBody>
          </Table>
        </div>
      )}
    </div>
  );
}
