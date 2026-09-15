import { Fragment, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { motion } from "framer-motion";
import { ChevronDown, ChevronRight } from "lucide-react";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { SeverityBadge } from "@/components/ui/severity-badge";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { AiSummary } from "@/components/AiSummary";
import { LogText } from "@/components/LogText";
import { cn } from "@/lib/utils";
import { useAlerts, useSummarizeAlert } from "@/api/hooks";

const STATUSES = ["", "open", "acknowledged", "resolved", "false_positive"];
const SUMMARY_STATUSES = ["open", "acknowledged", "resolved", "false_positive"];
const PAGE_SIZE = 25;
const ORIGIN_LABELS = { batch: "From upload", range: "Past range" };

function StatusCard({ status, index, isActive, onSelect, scope }) {
  const { data } = useAlerts({ status, limit: 1, ...scope });
  return (
    <motion.button
      initial={{ opacity: 0, y: 6 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: index * 0.04 }}
      onClick={() => onSelect(isActive ? "" : status)}
      className={cn(
        "rounded-lg border p-4 text-left transition-colors",
        isActive ? "border-primary bg-primary/10" : "border-border bg-card hover:border-primary/40"
      )}
    >
      <p className="text-xs text-muted-foreground uppercase tracking-wide capitalize">
        {status.replace("_", " ")}
      </p>
      <p className="text-2xl font-bold font-mono mt-1 tabular-nums">{data?.total ?? "—"}</p>
    </motion.button>
  );
}

function StatusSummary({ activeStatus, onSelect, scope }) {
  return (
    <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
      {SUMMARY_STATUSES.map((status, i) => (
        <StatusCard
          key={status}
          status={status}
          index={i}
          isActive={activeStatus === status}
          onSelect={onSelect}
          scope={scope}
        />
      ))}
    </div>
  );
}

export default function Alerts() {
  const [searchParams] = useSearchParams();
  const batchId = searchParams.get("batch_id") ?? "";
  const [status, setStatus] = useState("");
  const [page, setPage] = useState(0);
  const [expanded, setExpanded] = useState(null);

  const scope = batchId ? { batch_id: batchId } : {};
  const { data, isLoading } = useAlerts({
    ...(status && { status }),
    ...scope,
    limit: PAGE_SIZE,
    offset: page * PAGE_SIZE,
  });

  const alerts = data?.alerts ?? [];
  const total = data?.total ?? 0;

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">Alerts</h1>

      {batchId && (
        <div className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-primary/30 bg-primary/5 px-4 py-2 text-sm">
          <span>
            Showing alerts found by analyzing one upload{" "}
            <span className="font-mono text-xs text-muted-foreground">{batchId}</span>
          </span>
          <Link to="/alerts" className="text-primary hover:underline">Show all alerts</Link>
        </div>
      )}

      <StatusSummary
        activeStatus={status}
        scope={scope}
        onSelect={(s) => {
          setPage(0);
          setStatus(s);
        }}
      />

      <div className="flex flex-wrap gap-3 items-center">
        <select
          className="h-9 rounded-md border border-input bg-background px-3 text-sm"
          value={status}
          onChange={(e) => {
            setPage(0);
            setStatus(e.target.value);
          }}
        >
          {STATUSES.map((s) => (
            <option key={s} value={s}>
              {s ? s.replace("_", " ") : "All statuses"}
            </option>
          ))}
        </select>
        <span className="text-sm text-muted-foreground ml-auto">{total} alerts</span>
      </div>

      <div className="rounded-lg border border-border overflow-x-auto">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="w-8"></TableHead>
              <TableHead>Happened</TableHead>
              <TableHead>Title</TableHead>
              <TableHead>MITRE</TableHead>
              <TableHead>Source IP</TableHead>
              <TableHead>Score</TableHead>
              <TableHead>Severity</TableHead>
              <TableHead>Status</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {isLoading && (
              <TableRow>
                <TableCell colSpan={8} className="text-center text-muted-foreground">
                  Loading...
                </TableCell>
              </TableRow>
            )}
            {!isLoading && alerts.length === 0 && (
              <TableRow>
                <TableCell colSpan={8} className="text-center text-muted-foreground">
                  No alerts found.
                </TableCell>
              </TableRow>
            )}
            {alerts.map((alert) => {
              const isOpen = expanded === alert.id;
              // When the attack happened; an uploaded old log's alert is created long after.
              const happened = alert.first_event_time ?? alert.created_at;
              return (
                <Fragment key={alert.id}>
                  <TableRow className="cursor-pointer" onClick={() => setExpanded(isOpen ? null : alert.id)}>
                    <TableCell>
                      {isOpen ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
                    </TableCell>
                    <TableCell
                      className="font-mono text-xs whitespace-nowrap"
                      title={`Alert created ${new Date(alert.created_at).toLocaleString()}`}
                    >
                      {new Date(happened).toLocaleString()}
                    </TableCell>
                    {/* Titles can embed log content, e.g. the username in a password-spray alert. */}
                    <TableCell className="max-w-xs">
                      <div className="flex items-center gap-2">
                        <span className="truncate"><LogText value={alert.title} /></span>
                        {ORIGIN_LABELS[alert.origin] && (
                          <Badge variant="outline" className="h-4 shrink-0 px-1.5 text-[10px]">{ORIGIN_LABELS[alert.origin]}</Badge>
                        )}
                      </div>
                    </TableCell>
                    <TableCell className="font-mono text-xs">{alert.mitre_technique ?? "—"}</TableCell>
                    <TableCell className="font-mono">{alert.source_ip ?? "—"}</TableCell>
                    <TableCell className="font-mono">{alert.threat_score ?? "—"}</TableCell>
                    <TableCell>
                      <SeverityBadge severity={alert.severity} />
                    </TableCell>
                    <TableCell className="capitalize">{alert.status.replace("_", " ")}</TableCell>
                  </TableRow>
                  {isOpen && (
                    <TableRow>
                      <TableCell colSpan={8} className="bg-background/50 px-4 py-3">
                        <AiSummary kind="alert" targetId={alert.id} useSummarize={useSummarizeAlert} />
                      </TableCell>
                    </TableRow>
                  )}
                </Fragment>
              );
            })}
          </TableBody>
        </Table>
      </div>

      <div className="flex items-center justify-between">
        <Button variant="outline" size="sm" disabled={page === 0} onClick={() => setPage((p) => p - 1)}>
          Previous
        </Button>
        <span className="text-sm text-muted-foreground">
          Page {page + 1} of {Math.max(1, Math.ceil(total / PAGE_SIZE))}
        </span>
        <Button
          variant="outline"
          size="sm"
          disabled={(page + 1) * PAGE_SIZE >= total}
          onClick={() => setPage((p) => p + 1)}
        >
          Next
        </Button>
      </div>
    </div>
  );
}
