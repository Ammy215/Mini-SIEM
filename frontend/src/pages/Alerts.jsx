import { useState } from "react";
import { motion } from "framer-motion";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { SeverityBadge } from "@/components/ui/severity-badge";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import { useAlerts } from "@/api/hooks";

const STATUSES = ["", "open", "acknowledged", "resolved", "false_positive"];
const SUMMARY_STATUSES = ["open", "acknowledged", "resolved", "false_positive"];
const PAGE_SIZE = 25;

function StatusCard({ status, index, isActive, onSelect }) {
  const { data } = useAlerts({ status, limit: 1 });
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

function StatusSummary({ activeStatus, onSelect }) {
  return (
    <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
      {SUMMARY_STATUSES.map((status, i) => (
        <StatusCard
          key={status}
          status={status}
          index={i}
          isActive={activeStatus === status}
          onSelect={onSelect}
        />
      ))}
    </div>
  );
}

export default function Alerts() {
  const [status, setStatus] = useState("");
  const [page, setPage] = useState(0);

  const { data, isLoading } = useAlerts({
    ...(status && { status }),
    limit: PAGE_SIZE,
    offset: page * PAGE_SIZE,
  });

  const alerts = data?.alerts ?? [];
  const total = data?.total ?? 0;

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">Alerts</h1>

      <StatusSummary
        activeStatus={status}
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
              <TableHead>Time</TableHead>
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
                <TableCell colSpan={7} className="text-center text-muted-foreground">
                  Loading...
                </TableCell>
              </TableRow>
            )}
            {!isLoading && alerts.length === 0 && (
              <TableRow>
                <TableCell colSpan={7} className="text-center text-muted-foreground">
                  No alerts found.
                </TableCell>
              </TableRow>
            )}
            {alerts.map((alert) => (
              <TableRow key={alert.id}>
                <TableCell className="font-mono text-xs whitespace-nowrap">
                  {new Date(alert.created_at).toLocaleString()}
                </TableCell>
                <TableCell className="max-w-xs truncate">{alert.title}</TableCell>
                <TableCell className="font-mono text-xs">{alert.mitre_technique ?? "—"}</TableCell>
                <TableCell className="font-mono">{alert.source_ip ?? "—"}</TableCell>
                <TableCell className="font-mono">{alert.threat_score ?? "—"}</TableCell>
                <TableCell>
                  <SeverityBadge severity={alert.severity} />
                </TableCell>
                <TableCell className="capitalize">{alert.status.replace("_", " ")}</TableCell>
              </TableRow>
            ))}
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
