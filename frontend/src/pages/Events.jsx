import { useState } from "react";
import { useSearchParams } from "react-router-dom";
import { SlidersHorizontal, X } from "lucide-react";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { LogText } from "@/components/LogText";
import { useEvents } from "@/api/hooks";

const SOURCE_TYPES = ["", "ssh", "nginx", "windows", "firewall", "cef", "syslog", "app", "kv", "csv", "generic"];
const PAGE_SIZE = 25;
const EMPTY_FILTERS = { from: "", to: "", username: "", host: "", event_code: "", dest_port: "", country: "" };

function destination(event) {
  if (!event.dest_ip && event.dest_port == null) return null;
  return `${event.dest_ip ?? "?"}${event.dest_port != null ? `:${event.dest_port}` : ""}`;
}

// Only filters that are complete and valid are sent, so half-typed input doesn't produce errors.
function filterParams(filters) {
  const params = {};
  for (const key of ["from", "to"]) {
    const date = filters[key] ? new Date(filters[key]) : null;
    if (date && !Number.isNaN(date.getTime())) params[key] = date.toISOString();
  }
  for (const key of ["username", "host", "event_code"]) {
    if (filters[key].trim()) params[key] = filters[key].trim();
  }
  if (/^\d{1,5}$/.test(filters.dest_port) && Number(filters.dest_port) <= 65535) params.dest_port = Number(filters.dest_port);
  if (/^[A-Z]{2}$/.test(filters.country)) params.country = filters.country;
  if (params.from && params.to && params.to <= params.from) delete params.to;
  return params;
}

function FilterInput({ label, ...props }) {
  return (
    <label className="space-y-1">
      <span className="text-xs text-muted-foreground">{label}</span>
      <Input className="h-8 text-xs" {...props} />
    </label>
  );
}

export default function Events() {
  const [searchParams, setSearchParams] = useSearchParams();
  const batchId = searchParams.get("batch_id") ?? "";
  const [sourceType, setSourceType] = useState("");
  const [q, setQ] = useState("");
  const [page, setPage] = useState(0);
  const [showFilters, setShowFilters] = useState(false);
  const [filters, setFilters] = useState(EMPTY_FILTERS);

  const extra = filterParams(filters);
  const activeFilters = Object.keys(extra).length;

  const { data, isLoading } = useEvents({
    ...(sourceType && { source_type: sourceType }),
    ...(q && { q }),
    ...(batchId && { batch_id: batchId }),
    ...extra,
    limit: PAGE_SIZE,
    offset: page * PAGE_SIZE,
  });

  const events = data?.events ?? [];
  const total = data?.total ?? 0;

  const setFilter = (key, value) => {
    setPage(0);
    setFilters((previous) => ({ ...previous, [key]: value }));
  };

  return (
    <div className="space-y-6">
      <h1 className="text-display text-2xl">Events</h1>

      {batchId && (
        <div className="flex items-center justify-between gap-3 rounded-lg border border-primary/30 bg-primary/5 px-4 py-2.5 text-sm">
          <span>
            Showing events from one upload <span className="font-mono text-xs text-muted-foreground">{batchId}</span>
          </span>
          <Button
            variant="ghost"
            size="sm"
            onClick={() => {
              setPage(0);
              setSearchParams({});
            }}
          >
            <X className="h-3.5 w-3.5" />
            Show all events
          </Button>
        </div>
      )}

      <div className="space-y-3">
        <div className="flex flex-wrap gap-3 items-center">
          <select
            className="h-9 rounded-md border border-input bg-background px-3 text-sm"
            value={sourceType}
            onChange={(e) => {
              setPage(0);
              setSourceType(e.target.value);
            }}
          >
            {SOURCE_TYPES.map((t) => (
              <option key={t} value={t}>
                {t || "All source types"}
              </option>
            ))}
          </select>
          <Input
            placeholder="Search raw message..."
            className="max-w-xs"
            value={q}
            onChange={(e) => {
              setPage(0);
              setQ(e.target.value);
            }}
          />
          <Button variant="outline" size="sm" onClick={() => setShowFilters((s) => !s)}>
            <SlidersHorizontal className="h-3.5 w-3.5" />
            Filters{activeFilters ? ` (${activeFilters})` : ""}
          </Button>
          {activeFilters > 0 && (
            <Button variant="ghost" size="sm" onClick={() => setFilters(EMPTY_FILTERS)}>
              <X className="h-3.5 w-3.5" /> Clear
            </Button>
          )}
          <span className="text-sm text-muted-foreground ml-auto">{total.toLocaleString()} events</span>
        </div>

        {showFilters && (
          <div className="grid gap-3 rounded-lg border border-border p-3 sm:grid-cols-2 lg:grid-cols-4">
            <FilterInput label="From" type="datetime-local" value={filters.from} onChange={(e) => setFilter("from", e.target.value)} />
            <FilterInput label="To" type="datetime-local" value={filters.to} onChange={(e) => setFilter("to", e.target.value)} />
            <FilterInput label="Username" value={filters.username} onChange={(e) => setFilter("username", e.target.value)} />
            <FilterInput label="Host" value={filters.host} onChange={(e) => setFilter("host", e.target.value)} />
            <FilterInput label="Event code" placeholder="e.g. 4625" value={filters.event_code} onChange={(e) => setFilter("event_code", e.target.value)} />
            <FilterInput label="Destination port" inputMode="numeric" placeholder="e.g. 22" value={filters.dest_port} onChange={(e) => setFilter("dest_port", e.target.value)} />
            <FilterInput
              label="Source country"
              placeholder="e.g. DE"
              maxLength={2}
              className="h-8 font-mono text-xs uppercase"
              value={filters.country}
              onChange={(e) => setFilter("country", e.target.value.toUpperCase())}
            />
          </div>
        )}
      </div>

      <div className="rounded-lg border border-border overflow-x-auto">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Time</TableHead>
              <TableHead>Source</TableHead>
              <TableHead>Host</TableHead>
              <TableHead>Source IP</TableHead>
              <TableHead>Destination</TableHead>
              <TableHead>Action</TableHead>
              <TableHead>Username</TableHead>
              <TableHead>URL</TableHead>
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
            {!isLoading && events.length === 0 && (
              <TableRow>
                <TableCell colSpan={8} className="text-center text-muted-foreground">
                  No events found.
                </TableCell>
              </TableRow>
            )}
            {events.map((event) => (
              <TableRow key={event.id}>
                <TableCell className="font-mono text-xs whitespace-nowrap">
                  {new Date(event.event_time).toLocaleString()}
                </TableCell>
                <TableCell>{event.source_type}</TableCell>
                <TableCell className="max-w-[10rem] truncate text-xs">
                  <LogText value={event.host} />
                </TableCell>
                <TableCell className="font-mono whitespace-nowrap">
                  {event.source_ip ?? "—"}
                  {event.country && <span className="ml-1.5 text-xs text-muted-foreground">{event.country}</span>}
                </TableCell>
                <TableCell className="font-mono text-xs whitespace-nowrap">{destination(event) ?? "—"}</TableCell>
                <TableCell>
                  <LogText value={event.action} />
                </TableCell>
                <TableCell>
                  <LogText value={event.username} />
                </TableCell>
                <TableCell className="max-w-xs truncate font-mono text-xs">
                  <LogText value={event.url} />
                </TableCell>
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
