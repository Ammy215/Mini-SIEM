import { useState } from "react";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { useEvents } from "@/api/hooks";

const SOURCE_TYPES = ["", "ssh", "nginx", "syslog", "app"];
const PAGE_SIZE = 25;

export default function Events() {
  const [sourceType, setSourceType] = useState("");
  const [q, setQ] = useState("");
  const [page, setPage] = useState(0);

  const { data, isLoading } = useEvents({
    ...(sourceType && { source_type: sourceType }),
    ...(q && { q }),
    limit: PAGE_SIZE,
    offset: page * PAGE_SIZE,
  });

  const events = data?.events ?? [];
  const total = data?.total ?? 0;

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">Events</h1>

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
        <span className="text-sm text-muted-foreground ml-auto">{total} events</span>
      </div>

      <div className="rounded-lg border border-border overflow-x-auto">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Time</TableHead>
              <TableHead>Source</TableHead>
              <TableHead>Source IP</TableHead>
              <TableHead>Action</TableHead>
              <TableHead>Username</TableHead>
              <TableHead>URL</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {isLoading && (
              <TableRow>
                <TableCell colSpan={6} className="text-center text-muted-foreground">
                  Loading...
                </TableCell>
              </TableRow>
            )}
            {!isLoading && events.length === 0 && (
              <TableRow>
                <TableCell colSpan={6} className="text-center text-muted-foreground">
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
                <TableCell className="font-mono">{event.source_ip ?? "—"}</TableCell>
                <TableCell>{event.action ?? "—"}</TableCell>
                <TableCell>{event.username ?? "—"}</TableCell>
                <TableCell className="max-w-xs truncate font-mono text-xs">{event.url ?? "—"}</TableCell>
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
