import { Fragment, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { motion } from "framer-motion";
import { CheckCircle2, ChevronDown, ChevronRight, Terminal, UploadCloud } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { LogText } from "@/components/LogText";
import { useAuth } from "@/api/AuthContext";
import { useIngestFormats, useUploadBatches, useUploadLog } from "@/api/hooks";
import { apiErrorMessage } from "@/lib/errors";
import { cn } from "@/lib/utils";

const DEFAULT_MAX_BYTES = 10 * 1024 * 1024;

// What each skip reason means, in words someone uploading a file recognises.
const REASON_LABELS = {
  unrecognized_format: "Not in the chosen format",
  invalid_timestamp: "Date or time that doesn't exist",
  invalid_field: "A value didn't fit its field",
  parser_error: "Couldn't be read",
  line_too_long: "Line longer than 256 KB",
  column_count_mismatch: "Wrong number of CSV columns",
  malformed_csv_row: "Unreadable CSV row",
  malformed_xml: "XML cut off or broken",
  missing_event_id: "Windows event without an EventID",
  xml_dtd_forbidden: "XML with a DTD — refused for safety",
  xml_forbidden_construct: "Unsafe XML — refused",
  xml_too_deep: "XML nested too deeply — refused",
};

const DETECTION_LABELS = {
  mixed: "Mixed formats",
  unrecognized: "No known format",
  empty: "Empty file",
};

const EXPORT_TIPS = [
  {
    title: "Windows Security log (PowerShell)",
    command:
      "Get-WinEvent -LogName Security -MaxEvents 5000 |\n  Select-Object Id, TimeCreated, MachineName, @{n='Xml'; e={$_.ToXml()}} |\n  ConvertTo-Json | Out-File security.json",
    note: "Keeping the Xml column gives every field of every event ID. Event Viewer's \"Save All Events As… XML\" works too.",
  },
  {
    title: "Linux",
    command: "/var/log/auth.log   /var/log/ufw.log   /var/log/nginx/access.log",
    note: "Upload the files as they are. Old syslog files have no year in their timestamps — set the year below.",
  },
  {
    title: "Firewalls and appliances",
    command: "Syslog or CEF exports from Palo Alto, Fortinet, Check Point, pfSense…",
    note: "CEF, key=value and CSV exports are recognised automatically.",
  },
];

function formatBytes(bytes) {
  if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  if (bytes >= 1024) return `${Math.round(bytes / 1024)} KB`;
  return `${bytes} bytes`;
}

function formatLabel(name, formats) {
  return DETECTION_LABELS[name] ?? formats.find((f) => f.name === name)?.label ?? name;
}

function DropZone({ file, onFile, maxBytes, disabled }) {
  const inputRef = useRef(null);
  const [dragging, setDragging] = useState(false);
  const open = () => inputRef.current?.click();

  return (
    <div
      role="button"
      tabIndex={0}
      aria-label="Choose a log file to upload"
      onClick={open}
      onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && (e.preventDefault(), open())}
      onDragOver={(e) => {
        e.preventDefault();
        setDragging(true);
      }}
      onDragLeave={() => setDragging(false)}
      onDrop={(e) => {
        e.preventDefault();
        setDragging(false);
        const dropped = e.dataTransfer.files?.[0];
        if (dropped) onFile(dropped);
      }}
      className={cn(
        "flex flex-col items-center justify-center gap-2 rounded-lg border-2 border-dashed px-6 py-10 text-center cursor-pointer transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
        dragging ? "border-primary bg-primary/10" : "border-border hover:border-primary/50",
        disabled && "pointer-events-none opacity-60",
      )}
    >
      <input
        ref={inputRef}
        id="log-file"
        type="file"
        className="hidden"
        onChange={(e) => {
          const chosen = e.target.files?.[0];
          e.target.value = ""; // so choosing the same file again still fires
          if (chosen) onFile(chosen);
        }}
      />
      <UploadCloud className="h-8 w-8 text-primary" />
      {file ? (
        <>
          <p className="font-mono text-sm break-all"><LogText value={file.name} /></p>
          <p className="text-xs text-muted-foreground">{formatBytes(file.size)} · click to choose a different file</p>
        </>
      ) : (
        <>
          <p className="text-sm">Drop a log file here, or click to choose one</p>
          <p className="text-xs text-muted-foreground">
            Up to {formatBytes(maxBytes)} — text logs, JSON, CSV, CEF or Windows XML
          </p>
        </>
      )}
    </div>
  );
}

function CountTile({ label, value, tone }) {
  return (
    <div className="rounded-lg border border-border bg-background/40 p-3">
      <p className="text-xs uppercase tracking-wide text-muted-foreground">{label}</p>
      <p className={cn("mt-1 text-2xl font-bold font-mono tabular-nums", tone)}>{value.toLocaleString()}</p>
    </div>
  );
}

function ParserCounts({ byParser, formats }) {
  const entries = Object.entries(byParser ?? {}).sort((a, b) => b[1] - a[1]);
  if (entries.length === 0) return null;
  return (
    <div className="flex flex-wrap gap-2">
      {entries.map(([name, count]) => (
        <Badge key={name} variant="outline" className="h-6 gap-1.5 font-normal">
          <span>{formatLabel(name, formats)}</span>
          <span className="font-mono text-muted-foreground">{count.toLocaleString()}</span>
        </Badge>
      ))}
    </div>
  );
}

function SkipReasons({ reasons }) {
  const entries = Object.entries(reasons ?? {});
  if (entries.length === 0) return null;
  return (
    <ul className="max-w-md space-y-1 text-sm">
      {entries.map(([reason, count]) => (
        <li key={reason} className="flex justify-between gap-4">
          <span>{REASON_LABELS[reason] ?? reason}</span>
          <span className="font-mono text-muted-foreground">{count.toLocaleString()}</span>
        </li>
      ))}
    </ul>
  );
}

function UploadResult({ result, formats }) {
  const confidence =
    result.confidence == null
      ? "format chosen by you"
      : `${Math.round(result.confidence * 100)}% of sampled lines matched`;

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.25 }}>
      <Card className="border-primary/30">
        <CardHeader className="space-y-2">
          <CardTitle className="flex items-center gap-2 text-base">
            <CheckCircle2 className="h-5 w-5 text-siem-green" />
            <span className="break-all">Uploaded <LogText value={result.filename} className="font-mono" /></span>
          </CardTitle>
          <p className="text-sm text-muted-foreground">
            Detected as <span className="text-foreground font-medium">{formatLabel(result.detected_format, formats)}</span>
            {" · "}
            {confidence}
          </p>
        </CardHeader>
        <CardContent className="space-y-5">
          <div className="grid grid-cols-3 gap-3">
            <CountTile label="Lines" value={result.total_lines} />
            <CountTile label="Stored" value={result.inserted} tone="text-siem-green" />
            <CountTile label="Skipped" value={result.skipped} tone={result.skipped ? "text-amber" : undefined} />
          </div>

          <div className="space-y-2">
            <p className="text-xs uppercase tracking-wide text-muted-foreground">Read by</p>
            <ParserCounts byParser={result.by_parser} formats={formats} />
          </div>

          {result.skipped > 0 && (
            <div className="space-y-3">
              <p className="text-xs uppercase tracking-wide text-muted-foreground">Why lines were skipped</p>
              <SkipReasons reasons={result.skipped_reasons} />
              {result.skipped_samples.length > 0 && (
                <div className="rounded-lg border border-border overflow-x-auto">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead className="w-16">Line</TableHead>
                        <TableHead>Reason</TableHead>
                        <TableHead>Content</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {result.skipped_samples.map((sample) => (
                        <TableRow key={`${sample.line}-${sample.reason}`}>
                          <TableCell className="font-mono text-xs">{sample.line}</TableCell>
                          <TableCell className="text-xs whitespace-nowrap">{REASON_LABELS[sample.reason] ?? sample.reason}</TableCell>
                          <TableCell className="max-w-md truncate font-mono text-xs">
                            <LogText value={sample.excerpt} />
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </div>
              )}
            </div>
          )}

          {result.inserted > 0 && (
            <Button asChild variant="outline" size="sm">
              <Link to={`/events?batch_id=${result.batch_id}`}>View these events</Link>
            </Button>
          )}
        </CardContent>
      </Card>
    </motion.div>
  );
}

function UploadHistory({ formats }) {
  const { data, isLoading } = useUploadBatches(true);
  const [expanded, setExpanded] = useState(null);
  const batches = data?.batches ?? [];

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Upload history</CardTitle>
      </CardHeader>
      <CardContent className="p-0">
        <div className="overflow-x-auto">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-8"></TableHead>
                <TableHead>Uploaded</TableHead>
                <TableHead>File</TableHead>
                <TableHead>By</TableHead>
                <TableHead>Format</TableHead>
                <TableHead className="text-right">Stored</TableHead>
                <TableHead className="text-right">Skipped</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {isLoading && (
                <TableRow>
                  <TableCell colSpan={7} className="text-center text-muted-foreground">Loading...</TableCell>
                </TableRow>
              )}
              {!isLoading && batches.length === 0 && (
                <TableRow>
                  <TableCell colSpan={7} className="text-center text-muted-foreground">No uploads yet.</TableCell>
                </TableRow>
              )}
              {batches.map((batch) => {
                const isOpen = expanded === batch.id;
                return (
                  <Fragment key={batch.id}>
                    <TableRow className="cursor-pointer" onClick={() => setExpanded(isOpen ? null : batch.id)}>
                      <TableCell>
                        {isOpen ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
                      </TableCell>
                      <TableCell className="font-mono text-xs whitespace-nowrap">
                        {new Date(batch.created_at).toLocaleString()}
                      </TableCell>
                      <TableCell className="max-w-[16rem] truncate font-mono text-xs">
                        <LogText value={batch.filename} />
                      </TableCell>
                      <TableCell className="text-xs text-muted-foreground">{batch.uploaded_by ?? "—"}</TableCell>
                      <TableCell className="text-xs whitespace-nowrap">
                        {formatLabel(batch.detected_format, formats)}
                        {batch.requested_format !== "auto" && <span className="text-muted-foreground"> (chosen)</span>}
                      </TableCell>
                      <TableCell className="text-right font-mono">{batch.inserted.toLocaleString()}</TableCell>
                      <TableCell className={cn("text-right font-mono", batch.skipped && "text-amber")}>
                        {batch.skipped.toLocaleString()}
                      </TableCell>
                    </TableRow>
                    {isOpen && (
                      <TableRow>
                        <TableCell colSpan={7} className="bg-background/50 px-4 py-4">
                          <div className="grid gap-4 md:grid-cols-3">
                            <div className="space-y-2">
                              <p className="text-xs uppercase tracking-wide text-muted-foreground">Read by</p>
                              <ParserCounts byParser={batch.by_parser} formats={formats} />
                            </div>
                            <div className="space-y-2">
                              <p className="text-xs uppercase tracking-wide text-muted-foreground">Skipped</p>
                              {batch.skipped ? <SkipReasons reasons={batch.skipped_reasons} /> : <p className="text-sm text-muted-foreground">Nothing skipped</p>}
                            </div>
                            <div className="space-y-1 text-xs">
                              <p className="uppercase tracking-wide text-muted-foreground">Events span</p>
                              <p className="font-mono">
                                {batch.first_event_time ? new Date(batch.first_event_time).toLocaleString() : "—"}
                                {" → "}
                                {batch.last_event_time ? new Date(batch.last_event_time).toLocaleString() : "—"}
                              </p>
                              <p className="font-mono text-muted-foreground" title={batch.sha256}>
                                sha256 {batch.sha256.slice(0, 16)}… · {formatBytes(batch.size_bytes)}
                              </p>
                              {batch.inserted > 0 && (
                                <Link to={`/events?batch_id=${batch.id}`} className="inline-block pt-1 text-primary hover:underline">
                                  View these events
                                </Link>
                              )}
                            </div>
                          </div>
                        </TableCell>
                      </TableRow>
                    )}
                  </Fragment>
                );
              })}
            </TableBody>
          </Table>
        </div>
      </CardContent>
    </Card>
  );
}

export default function Upload() {
  const { user } = useAuth();
  const roles = user?.roles ?? [];
  const canUpload = roles.includes("admin") || roles.includes("analyst");

  const { data: formatsData } = useIngestFormats(canUpload);
  const uploadLog = useUploadLog();
  const [file, setFile] = useState(null);
  const [format, setFormat] = useState("auto");
  const [year, setYear] = useState("");
  const [progress, setProgress] = useState(0);
  const [error, setError] = useState(null);
  const [result, setResult] = useState(null);

  if (!canUpload) {
    return (
      <div className="space-y-6">
        <h1 className="text-2xl font-bold">Upload Logs</h1>
        <p className="text-sm text-muted-foreground">Analyst or admin role required to upload logs.</p>
      </div>
    );
  }

  const formats = formatsData?.formats ?? [];
  const maxBytes = formatsData?.max_upload_bytes ?? DEFAULT_MAX_BYTES;
  const selectedFormat = formats.find((f) => f.name === format);

  const chooseFile = (chosen) => {
    setError(null);
    setResult(null);
    setProgress(0);
    if (chosen.size > maxBytes) {
      setFile(null);
      setError(`${chosen.name} is ${formatBytes(chosen.size)}; the limit is ${formatBytes(maxBytes)}. Split it into smaller files.`);
      return;
    }
    setFile(chosen);
  };

  const handleUpload = async () => {
    setError(null);
    setResult(null);
    setProgress(0);
    try {
      const data = await uploadLog.mutateAsync({
        file,
        format,
        year: year ? Number(year) : undefined,
        onProgress: setProgress,
      });
      setResult(data);
      setFile(null);
    } catch (err) {
      setError(apiErrorMessage(err, "Upload failed. Check the file and try again."));
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold">Upload Logs</h1>
        <p className="text-sm text-muted-foreground mt-1">
          Any log file is accepted. Its format is detected automatically, and lines no parser recognises are still
          stored as searchable text.
        </p>
      </div>

      <div className="grid items-start gap-6 lg:grid-cols-[minmax(0,2fr)_minmax(0,1fr)]">
        <Card>
          <CardContent className="space-y-5">
            <DropZone file={file} onFile={chooseFile} maxBytes={maxBytes} disabled={uploadLog.isPending} />

            <div className="grid gap-4 sm:grid-cols-2">
              <div className="space-y-1.5">
                <Label htmlFor="upload-format">Format</Label>
                <select
                  id="upload-format"
                  className="h-9 w-full rounded-md border border-input bg-background px-3 text-sm"
                  value={format}
                  onChange={(e) => setFormat(e.target.value)}
                  disabled={uploadLog.isPending}
                >
                  {(formats.length ? formats : [{ name: "auto", label: "Auto-detect" }]).map((f) => (
                    <option key={f.name} value={f.name}>{f.label}</option>
                  ))}
                </select>
                {selectedFormat && <p className="text-xs text-muted-foreground">{selectedFormat.description}</p>}
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="upload-year">Year (optional)</Label>
                <Input
                  id="upload-year"
                  type="number"
                  min={1970}
                  max={2100}
                  placeholder="e.g. 2025"
                  value={year}
                  onChange={(e) => setYear(e.target.value)}
                  disabled={uploadLog.isPending}
                />
                <p className="text-xs text-muted-foreground">
                  Only for logs whose timestamps have no year, like classic syslog and OpenSSH. Leave empty to use the
                  most recent matching date.
                </p>
              </div>
            </div>

            {uploadLog.isPending && (
              <div className="space-y-1.5" aria-live="polite">
                <div className="h-2 overflow-hidden rounded-full bg-muted">
                  <div className="h-full bg-primary transition-[width] duration-200" style={{ width: `${progress}%` }} />
                </div>
                <p className="text-xs text-muted-foreground font-mono">
                  {progress < 100 ? `Uploading… ${progress}%` : "Parsing and storing…"}
                </p>
              </div>
            )}

            {error && <p className="text-sm text-destructive">{error}</p>}

            <Button onClick={handleUpload} disabled={!file || uploadLog.isPending}>
              {uploadLog.isPending ? "Uploading…" : "Upload"}
            </Button>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <Terminal className="h-4 w-4 text-primary" />
              Getting logs out of your systems
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            {EXPORT_TIPS.map((tip) => (
              <div key={tip.title} className="space-y-1.5">
                <p className="text-sm font-medium">{tip.title}</p>
                <pre className="whitespace-pre-wrap break-words rounded-md border border-border bg-background/60 p-2.5 font-mono text-[11px] leading-relaxed">
                  {tip.command}
                </pre>
                <p className="text-xs text-muted-foreground">{tip.note}</p>
              </div>
            ))}
          </CardContent>
        </Card>
      </div>

      {result && <UploadResult result={result} formats={formats} />}

      <UploadHistory formats={formats} />
    </div>
  );
}
