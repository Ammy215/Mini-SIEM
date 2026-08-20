import { useState } from "react";
import { Search } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { useEnrichIp } from "@/api/hooks";

function Field({ label, value }) {
  return (
    <div className="flex items-start justify-between gap-3 py-1.5 text-sm border-b border-border last:border-0">
      <span className="text-muted-foreground shrink-0">{label}</span>
      <span className="font-mono text-right break-all">{value ?? "—"}</span>
    </div>
  );
}

export default function IpIntel() {
  const [ip, setIp] = useState("");
  const enrich = useEnrichIp();

  const handleSubmit = (e) => {
    e.preventDefault();
    if (ip) enrich.mutate(ip);
  };

  const result = enrich.data;

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">IP Intel</h1>

      <form onSubmit={handleSubmit} className="flex gap-2 max-w-md">
        <Input
          placeholder="e.g. 8.8.8.8"
          value={ip}
          onChange={(e) => setIp(e.target.value)}
          className="font-mono"
        />
        <Button type="submit" disabled={enrich.isPending}>
          <Search className="h-4 w-4 mr-1.5" />
          {enrich.isPending ? "Looking up..." : "Lookup"}
        </Button>
      </form>

      {enrich.isError && (
        <p className="text-sm text-destructive">
          {enrich.error?.response?.data?.detail ?? "Lookup failed"}
        </p>
      )}

      {result && (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-base flex items-center justify-between">
                AbuseIPDB
                {result.cached?.abuseipdb && <span className="text-xs text-muted-foreground font-normal">cached</span>}
              </CardTitle>
            </CardHeader>
            <CardContent>
              {result.abuseipdb?.error ? (
                <p className="text-sm text-muted-foreground">{result.abuseipdb.error}</p>
              ) : (
                <>
                  <Field label="Abuse score" value={result.abuseipdb?.abuse_confidence_score} />
                  <Field label="Total reports" value={result.abuseipdb?.total_reports} />
                  <Field label="Country" value={result.abuseipdb?.country_code} />
                  <Field label="ISP" value={result.abuseipdb?.isp} />
                  <Field label="Whitelisted" value={String(result.abuseipdb?.is_whitelisted)} />
                </>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="text-base flex items-center justify-between">
                OTX
                {result.cached?.otx && <span className="text-xs text-muted-foreground font-normal">cached</span>}
              </CardTitle>
            </CardHeader>
            <CardContent>
              {result.otx?.error ? (
                <p className="text-sm text-muted-foreground">{result.otx.error}</p>
              ) : (
                <>
                  <Field label="Pulse count" value={result.otx?.pulse_count} />
                  <Field label="Country" value={result.otx?.country} />
                  <Field label="ASN" value={result.otx?.asn} />
                </>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="text-base flex items-center justify-between">
                IPInfo
                {result.cached?.ipinfo && <span className="text-xs text-muted-foreground font-normal">cached</span>}
              </CardTitle>
            </CardHeader>
            <CardContent>
              {result.ipinfo?.error ? (
                <p className="text-sm text-muted-foreground">{result.ipinfo.error}</p>
              ) : (
                <>
                  <Field label="City" value={result.ipinfo?.city} />
                  <Field label="Region" value={result.ipinfo?.region} />
                  <Field label="Country" value={result.ipinfo?.country} />
                  <Field label="Org" value={result.ipinfo?.org} />
                  <Field label="Timezone" value={result.ipinfo?.timezone} />
                </>
              )}
            </CardContent>
          </Card>
        </div>
      )}
    </div>
  );
}
