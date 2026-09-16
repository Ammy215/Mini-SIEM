import { CheckCircle2, XCircle } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { useAuth } from "@/api/AuthContext";
import { useSetupValidate } from "@/api/hooks";

function KeyRow({ name, present }) {
  return (
    <div className="flex items-center justify-between py-1.5 text-sm border-b border-border last:border-0">
      <span className="font-mono uppercase">{name}</span>
      {present ? (
        <span className="flex items-center gap-1.5 text-siem-green">
          <CheckCircle2 className="h-4 w-4" /> Configured
        </span>
      ) : (
        <span className="flex items-center gap-1.5 text-muted-foreground">
          <XCircle className="h-4 w-4" /> Not set
        </span>
      )}
    </div>
  );
}

function ContextRow({ label, value, unset }) {
  return (
    <div className="flex flex-wrap items-center justify-between gap-2 py-1.5 text-sm border-b border-border last:border-0">
      <span className="text-muted-foreground">{label}</span>
      {value ? <span className="font-mono text-siem-green">{value}</span> : <span className="text-muted-foreground">{unset}</span>}
    </div>
  );
}

export default function Settings() {
  const { user } = useAuth();
  const isAdmin = user?.roles?.includes("admin");
  const { data: validate } = useSetupValidate(isAdmin);

  return (
    <div className="space-y-6">
      <h1 className="text-display text-2xl">Settings</h1>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Profile</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex items-center justify-between py-1.5 text-sm border-b border-border">
            <span className="text-muted-foreground">Email</span>
            <span className="font-mono">{user?.email}</span>
          </div>
          <div className="flex items-center justify-between py-1.5 text-sm border-b border-border">
            <span className="text-muted-foreground">Full name</span>
            <span>{user?.full_name ?? "—"}</span>
          </div>
          <div className="flex items-center justify-between py-1.5 text-sm">
            <span className="text-muted-foreground">Roles</span>
            <span className="font-mono">{user?.roles?.join(", ")}</span>
          </div>
        </CardContent>
      </Card>

      {isAdmin && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Threat Intel API Keys</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-center justify-between py-1.5 text-sm border-b border-border">
              <span className="text-muted-foreground">Database</span>
              <span className={validate?.database === "connected" ? "text-siem-green" : "text-destructive"}>
                {validate?.database ?? "—"}
              </span>
            </div>
            {validate?.api_keys_present &&
              Object.entries(validate.api_keys_present).map(([name, present]) => (
                <KeyRow key={name} name={name} present={present} />
              ))}
          </CardContent>
        </Card>
      )}

      {isAdmin && validate?.context && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Detection Context</CardTitle>
          </CardHeader>
          <CardContent>
            <ContextRow
              label="Home countries"
              value={validate.context.home_countries.length ? validate.context.home_countries.join(", ") : null}
              unset="Not set — foreign_geo is skipped (HOME_COUNTRIES)"
            />
            <ContextRow
              label="Business hours"
              value={
                validate.context.business_hours_configured
                  ? `${validate.context.business_hours} ${validate.context.business_days} (${validate.context.business_timezone})`
                  : null
              }
              unset="Not set — after_hours is skipped (BUSINESS_HOURS)"
            />
            <ContextRow
              label="Background country lookups"
              value={validate.context.geo_lookups_enabled ? "Enabled" : null}
              unset="Disabled (ENABLE_GEO_LOOKUPS)"
            />
          </CardContent>
        </Card>
      )}
    </div>
  );
}
