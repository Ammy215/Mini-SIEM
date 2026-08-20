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

export default function Settings() {
  const { user } = useAuth();
  const { data: validate } = useSetupValidate();

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">Settings</h1>

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
    </div>
  );
}
