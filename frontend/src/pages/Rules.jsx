import { useState } from "react";
import { Pencil, Plus } from "lucide-react";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { SeverityBadge } from "@/components/ui/severity-badge";
import { Badge } from "@/components/ui/badge";
import { Switch } from "@/components/ui/switch";
import { Button } from "@/components/ui/button";
import { RuleEditorDialog } from "@/components/rules/RuleEditorDialog";
import { useAuth } from "@/api/AuthContext";
import { useRules, useToggleRule } from "@/api/hooks";

const SECTIONS = [
  ["threshold", "Threshold Rules"],
  ["signature", "Signature Rules"],
  ["sequence", "Sequence Rules"],
];

function LastRun({ rule }) {
  if (rule.last_error) {
    return (
      <Badge variant="outline" className="border-destructive text-destructive" title={rule.last_error}>
        Error
      </Badge>
    );
  }
  if (!rule.last_run_at) return <span className="text-xs text-muted-foreground">—</span>;
  return (
    <span className="text-xs text-muted-foreground" title={new Date(rule.last_run_at).toLocaleString()}>
      OK · {rule.last_alerts ?? 0} new
    </span>
  );
}

export default function Rules() {
  const { user } = useAuth();
  const roles = user?.roles ?? [];
  const isAdmin = roles.includes("admin");
  const canEdit = isAdmin || roles.includes("analyst");
  const { data, isLoading } = useRules();
  const toggleRule = useToggleRule();
  // null: closed; "new": creating; otherwise the rule being edited.
  const [editing, setEditing] = useState(null);

  const rules = data?.rules ?? [];

  const renderTable = (list) => (
    <div className="rounded-lg border border-border overflow-x-auto">
      <Table label="Detection rules">
        <TableHeader>
          <TableRow>
            <TableHead>Rule</TableHead>
            <TableHead>MITRE</TableHead>
            <TableHead>Min severity</TableHead>
            <TableHead>Last run</TableHead>
            <TableHead>Enabled</TableHead>
            {canEdit && <TableHead className="w-10"></TableHead>}
          </TableRow>
        </TableHeader>
        <TableBody>
          {list.map((rule) => (
            <TableRow key={rule.id}>
              <TableCell>
                <p>{rule.title}</p>
                <div className="flex items-center gap-2">
                  <p className="text-xs text-muted-foreground font-mono">{rule.rule_key}</p>
                  {rule.origin === "custom" && (
                    <Badge variant="outline" className="h-4 px-1.5 text-[10px] border-cyan text-cyan">Custom</Badge>
                  )}
                  {rule.user_modified && (
                    <Badge variant="outline" className="h-4 px-1.5 text-[10px]">Modified</Badge>
                  )}
                </div>
              </TableCell>
              <TableCell className="font-mono text-xs">{rule.mitre_technique ?? "—"}</TableCell>
              <TableCell><SeverityBadge severity={rule.severity} /></TableCell>
              <TableCell><LastRun rule={rule} /></TableCell>
              <TableCell>
                <Switch
                  aria-label={`${rule.enabled ? "Disable" : "Enable"} ${rule.title}`}
                  checked={rule.enabled}
                  disabled={!canEdit || toggleRule.isPending}
                  onCheckedChange={() => toggleRule.mutate(rule.id)}
                />
              </TableCell>
              {canEdit && (
                <TableCell>
                  <Button variant="ghost" size="icon-sm" onClick={() => setEditing(rule)} aria-label={`Edit ${rule.title}`}>
                    <Pencil className="h-3.5 w-3.5" />
                  </Button>
                </TableCell>
              )}
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  );

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h1 className="text-display text-2xl">Detection Rules</h1>
        {isAdmin && (
          <Button onClick={() => setEditing("new")}>
            <Plus className="h-4 w-4" /> New rule
          </Button>
        )}
      </div>
      {!canEdit && (
        <p className="text-sm text-muted-foreground -mt-4">Read-only — analyst or admin role required to edit.</p>
      )}
      {canEdit && !isAdmin && (
        <p className="text-sm text-muted-foreground -mt-4">
          You can rename rules, set their minimum severity and switch them on or off. Creating rules and changing
          what a rule detects is admin-only.
        </p>
      )}

      {isLoading && <p className="text-sm text-muted-foreground">Loading...</p>}

      {!isLoading &&
        SECTIONS.map(([type, heading]) => {
          const list = rules.filter((r) => r.rule_type === type);
          if (type === "sequence" && list.length === 0) return null;
          return (
            <div key={type} className="space-y-3">
              <h2 className="text-sm font-semibold text-muted-foreground uppercase tracking-wide">{heading}</h2>
              {renderTable(list)}
            </div>
          );
        })}

      {editing && (
        <RuleEditorDialog
          key={editing === "new" ? "new" : editing.id}
          rule={editing === "new" ? null : editing}
          isAdmin={isAdmin}
          open={!!editing}
          onOpenChange={(open) => !open && setEditing(null)}
        />
      )}
    </div>
  );
}
