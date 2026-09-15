import { useState } from "react";
import { Pencil, RotateCcw } from "lucide-react";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { SeverityBadge } from "@/components/ui/severity-badge";
import { Badge } from "@/components/ui/badge";
import { Switch } from "@/components/ui/switch";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from "@/components/ui/dialog";
import { useAuth } from "@/api/AuthContext";
import { useResetRule, useRules, useToggleRule, useUpdateRule } from "@/api/hooks";

const SEVERITIES = ["low", "medium", "high", "critical"];

// FastAPI sends `detail` as a string for errors the API raises itself, and as
// a list of {loc, msg} objects for request-shape validation errors.
function errorMessage(err, fallback) {
  const detail = err.response?.data?.detail;
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail)) return detail.map((d) => d.msg).join("; ");
  return fallback;
}

function EditRuleDialog({ rule, isAdmin, open, onOpenChange }) {
  const updateRule = useUpdateRule();
  const resetRule = useResetRule();
  const [title, setTitle] = useState(rule.title);
  const [description, setDescription] = useState(rule.description ?? "");
  const [severity, setSeverity] = useState(rule.severity);
  const [definitionText, setDefinitionText] = useState(JSON.stringify(rule.definition, null, 2));
  const [confirmingReset, setConfirmingReset] = useState(false);
  const [error, setError] = useState(null);

  const canReset = isAdmin && rule.origin === "builtin" && rule.user_modified;

  const handleSave = async () => {
    setError(null);
    const body = { title, description, severity };
    if (isAdmin) {
      try {
        body.definition = JSON.parse(definitionText);
      } catch {
        setError("Detection logic must be valid JSON");
        return;
      }
    }
    try {
      await updateRule.mutateAsync({ ruleId: rule.id, body });
      onOpenChange(false);
    } catch (err) {
      setError(errorMessage(err, "Failed to save rule"));
    }
  };

  const handleReset = async () => {
    if (!confirmingReset) {
      setConfirmingReset(true);
      return;
    }
    setError(null);
    try {
      await resetRule.mutateAsync(rule.id);
      onOpenChange(false);
    } catch (err) {
      setError(errorMessage(err, "Failed to reset rule"));
      setConfirmingReset(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>Edit rule</DialogTitle>
          <DialogDescription className="font-mono text-xs">{rule.rule_key}</DialogDescription>
        </DialogHeader>
        <div className="space-y-3">
          <div className="space-y-1.5">
            <Label htmlFor="rule-title">Title</Label>
            <Input id="rule-title" value={title} onChange={(e) => setTitle(e.target.value)} />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="rule-description">Description</Label>
            <Textarea
              id="rule-description"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              rows={2}
            />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="rule-severity">Minimum severity</Label>
            <select
              id="rule-severity"
              className="h-9 w-full rounded-md border border-input bg-background px-3 text-sm"
              value={severity}
              onChange={(e) => setSeverity(e.target.value)}
            >
              {SEVERITIES.map((s) => (
                <option key={s} value={s}>{s}</option>
              ))}
            </select>
            <p className="text-xs text-muted-foreground">
              Alerts from this rule never rank below this. Threat intel can still raise them higher.
            </p>
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="rule-definition">Detection logic (JSON)</Label>
            {isAdmin ? (
              <Textarea
                id="rule-definition"
                className="font-mono text-xs"
                rows={14}
                value={definitionText}
                onChange={(e) => setDefinitionText(e.target.value)}
              />
            ) : (
              <>
                <pre
                  id="rule-definition"
                  className="max-h-48 overflow-auto rounded-md border border-border bg-muted/40 p-3 font-mono text-xs"
                >
                  {JSON.stringify(rule.definition, null, 2)}
                </pre>
                <p className="text-xs text-muted-foreground">Only admins can change what a rule detects.</p>
              </>
            )}
          </div>
          {rule.user_modified && (
            <p className="text-xs text-muted-foreground">
              Edited{rule.updated_at ? ` ${new Date(rule.updated_at).toLocaleString()}` : ""}. Kept across
              restarts instead of following the shipped default.
            </p>
          )}
          {error && <p className="text-sm text-destructive">{error}</p>}
        </div>
        <DialogFooter className="sm:justify-between">
          {canReset ? (
            <Button variant="ghost" onClick={handleReset} disabled={resetRule.isPending}>
              <RotateCcw className="h-3.5 w-3.5" />
              {confirmingReset ? "Confirm reset to default" : "Reset to default"}
            </Button>
          ) : (
            <span />
          )}
          <div className="flex gap-2">
            <Button variant="outline" onClick={() => onOpenChange(false)}>Cancel</Button>
            <Button onClick={handleSave} disabled={updateRule.isPending}>
              {updateRule.isPending ? "Saving..." : "Save"}
            </Button>
          </div>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export default function Rules() {
  const { user } = useAuth();
  const roles = user?.roles ?? [];
  const isAdmin = roles.includes("admin");
  const canEdit = isAdmin || roles.includes("analyst");
  const { data, isLoading } = useRules();
  const toggleRule = useToggleRule();
  const [editingRule, setEditingRule] = useState(null);

  const rules = data?.rules ?? [];
  const threshold = rules.filter((r) => r.rule_type === "threshold");
  const signature = rules.filter((r) => r.rule_type === "signature");

  const renderTable = (list) => (
    <div className="rounded-lg border border-border overflow-hidden">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Rule</TableHead>
            <TableHead>MITRE</TableHead>
            <TableHead>Min severity</TableHead>
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
                  {rule.user_modified && (
                    <Badge variant="outline" className="h-4 px-1.5 text-[10px]">Modified</Badge>
                  )}
                </div>
              </TableCell>
              <TableCell className="font-mono text-xs">{rule.mitre_technique ?? "—"}</TableCell>
              <TableCell><SeverityBadge severity={rule.severity} /></TableCell>
              <TableCell>
                <Switch
                  checked={rule.enabled}
                  disabled={!canEdit || toggleRule.isPending}
                  onCheckedChange={() => toggleRule.mutate(rule.id)}
                />
              </TableCell>
              {canEdit && (
                <TableCell>
                  <Button variant="ghost" size="icon-sm" onClick={() => setEditingRule(rule)} aria-label={`Edit ${rule.title}`}>
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
      <h1 className="text-2xl font-bold">Detection Rules</h1>
      {!canEdit && (
        <p className="text-sm text-muted-foreground -mt-4">Read-only — analyst or admin role required to edit.</p>
      )}
      {canEdit && !isAdmin && (
        <p className="text-sm text-muted-foreground -mt-4">
          You can rename rules, set their minimum severity and switch them on or off. Changing what a rule
          detects is admin-only.
        </p>
      )}

      {isLoading && <p className="text-sm text-muted-foreground">Loading...</p>}

      {!isLoading && (
        <>
          <div className="space-y-3">
            <h2 className="text-sm font-semibold text-muted-foreground uppercase tracking-wide">Threshold Rules</h2>
            {renderTable(threshold)}
          </div>
          <div className="space-y-3">
            <h2 className="text-sm font-semibold text-muted-foreground uppercase tracking-wide">Signature Rules</h2>
            {renderTable(signature)}
          </div>
        </>
      )}

      {editingRule && (
        <EditRuleDialog
          key={editingRule.id}
          rule={editingRule}
          isAdmin={isAdmin}
          open={!!editingRule}
          onOpenChange={(open) => !open && setEditingRule(null)}
        />
      )}
    </div>
  );
}
