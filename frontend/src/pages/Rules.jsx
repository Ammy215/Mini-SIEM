import { useState } from "react";
import { Pencil } from "lucide-react";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { SeverityBadge } from "@/components/ui/severity-badge";
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
import { useRules, useToggleRule, useUpdateRule } from "@/api/hooks";

function EditRuleDialog({ rule, open, onOpenChange }) {
  const updateRule = useUpdateRule();
  const [title, setTitle] = useState(rule.title);
  const [description, setDescription] = useState(rule.description ?? "");
  const [severity, setSeverity] = useState(rule.severity);
  const [definitionText, setDefinitionText] = useState(JSON.stringify(rule.definition, null, 2));
  const [error, setError] = useState(null);

  const handleSave = async () => {
    setError(null);
    let definition;
    try {
      definition = JSON.parse(definitionText);
    } catch {
      setError("Definition must be valid JSON");
      return;
    }
    try {
      await updateRule.mutateAsync({ ruleId: rule.id, body: { title, description, severity, definition } });
      onOpenChange(false);
    } catch (err) {
      setError(err.response?.data?.detail ?? "Failed to save rule");
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>Edit rule</DialogTitle>
          <DialogDescription className="font-mono text-xs">{rule?.rule_key}</DialogDescription>
        </DialogHeader>
        <div className="space-y-3">
          <div className="space-y-1.5">
            <Label>Title</Label>
            <Input value={title} onChange={(e) => setTitle(e.target.value)} />
          </div>
          <div className="space-y-1.5">
            <Label>Description</Label>
            <Textarea value={description} onChange={(e) => setDescription(e.target.value)} rows={2} />
          </div>
          <div className="space-y-1.5">
            <Label>Severity</Label>
            <select
              className="h-9 w-full rounded-md border border-input bg-background px-3 text-sm"
              value={severity}
              onChange={(e) => setSeverity(e.target.value)}
            >
              {["low", "medium", "high", "critical"].map((s) => (
                <option key={s} value={s}>{s}</option>
              ))}
            </select>
          </div>
          <div className="space-y-1.5">
            <Label>Definition (JSON)</Label>
            <Textarea
              className="font-mono text-xs"
              rows={8}
              value={definitionText}
              onChange={(e) => setDefinitionText(e.target.value)}
            />
          </div>
          {error && <p className="text-sm text-destructive">{error}</p>}
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>Cancel</Button>
          <Button onClick={handleSave} disabled={updateRule.isPending}>
            {updateRule.isPending ? "Saving..." : "Save"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export default function Rules() {
  const { user } = useAuth();
  const canEdit = user?.roles?.some((r) => ["analyst", "admin"].includes(r));
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
            <TableHead>Severity</TableHead>
            <TableHead>Enabled</TableHead>
            {canEdit && <TableHead className="w-10"></TableHead>}
          </TableRow>
        </TableHeader>
        <TableBody>
          {list.map((rule) => (
            <TableRow key={rule.id}>
              <TableCell>
                <p>{rule.title}</p>
                <p className="text-xs text-muted-foreground font-mono">{rule.rule_key}</p>
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
                  <Button variant="ghost" size="icon-sm" onClick={() => setEditingRule(rule)}>
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
          open={!!editingRule}
          onOpenChange={(open) => !open && setEditingRule(null)}
        />
      )}
    </div>
  );
}
