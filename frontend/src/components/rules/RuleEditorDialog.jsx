import { useState } from "react";
import { FlaskConical, RotateCcw, Trash2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { LogText } from "@/components/LogText";
import { ConditionGroup } from "@/components/rules/ConditionBuilder";
import { apiErrorMessage } from "@/lib/errors";
import { RULE_TYPES, definitionFromForm, formFromDefinition } from "@/lib/ruleDefinition";
import { cn } from "@/lib/utils";
import {
  useCreateRule, useDeleteRule, usePreviewRule, useResetRule, useRuleMeta, useUpdateRule,
} from "@/api/hooks";

const SEVERITIES = ["low", "medium", "high", "critical"];
const PREVIEW_HOURS = [1, 24, 72, 168];
const selectClass = "h-9 w-full rounded-md border border-input bg-background px-3 text-sm";
const smallSelect = "h-8 rounded-md border border-input bg-background px-2 text-xs";
const numberClass = "h-8 w-20 font-mono text-xs";

const NEW_RULE_DEFINITION = {
  version: 2,
  filter: { field: "url", op: "contains", value: "" },
  alert: { group_window_minutes: 60 },
};

function Section({ title, children }) {
  return (
    <div className="space-y-2">
      <h3 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">{title}</h3>
      {children}
    </div>
  );
}

function Inline({ children }) {
  return <div className="flex flex-wrap items-center gap-2 text-sm">{children}</div>;
}

function Builder({ form, setForm, meta, isNew }) {
  const set = (patch) => setForm({ ...form, ...patch });
  const setAggregate = (patch) => set({ aggregate: { ...form.aggregate, ...patch } });
  const setSequence = (patch) => set({ sequence: { ...form.sequence, ...patch } });
  const setAlert = (patch) => set({ alert: { ...form.alert, ...patch } });
  const fields = Object.keys(meta?.fields ?? {});

  return (
    <div className="space-y-4">
      <Section title="Rule type">
        <div className="grid gap-2 sm:grid-cols-3">
          {RULE_TYPES.map((t) => (
            <button
              key={t.value}
              type="button"
              disabled={!isNew}
              onClick={() => set({ type: t.value })}
              className={cn(
                "rounded-md border p-2 text-left text-xs transition-colors disabled:cursor-not-allowed",
                form.type === t.value ? "border-cyan bg-cyan/10" : "border-border hover:bg-muted/40 disabled:opacity-50",
              )}
            >
              <p className="font-semibold text-sm">{t.label}</p>
              <p className="text-muted-foreground">{t.hint}</p>
            </button>
          ))}
        </div>
        {!isNew && <p className="text-xs text-muted-foreground">A saved rule keeps its type.</p>}
      </Section>

      <Section title="Log sources">
        <Input
          className="font-mono text-xs"
          placeholder="e.g. nginx, ssh — leave blank for all sources"
          value={form.logsource}
          onChange={(e) => set({ logsource: e.target.value })}
        />
      </Section>

      {form.type === "signature" && (
        <Section title="Alert when an event matches">
          <ConditionGroup node={form.filter} meta={meta} onChange={(filter) => set({ filter })} />
        </Section>
      )}

      {form.type === "threshold" && (
        <>
          <Section title="Which events to count">
            <label className="flex items-center gap-2 text-sm">
              <input type="checkbox" checked={form.useFilter} onChange={(e) => set({ useFilter: e.target.checked })} />
              Only count events that match conditions
            </label>
            {form.useFilter && <ConditionGroup node={form.filter} meta={meta} onChange={(filter) => set({ filter })} />}
          </Section>
          <Section title="Count">
            <Inline>
              <select aria-label="Function" className={smallSelect} value={form.aggregate.function} onChange={(e) => setAggregate({ function: e.target.value })}>
                <option value="count">number of events</option>
                <option value="distinct">distinct values of</option>
              </select>
              {form.aggregate.function === "distinct" && (
                <select aria-label="Distinct field" className={cn(smallSelect, "font-mono")} value={form.aggregate.distinct_field} onChange={(e) => setAggregate({ distinct_field: e.target.value })}>
                  {fields.map((f) => <option key={f} value={f}>{f}</option>)}
                </select>
              )}
              <span>per</span>
              <select aria-label="Group by" className={cn(smallSelect, "font-mono")} value={form.aggregate.group_by} onChange={(e) => setAggregate({ group_by: e.target.value })}>
                {(meta?.group_fields ?? []).map((f) => <option key={f} value={f}>{f}</option>)}
              </select>
              <span>over</span>
              <Input aria-label="Window minutes" type="number" className={numberClass} value={form.aggregate.window_minutes} onChange={(e) => setAggregate({ window_minutes: e.target.value })} />
              <span>minutes; alert when</span>
              <select aria-label="Comparison" className={smallSelect} value={form.aggregate.op} onChange={(e) => setAggregate({ op: e.target.value })}>
                <option value="gte">at least</option>
                <option value="gt">more than</option>
              </select>
              <Input aria-label="Threshold" type="number" className={numberClass} value={form.aggregate.threshold} onChange={(e) => setAggregate({ threshold: e.target.value })} />
            </Inline>
          </Section>
        </>
      )}

      {form.type === "sequence" && (
        <>
          <Section title="Same">
            <select aria-label="Join on" className={cn(smallSelect, "font-mono")} value={form.sequence.join_on} onChange={(e) => setSequence({ join_on: e.target.value })}>
              {(meta?.join_fields ?? []).map((f) => <option key={f} value={f}>{f}</option>)}
            </select>
          </Section>
          <Section title="Step 1">
            <Inline>
              <span>At least</span>
              <Input aria-label="Minimum count" type="number" className={numberClass} value={form.sequence.min_count} onChange={(e) => setSequence({ min_count: e.target.value })} />
              <span>events matching the conditions below, within</span>
              <Input aria-label="Step 1 minutes" type="number" className={numberClass} value={form.sequence.first_within} onChange={(e) => setSequence({ first_within: e.target.value })} />
              <span>minutes</span>
            </Inline>
            <ConditionGroup node={form.sequence.first} meta={meta} onChange={(first) => setSequence({ first })} />
          </Section>
          <Section title="Step 2">
            <Inline>
              <span>Then an event matching the conditions below, within</span>
              <Input aria-label="Step 2 minutes" type="number" className={numberClass} value={form.sequence.then_within} onChange={(e) => setSequence({ then_within: e.target.value })} />
              <span>minutes of the last step 1 event</span>
            </Inline>
            <ConditionGroup node={form.sequence.then} meta={meta} onChange={(then) => setSequence({ then })} />
          </Section>
        </>
      )}

      <Section title="Alert">
        <div className="grid gap-2 sm:grid-cols-2">
          <div className="space-y-1">
            <Label className="text-xs">Scoring signal</Label>
            <select className={cn(selectClass, "font-mono text-xs")} value={form.alert.signal ?? ""} onChange={(e) => setAlert({ signal: e.target.value })}>
              <option value="">none</option>
              {(meta?.signals ?? []).map((s) => <option key={s} value={s}>{s}</option>)}
            </select>
          </div>
          {form.type === "signature" && (
            <div className="space-y-1">
              <Label className="text-xs">Group repeat hits per attacker for (minutes)</Label>
              <Input type="number" className="h-9 font-mono text-xs" value={form.alert.group_window_minutes ?? 60} onChange={(e) => setAlert({ group_window_minutes: e.target.value })} />
            </div>
          )}
        </div>
        <div className="space-y-1">
          <Label className="text-xs">Alert title (optional)</Label>
          <Input
            className="text-xs"
            placeholder="e.g. Suspicious login from {source_ip}"
            value={form.alert.title ?? ""}
            onChange={(e) => setAlert({ title: e.target.value })}
          />
          <p className="text-xs text-muted-foreground">
            Placeholders: {(meta?.title_placeholders ?? []).map((p) => `{${p}}`).join(" ")}. Blank uses the rule title.
          </p>
        </div>
      </Section>
    </div>
  );
}

function PreviewResult({ result }) {
  return (
    <div className="space-y-2 rounded-md border border-border p-3">
      <p className="text-sm">
        <span className="font-mono font-semibold">{result.matches}</span>
        {result.rule_type === "signature" ? " matching events" : result.rule_type === "threshold" ? " windows over the threshold" : " completed sequences"}
        {" from "}
        <span className="font-mono font-semibold">{result.groups}</span> {result.groups === 1 ? "source" : "sources"} in the last {result.hours} h
        {result.truncated && " (stopped counting at the cap)"}. Nothing was saved.
      </p>
      {result.rule_type === "threshold" && (
        <p className="text-xs text-muted-foreground">
          Counted in fixed windows here, so a burst split across two windows may not show up; live detection looks back from every run.
        </p>
      )}
      {result.samples.length > 0 && (
        <div className="max-h-56 overflow-auto">
          <table className="w-full text-xs">
            <thead className="text-muted-foreground">
              <tr><th className="py-1 pr-2 text-left font-normal">Time</th><th className="py-1 pr-2 text-left font-normal">Source</th><th className="py-1 text-left font-normal">Detail</th></tr>
            </thead>
            <tbody>
              {result.samples.map((s, i) => (
                <tr key={i} className="border-t border-border align-top">
                  <td className="py-1 pr-2 whitespace-nowrap">{s.time ? new Date(s.time).toLocaleString() : "—"}</td>
                  <td className="py-1 pr-2 font-mono"><LogText value={s.group} /></td>
                  <td className="py-1 font-mono break-all"><LogText value={s.detail} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

export function RuleEditorDialog({ rule, isAdmin, open, onOpenChange }) {
  const isNew = !rule;
  const { data: meta } = useRuleMeta();
  const createRule = useCreateRule();
  const updateRule = useUpdateRule();
  const resetRule = useResetRule();
  const deleteRule = useDeleteRule();
  const previewRule = usePreviewRule();

  const [ruleKey, setRuleKey] = useState("");
  const [title, setTitle] = useState(rule?.title ?? "");
  const [description, setDescription] = useState(rule?.description ?? "");
  const [severity, setSeverity] = useState(rule?.severity ?? "medium");
  const [mitre, setMitre] = useState(rule?.mitre_technique ?? "");
  const [form, setForm] = useState(() => formFromDefinition(rule?.definition ?? NEW_RULE_DEFINITION));
  const [tab, setTab] = useState("builder");
  const [jsonText, setJsonText] = useState("");
  const [previewHours, setPreviewHours] = useState(24);
  const [confirming, setConfirming] = useState(null); // "reset" | "delete"
  const [error, setError] = useState(null);

  const canReset = isAdmin && rule?.origin === "builtin" && rule?.user_modified;
  const canDelete = isAdmin && rule?.origin === "custom";

  // The definition as currently edited, from whichever tab is showing.
  const currentDefinition = () => {
    if (tab === "json") {
      try {
        return JSON.parse(jsonText);
      } catch {
        throw new Error("Detection logic must be valid JSON");
      }
    }
    return definitionFromForm(form, meta);
  };

  const switchTab = (next) => {
    setError(null);
    if (next === tab) return;
    if (next === "json") {
      setJsonText(JSON.stringify(definitionFromForm(form, meta), null, 2));
      setTab("json");
      return;
    }
    try {
      setForm(formFromDefinition(JSON.parse(jsonText)));
      setTab("builder");
    } catch {
      setError("Fix the JSON before switching back to the builder");
    }
  };

  const run = async (action) => {
    setError(null);
    try {
      await action();
    } catch (err) {
      setError(err instanceof Error && !err.response ? err.message : apiErrorMessage(err, "Something went wrong"));
    }
  };

  const handleSave = () =>
    run(async () => {
      if (isNew) {
        await createRule.mutateAsync({
          rule_key: ruleKey.trim(), title, description: description || null, severity,
          mitre_technique: mitre || null, definition: currentDefinition(),
        });
      } else {
        const body = { title, description, severity };
        if (isAdmin) body.definition = currentDefinition();
        await updateRule.mutateAsync({ ruleId: rule.id, body });
      }
      onOpenChange(false);
    });

  const handlePreview = () =>
    run(() => previewRule.mutateAsync({ definition: currentDefinition(), hours: previewHours }));

  const handleConfirmed = (kind, action) => {
    if (confirming !== kind) {
      setConfirming(kind);
      return;
    }
    run(async () => {
      await action();
      onOpenChange(false);
    }).finally(() => setConfirming(null));
  };

  const saving = createRule.isPending || updateRule.isPending;

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[90vh] overflow-y-auto sm:max-w-3xl">
        <DialogHeader>
          <DialogTitle>{isNew ? "New detection rule" : "Edit rule"}</DialogTitle>
          <DialogDescription className="font-mono text-xs">
            {isNew ? "Custom rules are checked by the server before they are saved." : rule.rule_key}
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4">
          <div className="grid gap-3 sm:grid-cols-2">
            {isNew && (
              <div className="space-y-1.5">
                <Label htmlFor="rule-key">Rule key</Label>
                <Input id="rule-key" className="font-mono" placeholder="e.g. admin-panel-probe" value={ruleKey} onChange={(e) => setRuleKey(e.target.value)} />
                <p className="text-xs text-muted-foreground">Lowercase letters, digits, - and _. Can't be changed later.</p>
              </div>
            )}
            <div className="space-y-1.5">
              <Label htmlFor="rule-title">Title</Label>
              <Input id="rule-title" value={title} onChange={(e) => setTitle(e.target.value)} />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="rule-severity">Minimum severity</Label>
              <select id="rule-severity" className={selectClass} value={severity} onChange={(e) => setSeverity(e.target.value)}>
                {SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}
              </select>
            </div>
            {isNew && (
              <div className="space-y-1.5">
                <Label htmlFor="rule-mitre">MITRE ATT&amp;CK technique</Label>
                <select id="rule-mitre" className={cn(selectClass, "font-mono text-xs")} value={mitre} onChange={(e) => setMitre(e.target.value)}>
                  <option value="">none</option>
                  {(meta?.techniques ?? []).map((t) => <option key={t.id} value={t.id}>{t.id} — {t.name}</option>)}
                </select>
              </div>
            )}
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="rule-description">Description</Label>
            <Textarea id="rule-description" rows={2} value={description} onChange={(e) => setDescription(e.target.value)} />
            <p className="text-xs text-muted-foreground">Alerts never rank below the minimum severity. Threat intel can still raise them.</p>
          </div>

          {isAdmin ? (
            <div className="space-y-3">
              <div className="flex items-center gap-1 border-b border-border">
                {[["builder", "Builder"], ["json", "JSON"]].map(([value, label]) => (
                  <button
                    key={value}
                    type="button"
                    onClick={() => switchTab(value)}
                    className={cn(
                      "-mb-px border-b-2 px-3 py-1.5 text-sm",
                      tab === value ? "border-cyan text-foreground" : "border-transparent text-muted-foreground hover:text-foreground",
                    )}
                  >
                    {label}
                  </button>
                ))}
              </div>
              {tab === "builder" ? (
                <Builder form={form} setForm={setForm} meta={meta} isNew={isNew} />
              ) : (
                <Textarea aria-label="Definition JSON" className="font-mono text-xs" rows={18} value={jsonText} onChange={(e) => setJsonText(e.target.value)} />
              )}

              <div className="flex flex-wrap items-center gap-2">
                <Button variant="outline" onClick={handlePreview} disabled={previewRule.isPending}>
                  <FlaskConical className="h-3.5 w-3.5" />
                  {previewRule.isPending ? "Testing..." : "Test rule"}
                </Button>
                <span className="text-xs text-muted-foreground">against the last</span>
                <select aria-label="Preview range" className={smallSelect} value={previewHours} onChange={(e) => setPreviewHours(Number(e.target.value))}>
                  {PREVIEW_HOURS.map((h) => <option key={h} value={h}>{h === 168 ? "7 days" : `${h} h`}</option>)}
                </select>
                <span className="text-xs text-muted-foreground">of events — no alerts are created</span>
              </div>
              {previewRule.data && !previewRule.isPending && <PreviewResult result={previewRule.data} />}
            </div>
          ) : (
            <div className="space-y-1.5">
              <Label>Detection logic</Label>
              <pre className="max-h-48 overflow-auto rounded-md border border-border bg-muted/40 p-3 font-mono text-xs">
                {JSON.stringify(rule.definition, null, 2)}
              </pre>
              <p className="text-xs text-muted-foreground">Only admins can change what a rule detects.</p>
            </div>
          )}

          {rule?.last_error && (
            <p className="text-xs text-destructive">
              Last run failed{rule.last_error_at ? ` (${new Date(rule.last_error_at).toLocaleString()})` : ""}: {rule.last_error}
            </p>
          )}
          {rule?.user_modified && (
            <p className="text-xs text-muted-foreground">
              Edited{rule.updated_at ? ` ${new Date(rule.updated_at).toLocaleString()}` : ""}. Kept across restarts instead of following the shipped default.
            </p>
          )}
          {error && <p className="text-sm text-destructive">{error}</p>}
        </div>

        <DialogFooter className="gap-2 sm:justify-between">
          <div className="flex gap-2">
            {canReset && (
              <Button variant="ghost" onClick={() => handleConfirmed("reset", () => resetRule.mutateAsync(rule.id))} disabled={resetRule.isPending}>
                <RotateCcw className="h-3.5 w-3.5" />
                {confirming === "reset" ? "Confirm reset to default" : "Reset to default"}
              </Button>
            )}
            {canDelete && (
              <Button variant="ghost" className="text-destructive" onClick={() => handleConfirmed("delete", () => deleteRule.mutateAsync(rule.id))} disabled={deleteRule.isPending}>
                <Trash2 className="h-3.5 w-3.5" />
                {confirming === "delete" ? "Confirm delete" : "Delete"}
              </Button>
            )}
          </div>
          <div className="flex gap-2">
            <Button variant="outline" onClick={() => onOpenChange(false)}>Cancel</Button>
            <Button onClick={handleSave} disabled={saving}>
              {saving ? "Saving..." : isNew ? "Create rule" : "Save"}
            </Button>
          </div>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
