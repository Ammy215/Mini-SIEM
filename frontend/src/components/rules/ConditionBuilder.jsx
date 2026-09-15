import { Plus, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { cn } from "@/lib/utils";
import { LIST_OPS, fieldType, newGroup, newLeaf } from "@/lib/ruleDefinition";

const RAW_OPTION = "__raw__";
const selectClass = "h-8 rounded-md border border-input bg-background px-2 text-xs";

const OP_LABELS = {
  eq: "equals", neq: "does not equal", in: "is one of", contains: "contains", contains_any: "contains any of",
  startswith: "starts with", endswith: "ends with", regex: "matches regex", exists: "has a value",
  gt: ">", gte: "≥", lt: "<", lte: "≤", cidr: "is in CIDR range",
};

function NotToggle({ checked, onChange }) {
  return (
    <label className="flex items-center gap-1 text-xs text-muted-foreground">
      <input type="checkbox" checked={checked} onChange={(e) => onChange(e.target.checked)} />
      NOT
    </label>
  );
}

function ConditionRow({ node, onChange, onRemove, meta }) {
  const fields = Object.keys(meta?.fields ?? {});
  const isRaw = node.field.startsWith("raw.");
  const type = fieldType(node.field, meta) ?? "text";
  const ops = meta?.operators?.[type] ?? [];
  const update = (patch) => onChange({ ...node, ...patch });

  const setField = (field) => {
    const nextOps = meta?.operators?.[fieldType(field, meta) ?? "text"] ?? [];
    update({ field, op: nextOps.includes(node.op) ? node.op : nextOps[0] });
  };

  return (
    <div className="flex flex-wrap items-start gap-2 rounded-md bg-muted/30 p-2">
      <NotToggle checked={node.negate} onChange={(negate) => update({ negate })} />
      <select
        aria-label="Field"
        className={cn(selectClass, "font-mono")}
        value={isRaw ? RAW_OPTION : node.field}
        onChange={(e) => setField(e.target.value === RAW_OPTION ? "raw." : e.target.value)}
      >
        {fields.map((f) => <option key={f} value={f}>{f}</option>)}
        <option value={RAW_OPTION}>raw.&lt;key&gt;…</option>
      </select>
      {isRaw && (
        <Input
          aria-label="Raw key"
          className="h-8 w-32 font-mono text-xs"
          placeholder="key"
          value={node.field.slice(4)}
          onChange={(e) => update({ field: `raw.${e.target.value}` })}
        />
      )}
      <select aria-label="Operator" className={selectClass} value={node.op} onChange={(e) => update({ op: e.target.value })}>
        {ops.map((op) => <option key={op} value={op}>{OP_LABELS[op] ?? op}</option>)}
      </select>
      {node.op !== "exists" && (LIST_OPS.includes(node.op) ? (
        <Textarea
          aria-label="Values, one per line"
          className="min-h-16 flex-1 basis-48 font-mono text-xs"
          rows={3}
          placeholder="one value per line"
          value={node.value}
          onChange={(e) => update({ value: e.target.value })}
        />
      ) : (
        <Input
          aria-label="Value"
          className="h-8 flex-1 basis-40 font-mono text-xs"
          type={type === "int" ? "number" : "text"}
          placeholder={node.op === "cidr" ? "10.0.0.0/8" : "value"}
          value={node.value}
          onChange={(e) => update({ value: e.target.value })}
        />
      ))}
      <Button variant="ghost" size="icon-sm" onClick={onRemove} aria-label="Remove condition">
        <X className="h-3.5 w-3.5" />
      </Button>
    </div>
  );
}

export function ConditionGroup({ node, onChange, onRemove, meta, depth = 1 }) {
  const maxDepth = meta?.limits?.max_depth ?? 4;
  const update = (patch) => onChange({ ...node, ...patch });
  const setChild = (index, child) => update({ children: node.children.map((c, i) => (i === index ? child : c)) });
  const removeChild = (index) => update({ children: node.children.filter((_, i) => i !== index) });

  return (
    <div className={cn("space-y-2 rounded-md border border-border p-2", depth > 1 && "border-dashed")}>
      <div className="flex flex-wrap items-center gap-2">
        <NotToggle checked={node.negate} onChange={(negate) => update({ negate })} />
        <select aria-label="Match" className={selectClass} value={node.mode} onChange={(e) => update({ mode: e.target.value })}>
          <option value="all">ALL of these</option>
          <option value="any">ANY of these</option>
        </select>
        <div className="ml-auto flex gap-1">
          <Button variant="ghost" size="sm" onClick={() => update({ children: [...node.children, newLeaf()] })}>
            <Plus className="h-3.5 w-3.5" /> Condition
          </Button>
          {depth < maxDepth - 1 && (
            <Button variant="ghost" size="sm" onClick={() => update({ children: [...node.children, newGroup("any")] })}>
              <Plus className="h-3.5 w-3.5" /> Group
            </Button>
          )}
          {onRemove && (
            <Button variant="ghost" size="icon-sm" onClick={onRemove} aria-label="Remove group">
              <X className="h-3.5 w-3.5" />
            </Button>
          )}
        </div>
      </div>
      {node.children.length === 0 && <p className="text-xs text-muted-foreground">Add at least one condition.</p>}
      {node.children.map((child, index) =>
        child.kind === "group" ? (
          <ConditionGroup
            key={child.id}
            node={child}
            depth={depth + 1}
            meta={meta}
            onChange={(c) => setChild(index, c)}
            onRemove={() => removeChild(index)}
          />
        ) : (
          <ConditionRow
            key={child.id}
            node={child}
            meta={meta}
            onChange={(c) => setChild(index, c)}
            onRemove={() => removeChild(index)}
          />
        ),
      )}
    </div>
  );
}
