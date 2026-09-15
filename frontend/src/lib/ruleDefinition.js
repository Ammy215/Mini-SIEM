// Converts between a v2 rule definition (what the API stores) and the editable
// form the rule builder works on. The server validates every definition; this
// only shapes what the builder sends.

export const LIST_OPS = ["in", "contains_any"];
export const RAW_FIELD = /^raw\.[A-Za-z0-9_]{1,64}$/;

let nextId = 1;
const newId = () => `node-${nextId++}`;

export const RULE_TYPES = [
  { value: "signature", label: "Signature", hint: "Alert on events that match conditions" },
  { value: "threshold", label: "Threshold", hint: "Count matching events per group over a time window" },
  { value: "sequence", label: "Sequence", hint: "Some matching events, then another one, from the same source" },
];

export function fieldType(field, meta) {
  if (meta?.fields?.[field]) return meta.fields[field];
  return RAW_FIELD.test(field ?? "") ? "text" : null;
}

export function newLeaf(field = "url", op = "contains") {
  return { id: newId(), kind: "leaf", negate: false, field, op, value: "" };
}

export function newGroup(mode = "all", children) {
  return { id: newId(), kind: "group", negate: false, mode, children: children ?? [newLeaf()] };
}

// --- definition -> editor ---------------------------------------------------------

function valueToText(value) {
  if (Array.isArray(value)) return value.join("\n");
  return value == null ? "" : String(value);
}

function fromCondition(condition, negate = false) {
  if (condition && Object.keys(condition).length === 1 && "not" in condition) {
    return fromCondition(condition.not, !negate);
  }
  if (condition && ("all" in condition || "any" in condition)) {
    const mode = "all" in condition ? "all" : "any";
    return { id: newId(), kind: "group", negate, mode, children: (condition[mode] ?? []).map((c) => fromCondition(c)) };
  }
  return {
    id: newId(), kind: "leaf", negate,
    field: condition?.field ?? "url", op: condition?.op ?? "contains", value: valueToText(condition?.value),
  };
}

// The builder always edits a group at the top, so there's somewhere to add conditions.
function rootFrom(condition) {
  if (!condition) return newGroup("all");
  const node = fromCondition(condition);
  return node.kind === "group" && !node.negate ? node : newGroup("all", [node]);
}

export function formFromDefinition(definition) {
  const d = definition ?? {};
  const type = d.sequence ? "sequence" : d.aggregate ? "threshold" : "signature";
  return {
    type,
    logsource: (d.logsource ?? []).join(", "),
    useFilter: type !== "threshold" || Boolean(d.filter),
    filter: rootFrom(d.filter),
    aggregate: {
      group_by: "source_ip", window_minutes: 5, function: "count", distinct_field: "username", op: "gte", threshold: 10,
      ...d.aggregate,
    },
    sequence: {
      join_on: d.sequence?.join_on ?? "source_ip",
      min_count: d.sequence?.first?.min_count ?? 5,
      first_within: d.sequence?.first?.within_minutes ?? 10,
      then_within: d.sequence?.then?.within_minutes ?? 10,
      first: rootFrom(d.sequence?.first?.filter),
      then: rootFrom(d.sequence?.then?.filter),
    },
    // Kept whole, so settings the builder doesn't show (count_key, values_key…) survive a save.
    alert: { ...(d.alert ?? {}) },
  };
}

// --- editor -> definition ---------------------------------------------------------

function textToValue(node, meta) {
  const isInt = fieldType(node.field, meta) === "int";
  const convert = (text) => (isInt && /^\s*-?\d+\s*$/.test(text) ? Number(text) : text);
  if (LIST_OPS.includes(node.op)) {
    return node.value.split("\n").filter((line) => line.trim() !== "").map((line) => convert(isInt ? line.trim() : line));
  }
  return convert(node.value);
}

function toCondition(node, meta) {
  let out;
  if (node.kind === "group") {
    out = { [node.mode]: node.children.map((child) => toCondition(child, meta)) };
  } else {
    out = { field: node.field, op: node.op };
    if (node.op !== "exists") out.value = textToValue(node, meta);
  }
  return node.negate ? { not: out } : out;
}

function rootToCondition(root, meta) {
  if (!root.negate && root.children.length === 1) return toCondition(root.children[0], meta);
  return toCondition(root, meta);
}

const ALERT_KEYS_BY_TYPE = {
  signature: ["signal", "title", "group_by", "group_window_minutes"],
  threshold: ["signal", "title", "count_key", "values_key", "values_field"],
  sequence: ["signal", "title", "count_key"],
};

function alertFromForm(alert, type) {
  const out = {};
  for (const key of ALERT_KEYS_BY_TYPE[type]) {
    const value = alert[key];
    if (value === undefined || value === null || value === "") continue;
    out[key] = key === "group_window_minutes" ? Number(value) : value;
  }
  return out;
}

export function definitionFromForm(form, meta) {
  const definition = { version: 2 };
  const logsource = form.logsource.split(",").map((s) => s.trim()).filter(Boolean);
  if (logsource.length) definition.logsource = logsource;

  if (form.type === "sequence") {
    const s = form.sequence;
    definition.sequence = {
      join_on: s.join_on,
      first: { filter: rootToCondition(s.first, meta), min_count: Number(s.min_count), within_minutes: Number(s.first_within) },
      then: { filter: rootToCondition(s.then, meta), within_minutes: Number(s.then_within) },
    };
  } else {
    if (form.type === "signature" || form.useFilter) definition.filter = rootToCondition(form.filter, meta);
    if (form.type === "threshold") {
      const a = form.aggregate;
      definition.aggregate = {
        group_by: a.group_by,
        window_minutes: Number(a.window_minutes),
        function: a.function,
        ...(a.function === "distinct" ? { distinct_field: a.distinct_field } : {}),
        op: a.op,
        threshold: Number(a.threshold),
      };
    }
  }

  const alert = alertFromForm(form.alert, form.type);
  if (Object.keys(alert).length) definition.alert = alert;
  return definition;
}
