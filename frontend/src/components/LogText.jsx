import { cn } from "@/lib/utils";

// Unicode bidirectional control characters reorder the text drawn after them.
// In log content they are a spoofing trick: a username stored as
// "ADVTEST\u202Egnp.exe" renders as "ADVTESTexe.png". React escapes HTML, but
// it still lets these characters do their job — so they are shown as visible
// markers instead, and the value is highlighted.
const BIDI_CONTROL = /[\u202A-\u202E\u2066-\u2069]/;
const BIDI_CONTROLS = /[\u202A-\u202E\u2066-\u2069]/g;

export function revealBidiControls(value) {
  if (value == null) return value;
  return String(value).replace(
    BIDI_CONTROLS,
    (char) => `[U+${char.codePointAt(0).toString(16).toUpperCase()}]`,
  );
}

/** Renders a value that came from log data (usernames, URLs, filenames, titles). */
export function LogText({ value, fallback = "—", className }) {
  if (value == null || value === "") return <>{fallback}</>;
  const text = String(value);
  const spoofed = BIDI_CONTROL.test(text);
  return (
    <span
      className={cn(spoofed && "text-amber", className)}
      title={spoofed ? "Contains hidden text-direction characters, shown here as [U+…]" : undefined}
    >
      {spoofed ? revealBidiControls(text) : text}
    </span>
  );
}
