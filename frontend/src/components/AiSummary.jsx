import { Loader2, RotateCw, Sparkles } from "lucide-react";
import { apiErrorMessage } from "@/lib/errors";
import { Button } from "@/components/ui/button";
import { useAuth } from "@/api/AuthContext";

// Opt-in per click. The summary is rendered as plain text (React escapes it),
// so a prompt-injected response can't inject markup into the page.
export function AiSummary({ kind, targetId, useSummarize }) {
  const { user } = useAuth();
  const { mutate, data, isPending, isError, error } = useSummarize();

  const canUse = user?.roles?.some((r) => ["analyst", "admin"].includes(r));
  if (!canUse) return null;

  const run = () => mutate(targetId);

  return (
    <div className="rounded-md border border-border bg-card/60 p-3 space-y-2">
      {!data && (
        <div className="flex flex-wrap items-center gap-3">
          <Button size="sm" variant="outline" onClick={run} disabled={isPending}>
            {isPending ? (
              <Loader2 className="h-4 w-4 mr-1.5 animate-spin" />
            ) : (
              <Sparkles className="h-4 w-4 mr-1.5 text-primary" />
            )}
            {isPending ? "Summarizing…" : "Summarize with AI"}
          </Button>
          <span className="text-xs text-muted-foreground">
            Sends this {kind}&apos;s evidence (matched pattern, source IP, MITRE tag, severity) to Groq.
          </span>
        </div>
      )}

      {isError && (
        <p className="text-sm text-destructive">
          {apiErrorMessage(error, "Could not generate a summary.")}
        </p>
      )}

      {data && (
        <div className="space-y-2">
          <div className="flex items-center justify-between gap-3">
            <span className="flex items-center gap-1.5 text-xs text-muted-foreground">
              <Sparkles className="h-3.5 w-3.5 text-primary" />
              AI summary · <span className="font-mono">{data.model}</span>
            </span>
            <Button size="sm" variant="ghost" onClick={run} disabled={isPending}>
              <RotateCw className={`h-3.5 w-3.5 mr-1.5 ${isPending ? "animate-spin" : ""}`} />
              Regenerate
            </Button>
          </div>
          <p className="text-sm leading-relaxed whitespace-pre-wrap">{data.summary}</p>
          <p className="text-xs text-muted-foreground">
            AI-generated from this {kind}&apos;s evidence. Verify against the evidence before acting.
          </p>
        </div>
      )}
    </div>
  );
}
