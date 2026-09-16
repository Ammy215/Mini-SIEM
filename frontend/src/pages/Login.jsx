import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { motion } from "framer-motion";
import { AlertCircle, Eye, EyeOff, Loader2, Shield } from "lucide-react";
import { useAuth } from "@/api/AuthContext";
import { cn } from "@/lib/utils";
import { AmbientField } from "@/components/AmbientField";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

// Real figures from this build, not filler: 15 shipped rules, the 12 ATT&CK
// techniques they cover, and the 11 formats the ingest pipeline reads.
const CAPABILITIES = [
  { figure: "15", label: "Detection rules", detail: "threshold, signature, sequence" },
  { figure: "12", label: "ATT&CK techniques", detail: "tagged on every alert" },
  { figure: "11", label: "Log formats", detail: "auto-detected on upload" },
];

const rise = {
  hidden: { opacity: 0, y: 14 },
  show: (i = 0) => ({
    opacity: 1,
    y: 0,
    transition: { delay: 0.06 * i, duration: 0.5, ease: [0.22, 1, 0.36, 1] },
  }),
};

/**
 * Whether the API is actually reachable, from the one endpoint that needs no
 * token. Worth showing here: if the backend is down, that is better learned
 * before typing a password than after a failed sign-in that looks like a
 * wrong one.
 */
function useApiStatus() {
  const [status, setStatus] = useState({ state: "checking" });
  useEffect(() => {
    const controller = new AbortController();
    const base = import.meta.env.VITE_API_BASE_URL ?? "";
    fetch(`${base}/api/health`, { signal: controller.signal })
      .then((r) => (r.ok ? r.json() : Promise.reject(new Error(String(r.status)))))
      .then((body) =>
        setStatus({
          state: body?.database === "up" ? "online" : "degraded",
          database: body?.database,
        }),
      )
      .catch((err) => {
        if (err.name !== "AbortError") setStatus({ state: "unreachable" });
      });
    return () => controller.abort();
  }, []);
  return status;
}

const STATUS_COPY = {
  checking: { dot: "bg-muted-foreground", text: "Checking the console…" },
  online: { dot: "bg-siem-green", text: "Console online" },
  degraded: { dot: "bg-amber", text: "API up, database unavailable" },
  unreachable: { dot: "bg-siem-red", text: "Cannot reach the API" },
};

export default function Login() {
  const { login } = useAuth();
  const navigate = useNavigate();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState(null);
  const [submitting, setSubmitting] = useState(false);
  const api = useApiStatus();
  const health = STATUS_COPY[api.state];

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      await login(email, password);
      navigate("/", { replace: true });
    } catch (err) {
      setError(err.response?.data?.detail ?? "Login failed");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="min-h-screen grid lg:grid-cols-[1.05fr_minmax(420px,0.85fr)] bg-background">
      {/* ------------------------------------------------ brand / telemetry side */}
      <section className="relative hidden lg:flex flex-col justify-between overflow-hidden border-r border-border/70 p-12 xl:p-16">
        <div className="pointer-events-none absolute inset-0 aurora" aria-hidden="true" />
        <div className="pointer-events-none absolute inset-0 grid-plane" aria-hidden="true" />
        <AmbientField className="pointer-events-none absolute inset-0 h-full w-full opacity-90" />

        <motion.div
          initial="hidden"
          animate="show"
          variants={rise}
          custom={0}
          className="relative flex items-center gap-2.5"
        >
          <Shield className="h-5 w-5 text-primary" strokeWidth={2.4} />
          <span className="text-sm font-semibold tracking-[0.2em] uppercase">Mini SIEM</span>
        </motion.div>

        <div className="relative max-w-xl">
          <motion.p
            initial="hidden"
            animate="show"
            variants={rise}
            custom={1}
            className="font-mono text-[11px] uppercase tracking-[0.22em] text-primary/90"
          >
            Security operations console
          </motion.p>
          <motion.h1
            initial="hidden"
            animate="show"
            variants={rise}
            custom={2}
            className="mt-5 text-display text-[clamp(2.4rem,3.4vw,3.6rem)] leading-[1.03]"
          >
            Every log line,
            <br />
            watched for the
            <span className="text-primary"> pattern of an attack</span>.
          </motion.h1>
          <motion.p
            initial="hidden"
            animate="show"
            variants={rise}
            custom={3}
            className="mt-6 max-w-md text-[15px] leading-relaxed text-muted-foreground"
          >
            Collects logs from servers, firewalls and Windows hosts, normalises them into one
            schema, and runs detection rules over them continuously — raising alerts tagged with
            the MITRE ATT&amp;CK technique they match.
          </motion.p>
        </div>

        <motion.dl
          initial="hidden"
          animate="show"
          variants={rise}
          custom={4}
          className="relative grid grid-cols-3 gap-px overflow-hidden rounded-lg border border-border/70 bg-border/40"
        >
          {CAPABILITIES.map((c) => (
            <div key={c.label} className="bg-background/70 px-5 py-4 backdrop-blur-sm">
              <dt className="font-mono text-2xl font-semibold tabular-nums text-foreground">
                {c.figure}
              </dt>
              <dd className="mt-1 text-[13px] font-medium">{c.label}</dd>
              <dd className="mt-0.5 text-xs leading-snug text-muted-foreground">{c.detail}</dd>
            </div>
          ))}
        </motion.dl>
      </section>

      {/* ------------------------------------------------ sign in */}
      <section className="relative flex flex-col px-6 py-10 sm:px-10">
        {/* the mobile ambient, since the brand panel is hidden below lg */}
        <div className="pointer-events-none absolute inset-0 aurora lg:hidden" aria-hidden="true" />
        {/* a little depth on this side too, so it isn't a flat slab beside the
            telemetry panel */}
        <div
          className="pointer-events-none absolute inset-0 hidden lg:block"
          aria-hidden="true"
          style={{
            background:
              "radial-gradient(85% 55% at 50% 0%, hsl(190 100% 50% / 0.05), transparent 70%)",
          }}
        />

        <div className="relative flex flex-1 items-center justify-center">

        <motion.div
          initial={{ opacity: 0, y: 18 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.55, ease: [0.22, 1, 0.36, 1] }}
          className="relative w-full max-w-[380px]"
        >
          <div className="lg:hidden mb-10 flex items-center gap-2.5">
            <Shield className="h-5 w-5 text-primary" strokeWidth={2.4} />
            <span className="text-sm font-semibold tracking-[0.2em] uppercase">Mini SIEM</span>
          </div>

          <h2 className="text-display text-[1.75rem] leading-tight">Sign in</h2>
          <p className="mt-2 text-sm text-muted-foreground">
            Use the account an administrator set up for you.
          </p>

          <form onSubmit={handleSubmit} className="mt-8 space-y-5">
            <div className="space-y-2">
              <Label htmlFor="email" className="text-xs uppercase tracking-wider text-muted-foreground">
                Email
              </Label>
              <Input
                id="email"
                type="email"
                autoComplete="email"
                placeholder="you@example.com"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
                className="h-11"
              />
            </div>

            <div className="space-y-2">
              <Label
                htmlFor="password"
                className="text-xs uppercase tracking-wider text-muted-foreground"
              >
                Password
              </Label>
              <div className="relative">
                <Input
                  id="password"
                  type={showPassword ? "text" : "password"}
                  autoComplete="current-password"
                  placeholder="••••••••••••"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                  className="h-11 pr-11"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword((v) => !v)}
                  aria-label={showPassword ? "Hide password" : "Show password"}
                  className="absolute inset-y-0 right-0 grid w-11 place-items-center rounded-r-md text-muted-foreground transition-colors hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                >
                  {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                </button>
              </div>
            </div>

            {error && (
              <motion.p
                initial={{ opacity: 0, y: -4 }}
                animate={{ opacity: 1, y: 0 }}
                role="alert"
                className="flex items-start gap-2 rounded-md border border-destructive/40 bg-destructive/10 px-3 py-2.5 text-sm text-destructive"
              >
                <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" />
                <span>{error}</span>
              </motion.p>
            )}

            <Button type="submit" className="h-11 w-full text-[15px] font-semibold" disabled={submitting}>
              {submitting ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  Signing in…
                </>
              ) : (
                "Sign in"
              )}
            </Button>
          </form>

          <p className="mt-8 border-t border-border/70 pt-5 text-xs leading-relaxed text-muted-foreground">
            Accounts are created by an administrator, and every sign-in is recorded in the audit
            log with its source address.
          </p>
          </motion.div>
        </div>

        {/* Lines up with the form column above rather than the panel edge. */}
        <div className="relative mx-auto mt-10 flex w-full max-w-[380px] items-center gap-2.5">
          <span className="relative flex h-2 w-2">
            {api.state === "online" && (
              <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-siem-green opacity-60" />
            )}
            <span className={cn("relative inline-flex h-2 w-2 rounded-full", health.dot)} />
          </span>
          <span className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted-foreground">
            {health.text}
          </span>
        </div>
      </section>
    </div>
  );
}
