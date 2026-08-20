import { useState } from "react";
import { FlaskConical, Terminal, Zap } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { useAuth } from "@/api/AuthContext";
import { useAttackLogin, useAttackSearch, useRunDetection } from "@/api/hooks";

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL;

const SEARCH_PAYLOADS = [
  { label: "SQL Injection (T1190)", value: "' OR 1=1" },
  { label: "XSS (T1059.007)", value: "<script>alert(1)</script>" },
  { label: "Path Traversal (T1083)", value: "../../etc/passwd" },
];

function EndpointRow({ method, path }) {
  return (
    <div className="flex items-center gap-2 py-1.5 text-sm border-b border-border last:border-0 font-mono">
      <span className="text-siem-cyan">{method}</span>
      <span className="break-all">{API_BASE_URL}{path}</span>
    </div>
  );
}

export default function AttackLab() {
  const { user } = useAuth();
  const canRunDetection = user?.roles?.some((r) => ["analyst", "admin"].includes(r));

  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("wrongpassword");
  const [query, setQuery] = useState(SEARCH_PAYLOADS[0].value);

  const login = useAttackLogin();
  const search = useAttackSearch();
  const runDetection = useRunDetection();

  const submitLogin = (e) => {
    e.preventDefault();
    login.mutate({ username, password });
  };

  const submitSearch = (e) => {
    e.preventDefault();
    search.mutate(query);
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-2">
        <FlaskConical className="h-6 w-6 text-siem-amber" />
        <h1 className="text-2xl font-bold">Attack Lab</h1>
      </div>
      <p className="text-sm text-muted-foreground max-w-2xl">
        Dev-only, intentionally vulnerable practice routes. Every request here is
        logged as a normalized event, exactly like real traffic — the detection
        engine picks it up on its next pass. Point Burp Suite (Repeater / Intruder)
        at the endpoints below, or use the forms to fire requests directly.
      </p>

      <Card>
        <CardHeader>
          <CardTitle className="text-base flex items-center gap-2">
            <Terminal className="h-4 w-4" /> Endpoints
          </CardTitle>
        </CardHeader>
        <CardContent>
          <EndpointRow method="POST" path="/api/attack-lab/login" />
          <EndpointRow method="GET" path="/api/attack-lab/search?q=..." />
        </CardContent>
      </Card>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <Card>
          <CardHeader>
            <CardTitle className="text-base">
              Brute Force Login <span className="text-muted-foreground font-normal text-xs">T1110 / T1110.004</span>
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <form onSubmit={submitLogin} className="space-y-2">
              <Input
                placeholder="username"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                className="font-mono"
              />
              <Input
                placeholder="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="font-mono"
              />
              <Button type="submit" disabled={login.isPending} className="w-full">
                {login.isPending ? "Sending..." : "Attempt login"}
              </Button>
            </form>
            {login.data && (
              <p className={`text-sm ${login.data.success ? "text-siem-green" : "text-destructive"}`}>
                {login.data.message}
              </p>
            )}
            {login.isError && <p className="text-sm text-destructive">Request failed.</p>}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">
              Vulnerable Search <span className="text-muted-foreground font-normal text-xs">T1190 / T1059.007 / T1083 / T1595</span>
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <form onSubmit={submitSearch} className="space-y-2">
              <Input
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                className="font-mono"
              />
              <div className="flex flex-wrap gap-1.5">
                {SEARCH_PAYLOADS.map((p) => (
                  <button
                    key={p.value}
                    type="button"
                    onClick={() => setQuery(p.value)}
                    className="text-xs px-2 py-1 rounded border border-border text-muted-foreground hover:text-foreground hover:bg-muted transition-colors"
                  >
                    {p.label}
                  </button>
                ))}
              </div>
              <Button type="submit" disabled={search.isPending} className="w-full">
                {search.isPending ? "Searching..." : "Search"}
              </Button>
            </form>
            {search.data && (
              <p className="text-sm text-muted-foreground">
                Logged as request to <span className="font-mono">/search?q={search.data.query}</span> — no results (simulated).
              </p>
            )}
            {search.isError && <p className="text-sm text-destructive">Request failed.</p>}
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base flex items-center gap-2">
            <Zap className="h-4 w-4" /> Run detection now
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <p className="text-sm text-muted-foreground">
            The scheduler already runs every 60s, but you can trigger a pass
            immediately after firing test attacks above to see the matching
            MITRE-tagged alerts right away.
          </p>
          {canRunDetection ? (
            <Button onClick={() => runDetection.mutate()} disabled={runDetection.isPending}>
              {runDetection.isPending ? "Running..." : "Run detection pass"}
            </Button>
          ) : (
            <p className="text-sm text-muted-foreground">Analyst or admin role required to trigger detection.</p>
          )}
          {runDetection.data && (
            <div className="text-sm font-mono space-y-1 pt-2">
              {Object.entries(runDetection.data.results).map(([key, value]) => (
                <div key={key} className="flex justify-between border-b border-border py-1 last:border-0">
                  <span className="text-muted-foreground">{key}</span>
                  <span className={value > 0 ? "text-siem-green" : ""}>{value}</span>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
