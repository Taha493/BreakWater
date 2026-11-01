import { useEffect, useMemo, useState, type FormEvent } from "react";
import { ApiError, createApi } from "./api";
import { ApiContext } from "./context";
import { Documents } from "./pages/Documents";
import { Events } from "./pages/Events";
import { Overview } from "./pages/Overview";
import { Policies } from "./pages/Policies";
import { RedTeam } from "./pages/RedTeam";

const PAGES = [
  { id: "overview", name: "Overview" },
  { id: "events", name: "Events" },
  { id: "documents", name: "Documents" },
  { id: "policies", name: "Policies" },
  { id: "redteam", name: "Red-team runs" },
] as const;
type PageId = (typeof PAGES)[number]["id"];

const DEFAULT_GATEWAY = import.meta.env.VITE_GATEWAY_URL ?? "http://localhost:8000";

function parseHash(hash: string): { page: PageId; runId: string | null } {
  const [page, runId] = hash.replace(/^#\/?/, "").split("/");
  const known = PAGES.find((p) => p.id === page);
  return { page: known?.id ?? "overview", runId: known?.id === "redteam" && runId ? runId : null };
}

interface Session {
  gateway: string;
  key: string;
}

export function App() {
  // The admin key lives only in this state: never in storage, cookies, or the URL.
  const [session, setSession] = useState<Session | null>(null);
  return session ? (
    <Signed session={session} signOut={() => setSession(null)} />
  ) : (
    <SignIn onSignedIn={setSession} />
  );
}

function SignIn({ onSignedIn }: { onSignedIn: (s: Session) => void }) {
  const [gateway, setGateway] = useState(DEFAULT_GATEWAY);
  const [key, setKey] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [checking, setChecking] = useState(false);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setChecking(true);
    setError(null);
    try {
      await createApi(gateway, key, () => undefined).get("/admin/stats?range=1h");
      onSignedIn({ gateway, key });
    } catch (e) {
      setError(
        e instanceof ApiError && (e.status === 401 || e.status === 403)
          ? "That is not an admin key for this gateway."
          : `Cannot reach the gateway: ${e instanceof Error ? e.message : "unknown error"}`,
      );
    } finally {
      setChecking(false);
    }
  }

  const field = "w-full rounded-md border border-line bg-surface px-3 py-2 text-sm";
  return (
    <main className="mx-auto mt-24 max-w-sm px-4">
      <h1 className="mb-1 text-xl font-semibold">Breakwater</h1>
      <p className="mb-6 text-sm text-ink-2">Sign in with an admin key. It is kept in memory only and forgotten when you close or reload the page.</p>
      <form onSubmit={(e) => void submit(e)} className="space-y-3">
        <label className="block text-sm">
          Gateway URL
          <input value={gateway} onChange={(e) => setGateway(e.target.value)} className={field} required />
        </label>
        <label className="block text-sm">
          Admin key
          <input type="password" autoComplete="off" value={key} onChange={(e) => setKey(e.target.value)} className={field} required />
        </label>
        {error && (
          <p role="alert" className="text-sm text-critical">
            {error}
          </p>
        )}
        <button disabled={checking} className="w-full rounded-md bg-accent px-3 py-2 text-sm font-semibold text-white disabled:opacity-50">
          {checking ? "Checking…" : "Sign in"}
        </button>
      </form>
    </main>
  );
}

function Signed({ session, signOut }: { session: Session; signOut: () => void }) {
  const api = useMemo(() => createApi(session.gateway, session.key, signOut), [session, signOut]);
  const [route, setRoute] = useState(() => parseHash(window.location.hash));
  const [theme, setTheme] = useState<"system" | "light" | "dark">("system");

  useEffect(() => {
    const onHash = () => setRoute(parseHash(window.location.hash));
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, []);
  useEffect(() => {
    if (theme === "system") document.documentElement.removeAttribute("data-theme");
    else document.documentElement.setAttribute("data-theme", theme);
  }, [theme]);

  const go = (page: PageId, runId: string | null = null) => {
    window.location.hash = runId ? `/${page}/${runId}` : `/${page}`;
  };

  return (
    <ApiContext.Provider value={api}>
      <header className="border-b border-line bg-surface">
        <div className="mx-auto flex max-w-7xl flex-wrap items-center gap-x-6 gap-y-2 px-4 py-3">
          <span className="font-semibold">Breakwater</span>
          <nav aria-label="Pages" className="flex flex-wrap gap-1">
            {PAGES.map((p) => (
              <a
                key={p.id}
                href={`#/${p.id}`}
                aria-current={route.page === p.id ? "page" : undefined}
                className={`rounded-md px-3 py-1 text-sm ${route.page === p.id ? "bg-surface-2 font-semibold" : "text-ink-2 hover:bg-surface-2"}`}
              >
                {p.name}
              </a>
            ))}
          </nav>
          <div className="ml-auto flex items-center gap-3 text-sm">
            <select aria-label="Theme" value={theme} onChange={(e) => setTheme(e.target.value as typeof theme)} className="rounded-md border border-line bg-surface px-2 py-1">
              <option value="system">System theme</option>
              <option value="light">Light</option>
              <option value="dark">Dark</option>
            </select>
            <span className="hidden text-muted md:inline">{session.gateway}</span>
            <button onClick={signOut} className="underline">
              Sign out
            </button>
          </div>
        </div>
      </header>
      <main className="mx-auto max-w-7xl px-4 py-6">
        {route.page === "overview" && <Overview />}
        {route.page === "events" && <Events />}
        {route.page === "documents" && <Documents />}
        {route.page === "policies" && <Policies />}
        {route.page === "redteam" && <RedTeam runId={route.runId} open={(id) => go("redteam", id)} />}
      </main>
    </ApiContext.Provider>
  );
}
