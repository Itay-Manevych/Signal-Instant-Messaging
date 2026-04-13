import { useEffect, useState } from 'react';
import './App.css';

type Health = { ok: boolean; service?: string };

export default function App() {
  const [health, setHealth] = useState<Health | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    fetch('/api/health')
      .then((r) => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json() as Promise<Health>;
      })
      .then((data) => {
        if (!cancelled) setHealth(data);
      })
      .catch((e: unknown) => {
        if (!cancelled) setError(e instanceof Error ? e.message : 'Request failed');
      });
    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <main className="app">
      <h1>Signal Instant Messaging</h1>
      <section className="card">
        <h2>Server health</h2>
        {error && <p className="error">{error}</p>}
        {!error && health && (
          <pre className="status">{JSON.stringify(health, null, 2)}</pre>
        )}
        {!error && !health && <p>Checking…</p>}
      </section>
    </main>
  );
}
