import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import './App.css';
import { fetchUsers, login, register } from './api';
import type { WsServerMessage } from './protocol';

const TOKEN_KEY = 'signal-im-token';
const USER_KEY = 'signal-im-user';

type Session = { token: string; userId: string; username: string };

type ChatMessage = Extract<WsServerMessage, { type: 'chat' }>;

function peerIdForMessage(msg: ChatMessage, selfId: string): string {
  return msg.fromUserId === selfId ? msg.toUserId : msg.fromUserId;
}

function loadSession(): Session | null {
  try {
    const raw = sessionStorage.getItem(USER_KEY);
    const token = sessionStorage.getItem(TOKEN_KEY);
    if (!raw || !token) return null;
    const u = JSON.parse(raw) as { userId: string; username: string };
    if (!u.userId || !u.username) return null;
    return { token, userId: u.userId, username: u.username };
  } catch {
    return null;
  }
}

function saveSession(s: Session) {
  sessionStorage.setItem(TOKEN_KEY, s.token);
  sessionStorage.setItem(
    USER_KEY,
    JSON.stringify({ userId: s.userId, username: s.username }),
  );
}

function clearSession() {
  sessionStorage.removeItem(TOKEN_KEY);
  sessionStorage.removeItem(USER_KEY);
}

export default function App() {
  const [session, setSession] = useState<Session | null>(() => loadSession());
  const [mode, setMode] = useState<'login' | 'register'>('login');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [password2, setPassword2] = useState('');
  const [formError, setFormError] = useState<string | null>(null);
  const [authSuccess, setAuthSuccess] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const [peerList, setPeerList] = useState<{ id: string; username: string }[]>([]);
  const [recipientId, setRecipientId] = useState('');
  const [draft, setDraft] = useState('');
  /** One message list per peer (other user's id). */
  const [threads, setThreads] = useState<Record<string, ChatMessage[]>>({});
  const [onlineIds, setOnlineIds] = useState<Set<string>>(new Set());
  const [wsState, setWsState] = useState<'idle' | 'connecting' | 'open' | 'closed'>('idle');
  const [wsError, setWsError] = useState<string | null>(null);

  const wsRef = useRef<WebSocket | null>(null);

  const loadPeers = useCallback(async (tok: string) => {
    const users = await fetchUsers(tok);
    setPeerList(users);
  }, []);

  useEffect(() => {
    if (!session) return;
    let cancelled = false;
    loadPeers(session.token).catch((e: unknown) => {
      if (!cancelled) {
        setFormError(e instanceof Error ? e.message : 'Failed to load users');
      }
    });
    return () => {
      cancelled = true;
    };
  }, [session, loadPeers]);

  useEffect(() => {
    if (!session) {
      wsRef.current?.close();
      wsRef.current = null;
      setWsState('idle');
      setOnlineIds(new Set());
      return;
    }

    const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const url = `${proto}//${window.location.host}/api/ws?token=${encodeURIComponent(session.token)}`;

    setWsState('connecting');
    setWsError(null);
    const ws = new WebSocket(url);
    wsRef.current = ws;

    ws.onopen = () => {
      setWsState('open');
      void loadPeers(session.token);
    };

    ws.onclose = () => {
      setWsState('closed');
      if (wsRef.current === ws) wsRef.current = null;
    };

    ws.onerror = () => {
      setWsError('WebSocket error');
    };

    ws.onmessage = (ev) => {
      let parsed: unknown;
      try {
        parsed = JSON.parse(String(ev.data));
      } catch {
        return;
      }
      const msg = parsed as WsServerMessage;
      if (msg.type === 'presence') {
        setOnlineIds(new Set(msg.online.map((x) => x.userId)));
        void loadPeers(session.token);
        return;
      }
      if (msg.type === 'chat') {
        const peerId = peerIdForMessage(msg, session.userId);
        setThreads((prev) => {
          const list = prev[peerId] ?? [];
          if (list.some((m) => m.id === msg.id)) return prev;
          return { ...prev, [peerId]: [...list, msg] };
        });
        if (msg.fromUserId !== session.userId) {
          setPeerList((prev) => {
            if (prev.some((p) => p.id === msg.fromUserId)) return prev;
            return [...prev, { id: msg.fromUserId, username: msg.fromUsername }];
          });
        }
        return;
      }
      if (msg.type === 'error') {
        setWsError(msg.message);
      }
    };

    return () => {
      ws.close();
      if (wsRef.current === ws) wsRef.current = null;
    };
  }, [session, loadPeers]);

  const submitAuth = async () => {
    setFormError(null);
    setAuthSuccess(null);
    setBusy(true);
    try {
      if (mode === 'register') {
        if (password !== password2) {
          setFormError('Passwords do not match');
          return;
        }
        await register(username, password);
        setMode('login');
        setPassword('');
        setPassword2('');
        setAuthSuccess('Account created. Sign in with your username and password.');
      } else {
        const res = await login(username, password);
        const s: Session = {
          token: res.token,
          userId: res.userId,
          username: res.username,
        };
        saveSession(s);
        setSession(s);
        setThreads({});
        setRecipientId('');
      }
    } catch (e: unknown) {
      setFormError(e instanceof Error ? e.message : 'Failed');
    } finally {
      setBusy(false);
    }
  };

  const logout = () => {
    setSession(null);
    clearSession();
    setThreads({});
    setPeerList([]);
    setRecipientId('');
    setWsError(null);
  };

  const sendChat = () => {
    const ws = wsRef.current;
    if (!ws || ws.readyState !== WebSocket.OPEN || !recipientId) return;
    const text = draft.trim();
    if (!text) return;
    ws.send(JSON.stringify({ type: 'chat', toUserId: recipientId, text }));
    setDraft('');
  };

  const sortedPeers = useMemo(
    () => [...peerList].sort((a, b) => a.username.localeCompare(b.username)),
    [peerList],
  );

  const activeMessages = useMemo(() => {
    if (!recipientId) return [];
    return threads[recipientId] ?? [];
  }, [recipientId, threads]);

  const activePeerName = useMemo(() => {
    if (!recipientId) return null;
    return peerList.find((p) => p.id === recipientId)?.username ?? null;
  }, [recipientId, peerList]);

  const selectPeer = (id: string) => {
    setRecipientId(id);
    setDraft('');
  };

  if (!session) {
    return (
      <main className="app">
        <h1>Signal Instant Messaging</h1>
        <p className="tagline">Messages are not end-to-end encrypted yet.</p>
        <section className="card">
          <h2>{mode === 'login' ? 'Sign in' : 'Create account'}</h2>
          {authSuccess && <p className="success">{authSuccess}</p>}
          {formError && <p className="error">{formError}</p>}
          <div className="field">
            <label htmlFor="user">Username</label>
            <input
              id="user"
              autoComplete="username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
            />
          </div>
          <div className="field">
            <label htmlFor="pass">Password</label>
            <input
              id="pass"
              type="password"
              autoComplete={mode === 'login' ? 'current-password' : 'new-password'}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
          </div>
          {mode === 'register' && (
            <div className="field">
              <label htmlFor="pass2">Confirm password</label>
              <input
                id="pass2"
                type="password"
                autoComplete="new-password"
                value={password2}
                onChange={(e) => setPassword2(e.target.value)}
              />
            </div>
          )}
          <div className="actions">
            <button type="button" disabled={busy} onClick={submitAuth}>
              {busy ? '…' : mode === 'login' ? 'Sign in' : 'Register'}
            </button>
            <button
              type="button"
              className="ghost"
              onClick={() => {
                setMode(mode === 'login' ? 'register' : 'login');
                setFormError(null);
                setAuthSuccess(null);
              }}
            >
              {mode === 'login' ? 'Need an account?' : 'Have an account?'}
            </button>
          </div>
        </section>
      </main>
    );
  }

  return (
    <main className="app">
      <header className="topbar">
        <div>
          <h1>Signal Instant Messaging</h1>
          <p className="tagline">Signed in as {session.username}</p>
        </div>
        <button type="button" className="ghost" onClick={logout}>
          Sign out
        </button>
      </header>

      <section className="grid">
        <div className="card">
          <h2>Connection</h2>
          <p className="status-line">
            WebSocket:{' '}
            <span className={wsState === 'open' ? 'ok' : 'warn'}>{wsState}</span>
          </p>
          {wsError && <p className="error">{wsError}</p>}
        </div>

        <div className="card">
          <h2>Users</h2>
          <p className="hint">Select a user to open a separate conversation.</p>
          <ul className="user-list">
            {sortedPeers.length === 0 && <li className="muted">No other users registered.</li>}
            {sortedPeers.map((p) => (
              <li key={p.id}>
                <button
                  type="button"
                  className={recipientId === p.id ? 'user-pick active' : 'user-pick'}
                  onClick={() => selectPeer(p.id)}
                >
                  {p.username}
                  {onlineIds.has(p.id) ? (
                    <span className="dot online" title="Online" />
                  ) : (
                    <span className="dot offline" title="Offline" />
                  )}
                </button>
              </li>
            ))}
          </ul>
        </div>
      </section>

      <section className="card chat">
        <h2>
          {activePeerName ? `Chat with ${activePeerName}` : 'Chat'}
        </h2>
        {!recipientId && (
          <p className="hint chat-hint">Choose someone from the list to see your conversation with them.</p>
        )}
        <div className="thread">
          {recipientId && activeMessages.length === 0 && (
            <p className="muted">No messages in this conversation yet.</p>
          )}
          {activeMessages.map((m) => {
            const mine = m.fromUserId === session.userId;
            return (
              <div key={m.id} className={mine ? 'bubble mine' : 'bubble'}>
                <div className="meta">
                  {mine ? 'You' : m.fromUsername} ·{' '}
                  {new Date(m.sentAt).toLocaleTimeString()}
                </div>
                <div className="text">{m.text}</div>
              </div>
            );
          })}
        </div>
        <div className="composer">
          <input
            placeholder={recipientId ? 'Message…' : 'Pick a recipient first'}
            value={draft}
            disabled={!recipientId || wsState !== 'open'}
            onChange={(e) => setDraft(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter') sendChat();
            }}
          />
          <button type="button" disabled={!recipientId || wsState !== 'open'} onClick={sendChat}>
            Send
          </button>
        </div>
      </section>
    </main>
  );
}
