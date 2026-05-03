import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import './App.css';
import { fetchConversation, fetchUsers, login, publishKeys, register } from './api';
import type { WsServerMessage } from './protocol';
import { generateIdentityKeyPair, generateOneTimePreKeyPair, generateSignedPreKeyPair, toBase64 } from './crypto/signalKeys';
import { sign } from './crypto/signalCrypto';
import { createDevEnvelope, devBase64ToUtf8, loadSenderIdentityKeyB64 } from './crypto/envelope';
import { getSession, listSessions } from './crypto/sessionManager';
import { protocolLog, protocolWarn, shortId } from './crypto/protocolLog';

const TOKEN_KEY = 'signal-im-token';
const USER_KEY = 'signal-im-user';
const THEME_KEY = 'signal-im-theme';

type Session = { token: string; userId: string; username: string };

type ChatMessage = Extract<WsServerMessage, { type: 'chat' }>;

function peerIdForMessage(msg: ChatMessage, selfId: string): string {
  return msg.fromUserId === selfId ? msg.toUserId : msg.fromUserId;
}

function dayKey(iso: string): string {
  const d = new Date(iso);
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
}

function formatDayLabel(iso: string): string {
  return new Date(iso).toLocaleDateString(undefined, {
    weekday: 'short',
    year: 'numeric',
    month: 'short',
    day: 'numeric',
  });
}

function messageText(msg: ChatMessage): string {
  if (!msg.envelope) return msg.text ?? '';
  try {
    // TODO: Replace this dev decode with Double Ratchet AEAD decryption.
    return devBase64ToUtf8(msg.envelope.ciphertextB64);
  } catch {
    return '[encrypted message]';
  }
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

type Theme = 'dark' | 'light';

function loadTheme(): Theme | null {
  try {
    const raw = localStorage.getItem(THEME_KEY);
    return raw === 'light' || raw === 'dark' ? raw : null;
  } catch {
    return null;
  }
}

function SunIcon() {
  return (
    <svg viewBox="0 0 24 24" role="presentation" aria-hidden="true">
      <path
        d="M12 3v2.25M12 18.75V21M4.5 12H3m18 0h-1.5M5.47 5.47l1.59 1.59m11.47 11.47 1.59 1.59M18.53 5.47l-1.59 1.59M7.06 16.94l-1.59 1.59M12 16.5a4.5 4.5 0 1 0 0-9 4.5 4.5 0 0 0 0 9Z"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.8"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

function MoonIcon() {
  return (
    <svg viewBox="0 0 24 24" role="presentation" aria-hidden="true">
      <path
        d="M21 12.8A7.8 7.8 0 1 1 11.2 3a6.2 6.2 0 0 0 9.8 9.8Z"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.8"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

export default function App() {
  // Don't auto-sign-in on refresh; offer "resume" explicitly to avoid confusion
  // when a stale token exists in sessionStorage.
  const [savedSession, setSavedSession] = useState<Session | null>(() => loadSession());
  const [session, setSession] = useState<Session | null>(null);
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
  const [theme, setTheme] = useState<Theme>(() => {
    const saved = loadTheme();
    if (saved) return saved;
    const prefersLight =
      typeof window !== 'undefined' &&
      typeof window.matchMedia === 'function' &&
      window.matchMedia('(prefers-color-scheme: light)').matches;
    return prefersLight ? 'light' : 'dark';
  });

  const wsRef = useRef<WebSocket | null>(null);
  const enrollingRef = useRef(false);

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    try {
      localStorage.setItem(THEME_KEY, theme);
    } catch {
      // ignore
    }
  }, [theme]);

  const loadPeers = useCallback(async (tok: string) => {
    const users = await fetchUsers(tok);
    setPeerList(users);
  }, []);

  useEffect(() => {
    if (!session) return;
    let cancelled = false;
    loadPeers(session.token).catch((e: unknown) => {
      if (!cancelled) {
        const msg = e instanceof Error ? e.message : 'Failed to load users';
        setFormError(msg);
        // If we lost auth, don't keep a broken "logged in" UI around.
        if (/^HTTP 401\b|^HTTP 403\b/i.test(msg)) {
          setSession(null);
          clearSession();
          setSavedSession(null);
        }
      }
    });
    return () => {
      cancelled = true;
    };
  }, [session, loadPeers]);

  useEffect(() => {
    if (!session) return;

    const KEY_STORAGE_PREFIX = `signal-keys-${session.userId}`;
    const stored = localStorage.getItem(KEY_STORAGE_PREFIX);

    if (stored) {
      protocolLog('local identity/prekeys loaded', { user: session.username });
      return;
    }

    if (enrollingRef.current) return;
    enrollingRef.current = true;

    protocolLog('local keys missing; starting pre-key enrollment', { user: session.username });

    const enroll = async () => {
      try {
        // 1. Generate local keys
        protocolLog('generating identity key, signed prekey, and OPKs');
        const ik = generateIdentityKeyPair();
        const spk = generateSignedPreKeyPair();
        const sig = sign(ik.privateKey, spk.publicKey);

        const opks: { id: number; publicKey: Uint8Array; privateKey: Uint8Array }[] = [];
        for (let i = 0; i < 50; i++) {
          const pair = generateOneTimePreKeyPair();
          opks.push({ id: i, ...pair });
        }

        const fullState = {
          identityKey: {
            publicKeyB64: toBase64(ik.publicKey),
            privateKeyB64: toBase64(ik.privateKey),
          },
          signedPreKey: {
            publicKeyB64: toBase64(spk.publicKey),
            privateKeyB64: toBase64(spk.privateKey),
            signatureB64: toBase64(sig),
          },
          oneTimePreKeys: opks.map((o) => ({
            id: o.id,
            publicKeyB64: toBase64(o.publicKey),
            privateKeyB64: toBase64(o.privateKey),
          })),
        };

        // 2. Publish public components to server FIRST
        // If this fails, we catch it and don't save to localStorage, 
        // allowing the effect to retry on the next session trigger.
        protocolLog('publishing public pre-key bundle', { opks: fullState.oneTimePreKeys.length });
        await publishKeys(session.token, {
          identityKeyB64: fullState.identityKey.publicKeyB64,
          signedPreKeyB64: fullState.signedPreKey.publicKeyB64,
          signedPreKeySignatureB64: fullState.signedPreKey.signatureB64,
          oneTimePreKeysB64: fullState.oneTimePreKeys.map((o) => o.publicKeyB64),
        });

        // 3. Save private + public keys to localStorage ONLY after success
        localStorage.setItem(KEY_STORAGE_PREFIX, JSON.stringify(fullState));

        protocolLog('pre-key enrollment complete', { user: session.username });
      } catch (err) {
        protocolWarn('pre-key enrollment failed', {
          reason: err instanceof Error ? err.message : 'unknown',
        });
      } finally {
        enrollingRef.current = false;
      }
    };

    void enroll();
  }, [session]);

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
    protocolLog('websocket connecting', { user: session.username });
    const ws = new WebSocket(url);
    wsRef.current = ws;

    ws.onopen = () => {
      setWsState('open');
      setWsError(null);
      protocolLog('websocket open', {
        user: session.username,
        sessions: listSessions(session.userId).length,
      });
      void loadPeers(session.token);
    };

    ws.onclose = (ev) => {
      setWsState('closed');
      if (wsRef.current === ws) wsRef.current = null;
      // 4401 is what the server uses for auth errors in server/src/routes/ws.ts
      if (ev.code === 4401) {
        const reason = ev.reason || 'Unauthorized';
        setWsError(`WebSocket closed: ${reason}`);
        setSession(null);
        clearSession();
        setSavedSession(null);
      }
    };

    ws.onerror = () => {
      // Browsers give little detail here; treat it as a hint, not a hard failure.
      protocolWarn('websocket error');
      setWsError((prev) => prev ?? 'WebSocket error');
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
        const storedSession = getSession(session.userId, peerId);
        protocolLog('chat received', {
          from: shortId(msg.fromUserId),
          format: msg.envelope ? 'envelope' : 'legacy-text',
          session: storedSession?.isInitialized ? 'initialized' : 'missing',
        });
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
        setSavedSession(s);
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
    setSavedSession(null);
    setThreads({});
    setPeerList([]);
    setRecipientId('');
    setWsError(null);
  };

  const sendChat = () => {
    const ws = wsRef.current;
    if (!session || !ws || ws.readyState !== WebSocket.OPEN || !recipientId) return;
    const text = draft.trim();
    if (!text) return;
    const storedSession = getSession(session.userId, recipientId);
    protocolLog('send requested', {
      to: shortId(recipientId),
      session: storedSession?.isInitialized ? 'initialized' : 'missing',
    });
    if (!storedSession) {
      protocolWarn('no crypto session yet; using dev envelope placeholder', {
        to: shortId(recipientId),
      });
    }
    const senderIdentityKeyB64 = loadSenderIdentityKeyB64(session.userId);
    const envelope = createDevEnvelope(text, senderIdentityKeyB64);
    protocolLog('envelope created', { kind: envelope.kind, encrypted: false });
    ws.send(JSON.stringify({ type: 'chat', toUserId: recipientId, envelope }));
    protocolLog('envelope sent over websocket', { to: shortId(recipientId) });
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

  const activePeerOnline = useMemo(() => {
    if (!recipientId) return false;
    return onlineIds.has(recipientId);
  }, [recipientId, onlineIds]);

  const selectPeer = (id: string) => {
    setRecipientId(id);
    setDraft('');
    if (!session) return;
    const storedSession = getSession(session.userId, id);
    protocolLog('conversation selected', {
      peer: shortId(id),
      session: storedSession?.isInitialized ? 'initialized' : 'missing',
    });
    fetchConversation(session.token, id)
      .then((msgs) => {
        protocolLog('history received', {
          peer: shortId(id),
          count: msgs.length,
          envelopes: msgs.filter((m) => m.envelope).length,
        });
        setThreads((prev) => ({ ...prev, [id]: msgs as ChatMessage[] }));
      })
      .catch(() => {
        // If history fails to load, keep UI responsive; WS will still deliver new messages.
      });
  };

  if (!session) {
    return (
      <main className="app">
        <div className="auth-topbar">
          <div>
            <h1>Signal Instant Messaging</h1>
            <p className="tagline">Messages are not end-to-end encrypted yet.</p>
          </div>
          <button
            type="button"
            className="ghost theme-toggle"
            onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')}
            aria-label={theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}
          >
            <span className="theme-icon" aria-hidden="true">
              {theme === 'dark' ? <SunIcon /> : <MoonIcon />}
            </span>
            <span className="theme-label">{theme === 'dark' ? 'Light' : 'Dark'}</span>
          </button>
        </div>
        <div className="auth-stack">
          {savedSession && (
            <section className="card resume-card">
              <h2>Resume session?</h2>
              <p className="hint">
                You have a saved session as <b>{savedSession.username}</b>.
              </p>
              <div className="actions">
                <button
                  type="button"
                  onClick={() => {
                    setSession(savedSession);
                    setFormError(null);
                    setAuthSuccess(null);
                  }}
                >
                  Continue as {savedSession.username}
                </button>
                <button
                  type="button"
                  className="ghost"
                  onClick={() => {
                    clearSession();
                    setSavedSession(null);
                    setFormError(null);
                    setAuthSuccess(null);
                  }}
                >
                  Sign in as different user
                </button>
              </div>
            </section>
          )}

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
        </div>
      </main>
    );
  }

  return (
    <main className="app">
      <header className="topbar">
        <div>
          <h1>Signal Instant Messaging</h1>
          <p className="tagline">Signed in as {session.username}</p>
          <p className="status-line">
            WebSocket: <span className={wsState === 'open' ? 'ok' : 'warn'}>{wsState}</span>
          </p>
        </div>
        <div className="topbar-actions">
          <button
            type="button"
            className="ghost theme-toggle"
            onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')}
            aria-label={theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}
          >
            <span className="theme-icon" aria-hidden="true">
              {theme === 'dark' ? <SunIcon /> : <MoonIcon />}
            </span>
            <span className="theme-label">{theme === 'dark' ? 'Light' : 'Dark'}</span>
          </button>
          <button type="button" className="ghost" onClick={logout}>
            Sign out
          </button>
        </div>
      </header>

      <section className="chat-layout">
        <aside className="card sidebar">
          <div className="sidebar-head">
            <h2>Users</h2>
            {wsError && <p className="error">{wsError}</p>}
            <p className="hint">Click a user to open a separate conversation.</p>
          </div>
          <ul className="user-list">
            {sortedPeers.length === 0 && <li className="muted">No other users registered.</li>}
            {sortedPeers.map((p) => (
              <li key={p.id}>
                <button
                  type="button"
                  className={recipientId === p.id ? 'user-pick active' : 'user-pick'}
                  onClick={() => selectPeer(p.id)}
                >
                  <span className="user-name">{p.username}</span>
                  <span className="user-meta">
                    <span className={onlineIds.has(p.id) ? 'user-state online' : 'user-state offline'}>
                      {onlineIds.has(p.id) ? 'Online' : 'Offline'}
                    </span>
                    <span className={onlineIds.has(p.id) ? 'dot online' : 'dot offline'} aria-hidden="true" />
                  </span>
                </button>
              </li>
            ))}
          </ul>
        </aside>

        <section className="card chat-pane">
          {!recipientId ? (
            <div className="empty-chat">
              <h2>Chat</h2>
              <p className="hint">
                Pick a user from the left to open your conversation with them.
              </p>
            </div>
          ) : (
            <>
              <div className="chat-head">
                <h2 className="chat-title">{activePeerName ?? 'Chat'}</h2>
                {activePeerName && (
                  <p className={activePeerOnline ? 'chat-sub online' : 'chat-sub offline'}>
                    {activePeerOnline ? 'Online' : 'Offline'}
                  </p>
                )}
              </div>
              <div className="thread">
                {activeMessages.length === 0 && (
                  <p className="muted">No messages in this conversation yet.</p>
                )}
                {activeMessages.map((m, idx) => {
                  const mine = m.fromUserId === session.userId;
                  const prev = idx > 0 ? activeMessages[idx - 1] : null;
                  const showDay = !prev || dayKey(prev.sentAt) !== dayKey(m.sentAt);
                  return (
                    <div key={m.id}>
                      {showDay && (
                        <div className="day-sep">
                          <span>{formatDayLabel(m.sentAt)}</span>
                        </div>
                      )}
                      <div className={mine ? 'bubble mine' : 'bubble'}>
                        <div className="meta">
                          {mine ? 'You' : m.fromUsername} ·{' '}
                          {new Date(m.sentAt).toLocaleTimeString()}
                        </div>
                        <div className="text">{messageText(m)}</div>
                      </div>
                    </div>
                  );
                })}
              </div>
              <div className="composer">
                <input
                  placeholder={wsState === 'open' ? 'Message…' : 'Connecting…'}
                  value={draft}
                  disabled={wsState !== 'open'}
                  onChange={(e) => setDraft(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') sendChat();
                  }}
                />
                <button type="button" disabled={wsState !== 'open'} onClick={sendChat}>
                  Send
                </button>
              </div>
            </>
          )}
        </section>
      </section>
    </main>
  );
}
