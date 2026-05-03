import { SunIcon, MoonIcon, dayKey, formatDayLabel } from './utils';
import type { Session, ChatMessage } from './types';

interface ChatProps {
  session: Session;
  peerList: { id: string; username: string }[];
  onlineIds: Set<string>;
  recipientId: string;
  onSelectPeer: (id: string) => void;
  activeMessages: ChatMessage[];
  wsState: string;
  draft: string;
  setDraft: (v: string) => void;
  onSend: () => void;
  activePeerName: string | null;
  activePeerOnline: boolean;
  onLogout: () => void;
  setTheme: (t: 'dark' | 'light') => void;
  theme: 'dark' | 'light';
  wsError: string | null;
}

export function Chat({
  session,
  peerList,
  onlineIds,
  recipientId,
  onSelectPeer,
  activeMessages,
  wsState,
  draft,
  setDraft,
  onSend,
  activePeerName,
  activePeerOnline,
  onLogout,
  setTheme,
  theme,
  wsError
}: ChatProps) {
  const sortedPeers = [...peerList].sort((a, b) => a.username.localeCompare(b.username));

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
          >
            <span className="theme-icon">{theme === 'dark' ? <SunIcon /> : <MoonIcon />}</span>
            <span className="theme-label">{theme === 'dark' ? 'Light' : 'Dark'}</span>
          </button>
          <button type="button" className="ghost" onClick={onLogout}>
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
                  onClick={() => onSelectPeer(p.id)}
                >
                  <span className="user-name">{p.username}</span>
                  <span className="user-meta">
                    <span className={onlineIds.has(p.id) ? 'user-state online' : 'user-state offline'}>
                      {onlineIds.has(p.id) ? 'Online' : 'Offline'}
                    </span>
                    <span className={onlineIds.has(p.id) ? 'dot online' : 'dot offline'} />
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
              <p className="hint">Pick a user from the left to open your conversation with them.</p>
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
                {activeMessages.length === 0 && <p className="muted">No messages in this conversation yet.</p>}
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
                          {mine ? 'You' : m.fromUsername} · {new Date(m.sentAt).toLocaleTimeString()}
                        </div>
                        <div className="text">{m.text}</div>
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
                  onKeyDown={(e) => e.key === 'Enter' && onSend()}
                />
                <button type="button" disabled={wsState !== 'open'} onClick={onSend}>
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
