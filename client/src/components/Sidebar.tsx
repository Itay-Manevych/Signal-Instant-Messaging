import React from 'react';
import { useChat } from '../context/ChatContext';
import type { Session } from '../types';

interface SidebarProps {
  session: Session;
}

export function Sidebar({ session }: SidebarProps) {
  const { peerList, onlineIds, recipientId, setRecipientId, wsError } = useChat();
  const sortedPeers = [...peerList].sort((a, b) => a.username.localeCompare(b.username));

  return (
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
              onClick={() => setRecipientId(p.id)}
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
  );
}
