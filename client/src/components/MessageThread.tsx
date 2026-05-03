import React from 'react';
import { useChat } from '../context/ChatContext';
import { dayKey, formatDayLabel } from '../utils';
import type { Session } from '../types';

interface MessageThreadProps {
  session: Session;
}

export function MessageThread({ session }: MessageThreadProps) {
  const { threads, recipientId } = useChat();
  const activeMessages = threads[recipientId] ?? [];

  return (
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
  );
}
