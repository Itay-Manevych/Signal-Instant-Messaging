import React from 'react';
import { useChat } from '../context/ChatContext';

interface MessageInputProps {
  draft: string;
  setDraft: (v: string) => void;
  onSend: () => void;
}

export function MessageInput({ draft, setDraft, onSend }: MessageInputProps) {
  const { wsState } = useChat();

  return (
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
  );
}
