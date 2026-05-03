import { useChat } from './context/ChatContext';
import { TopBar } from './components/TopBar';
import { Sidebar } from './components/Sidebar';
import { MessageThread } from './components/MessageThread';
import { MessageInput } from './components/MessageInput';
import type { Session } from './types';
import './styles/Chat.css';

interface ChatProps {
  session: Session;
  draft: string;
  setDraft: (v: string) => void;
  onSend: () => void;
  onLogout: () => void;
  setTheme: (t: 'dark' | 'light') => void;
  theme: 'dark' | 'light';
}

export function Chat({
  session,
  draft,
  setDraft,
  onSend,
  onLogout,
  setTheme,
  theme,
}: ChatProps) {
  const { recipientId, peerList, onlineIds } = useChat();

  const activePeer = peerList.find(p => p.id === recipientId);
  const activePeerName = activePeer?.username ?? null;
  const activePeerOnline = onlineIds.has(recipientId);

  return (
    <main className="app">
      <TopBar 
        session={session} 
        theme={theme} 
        setTheme={setTheme} 
        onLogout={onLogout} 
      />

      <section className="chat-layout">
        <Sidebar session={session} />

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
              <MessageThread session={session} />
              <MessageInput draft={draft} setDraft={setDraft} onSend={onSend} />
            </>
          )}
        </section>
      </section>
    </main>
  );
}
