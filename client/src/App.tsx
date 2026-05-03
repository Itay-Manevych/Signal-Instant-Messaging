import { useEffect, useState } from 'react';
import { Auth } from './Auth';
import { Chat } from './Chat';
import { useChat } from './context/ChatContext';
import { useWebSocket } from './hooks/useWebSocket';
import { useSignalMessaging } from './hooks/useSignalMessaging';
import { useSignalKeys } from './hooks/useSignalKeys';
import { useSendMessage } from './hooks/useSendMessage';
import { usePeers } from './hooks/usePeers';
import { login, register } from './api';
import { 
  loadSession, 
  loadTheme, 
  saveTheme,
} from './utils';
import type { Session, Theme } from './types';
import './styles/global.css';

export default function App() {
  const { 
    session,
    setSession,
    setWsState, 
    recipientId,
    setRecipientId
  } = useChat();

  const [savedSession, setSavedSession] = useState<Session | null>(loadSession());
  const [theme, setTheme] = useState<Theme>(loadTheme() ?? 'dark');
  const [busy, setBusy] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);
  const [authSuccess, setAuthSuccess] = useState<string | null>(null);
  const [draft, setDraft] = useState('');

  // 1. Core behavior hooks
  const { onIncomingMessage } = useSignalMessaging(session);
  const { getKeys } = useSignalKeys(session);
  const { loadPeers } = usePeers(session);

  const onConnected = () => {
    if (session) void loadPeers(session.token);
  };

  const onAuthError = () => {
    setSession(null);
    setSavedSession(null);
  };

  const { sendMessage } = useWebSocket({
    session,
    onMessage: onIncomingMessage,
    onConnected,
    onAuthError
  });

  const { handleSend: coreSend } = useSendMessage(session, recipientId, getKeys, sendMessage);

  // 2. Theme management
  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
    saveTheme(theme);
  }, [theme]);

  // 3. Actions
  const handleLogin = async (u: string, p: string) => {
    setFormError(null);
    setAuthSuccess(null);
    setBusy(true);
    try {
      const res = await login(u, p);
      const s: Session = { token: res.token, userId: res.userId, username: res.username };
      setSession(s);
      setSavedSession(s);
    } catch (err: any) {
      setFormError(err.message || 'Login failed');
    } finally {
      setBusy(false);
    }
  };

  const handleRegister = async (u: string, p: string) => {
    setFormError(null);
    setAuthSuccess(null);
    setBusy(true);
    try {
      await register(u, p);
      setAuthSuccess('Account created. Please sign in.');
    } catch (err: any) {
      setFormError(err.message || 'Registration failed');
    } finally {
      setBusy(false);
    }
  };

  const handleLogout = () => {
    setSession(null);
    setSavedSession(null);
    setRecipientId('');
    setWsState('idle');
  };

  const handleSend = async () => {
    await coreSend(draft);
    setDraft('');
  };

  if (!session) {
    return (
      <Auth
        busy={busy}
        error={formError || authSuccess}
        onLogin={handleLogin}
        onRegister={handleRegister}
        theme={theme}
        setTheme={setTheme}
        savedSession={savedSession}
        setSession={(s) => {
          setSession(s);
          setSavedSession(s);
        }}
        clearSession={() => {
          setSession(null);
          setSavedSession(null);
        }}
      />
    );
  }

  return (
    <Chat
      session={session}
      draft={draft}
      setDraft={setDraft}
      onSend={handleSend}
      onLogout={handleLogout}
      setTheme={setTheme}
      theme={theme}
    />
  );
}
