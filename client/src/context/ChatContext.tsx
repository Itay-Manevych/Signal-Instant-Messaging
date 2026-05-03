import React, { createContext, useContext, useState, useMemo, useEffect } from 'react';
import type { ChatMessage, Session } from '../types';
import { loadSession, saveSession, clearSession, loadThreads, saveThreads } from '../utils';

interface ChatContextType {
  session: Session | null;
  setSession: (s: Session | null) => void;
  threads: Record<string, ChatMessage[]>;
  setThreads: React.Dispatch<React.SetStateAction<Record<string, ChatMessage[]>>>;
  peerList: { id: string; username: string }[];
  setPeerList: React.Dispatch<React.SetStateAction<{ id: string; username: string }[]>>;
  onlineIds: Set<string>;
  setOnlineIds: React.Dispatch<React.SetStateAction<Set<string>>>;
  wsState: 'idle' | 'connecting' | 'open' | 'closed';
  setWsState: React.Dispatch<React.SetStateAction<'idle' | 'connecting' | 'open' | 'closed'>>;
  wsError: string | null;
  setWsError: React.Dispatch<React.SetStateAction<string | null>>;
  recipientId: string;
  setRecipientId: React.Dispatch<React.SetStateAction<string>>;
}

const ChatContext = createContext<ChatContextType | undefined>(undefined);

export function ChatProvider({ children }: { children: React.ReactNode }) {
  const [session, setSessionState] = useState<Session | null>(loadSession());
  const [threads, setThreads] = useState<Record<string, ChatMessage[]>>({});
  const [peerList, setPeerList] = useState<{ id: string; username: string }[]>([]);
  const [onlineIds, setOnlineIds] = useState<Set<string>>(new Set());
  const [wsState, setWsState] = useState<'idle' | 'connecting' | 'open' | 'closed'>('idle');
  const [wsError, setWsError] = useState<string | null>(null);
  const [recipientId, setRecipientId] = useState<string>('');

  const setSession = (s: Session | null) => {
    if (s) saveSession(s);
    else clearSession();
    setSessionState(s);
  };

  // Load threads on mount/session change
  useEffect(() => {
    if (session) {
      setThreads(loadThreads(session.userId));
    } else {
      setThreads({});
    }
  }, [session]);

  // Save threads whenever they change
  useEffect(() => {
    if (session && Object.keys(threads).length > 0) {
      saveThreads(session.userId, threads);
    }
  }, [session, threads]);

  const value = useMemo(() => ({
    session,
    setSession,
    threads,
    setThreads,
    peerList,
    setPeerList,
    onlineIds,
    setOnlineIds,
    wsState,
    setWsState,
    wsError,
    setWsError,
    recipientId,
    setRecipientId,
  }), [session, threads, peerList, onlineIds, wsState, wsError, recipientId]);

  return (
    <ChatContext.Provider value={value}>
      {children}
    </ChatContext.Provider>
  );
}

export function useChat() {
  const context = useContext(ChatContext);
  if (context === undefined) {
    throw new Error('useChat must be used within a ChatProvider');
  }
  return context;
}
