import { useCallback } from 'react';
import { useChat } from '../context/ChatContext';
import { fetchUsers } from '../api';
import type { Session } from '../types';

export function usePeers(session: Session | null) {
  const { setPeerList } = useChat();

  const loadPeers = useCallback(async (token: string) => {
    try {
      const users = await fetchUsers(token);
      setPeerList(users.filter((u) => u.id !== session?.userId));
    } catch (err) {
      console.error('Failed to load users:', err);
    }
  }, [session?.userId, setPeerList]);

  return { loadPeers };
}
