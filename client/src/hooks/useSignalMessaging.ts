import { useCallback } from 'react';
import type { Session } from '../types';
import type { WsServerMessage } from '../protocol';
import { useChat } from '../context/ChatContext';
import { useMessageQueue } from './useMessageQueue';

export function useSignalMessaging(session: Session | null) {
  const { setOnlineIds, setWsError } = useChat();
  const { enqueue } = useMessageQueue(session);

  const onIncomingMessage = useCallback((msg: WsServerMessage) => {
    if (msg.type === 'presence') {
      setOnlineIds(new Set(msg.online.map((x) => x.userId)));
      return;
    }
    if (msg.type === 'chat') {
      enqueue(msg);
    }
    if (msg.type === 'error') {
      setWsError(msg.message);
    }
  }, [setOnlineIds, setWsError, enqueue]);

  return { onIncomingMessage };
}
