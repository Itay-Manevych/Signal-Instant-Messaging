import { useEffect, useRef, useCallback } from 'react';
import type { Session } from '../types';
import type { WsServerMessage } from '../protocol';
import { useChat } from '../context/ChatContext';

interface UseWebSocketOptions {
  session: Session | null;
  onMessage: (msg: WsServerMessage) => void;
  onConnected: () => void;
  onAuthError: (reason: string) => void;
}

export function useWebSocket({ session, onMessage, onConnected, onAuthError }: UseWebSocketOptions) {
  const { setWsState, setWsError, setOnlineIds } = useChat();
  const wsRef = useRef<WebSocket | null>(null);
  
  // Use refs to avoid re-triggering the connection when callbacks change
  const onMessageRef = useRef(onMessage);
  const onConnectedRef = useRef(onConnected);
  const onAuthErrorRef = useRef(onAuthError);

  useEffect(() => { onMessageRef.current = onMessage; }, [onMessage]);
  useEffect(() => { onConnectedRef.current = onConnected; }, [onConnected]);
  useEffect(() => { onAuthErrorRef.current = onAuthError; }, [onAuthError]);

  const connect = useCallback(() => {
    if (!session) return;
    if (wsRef.current && (wsRef.current.readyState === WebSocket.CONNECTING || wsRef.current.readyState === WebSocket.OPEN)) {
      console.log('🔌 WebSocket: Already connecting or open, skipping connect');
      return;
    }
    console.log('🔌 WebSocket: Connecting...');

    const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const url = `${proto}//${window.location.host}/api/ws?token=${encodeURIComponent(session.token)}`;

    setWsState('connecting');
    setWsError(null);
    
    const ws = new WebSocket(url);
    wsRef.current = ws;

    ws.onopen = () => {
      console.log('🟢 WebSocket: Open');
      setWsState('open');
      setWsError(null);
      onConnectedRef.current();
    };

    ws.onclose = (ev) => {
      console.log('🔴 WebSocket: Closed', ev.code, ev.reason);
      setWsState('closed');
      setOnlineIds(new Set());
      if (wsRef.current === ws) wsRef.current = null;

      if (ev.code === 4401) {
        const reason = ev.reason || 'Unauthorized';
        setWsError(`WebSocket closed: ${reason}`);
        onAuthErrorRef.current(reason);
      }
    };

    ws.onerror = (err) => {
      if (ws.readyState === WebSocket.CLOSING || ws.readyState === WebSocket.CLOSED) return;
      console.error('⚠️ WebSocket: Error', err);
      setWsError((prev) => prev ?? 'WebSocket error');
    };

    ws.onmessage = (ev) => {
      try {
        const msg = JSON.parse(String(ev.data)) as WsServerMessage;
        onMessageRef.current(msg);
      } catch (err) {
        console.error('Failed to parse WS message:', err);
      }
    };
  }, [session]);

  useEffect(() => {
    console.log('🔄 useWebSocket: Effect triggered', { hasSession: !!session });
    if (session) {
      connect();
    } else {
      wsRef.current?.close();
      wsRef.current = null;
      setWsState('idle');
      setOnlineIds(new Set());
    }

    return () => {
      console.log('🧹 useWebSocket: Cleaning up');
      wsRef.current?.close();
    };
  }, [session, connect]);

  const sendMessage = useCallback((payload: any) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify(payload));
    } else {
      console.warn('Cannot send message: WebSocket is not open');
    }
  }, []);

  return { sendMessage };
}
