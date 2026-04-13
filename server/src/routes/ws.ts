import type { FastifyInstance } from 'fastify';
import type { WebSocket } from 'ws';
import { randomUUID } from 'node:crypto';
import type { ConnectionHub, UserStore } from '../store.js';
import type { WsClientMessage, WsServerMessage } from '../protocol.js';

function parseQueryToken(url: string | undefined): string | null {
  if (!url) return null;
  const q = url.includes('?') ? url.slice(url.indexOf('?')) : '';
  const params = new URLSearchParams(q);
  return params.get('token');
}

function broadcastPresence(
  hub: ConnectionHub,
  store: UserStore,
): void {
  const online = hub.onlineUserIds().flatMap((id) => {
    const u = store.getById(id);
    return u ? [{ userId: u.id, username: u.username }] : [];
  });
  const payload: WsServerMessage = { type: 'presence', online };
  for (const id of hub.onlineUserIds()) {
    hub.sendTo(id, payload);
  }
}

export function registerWsRoutes(
  app: FastifyInstance,
  store: UserStore,
  hub: ConnectionHub,
): void {
  app.get('/api/ws', { websocket: true }, (socket: WebSocket, req) => {
    const rawToken = parseQueryToken(req.url);
    if (!rawToken) {
      socket.close(4401, 'Missing token');
      return;
    }

    let userId: string;
    let username: string;
    try {
      const payload = app.jwt.verify<{ sub: string; username: string }>(rawToken);
      userId = payload.sub;
      username = payload.username;
    } catch {
      socket.close(4401, 'Invalid token');
      return;
    }

    const user = store.getById(userId);
    if (!user || user.username !== username) {
      socket.close(4401, 'Unknown user');
      return;
    }

    hub.add(userId, {
      send: (data) => socket.send(data),
      close: (code, reason) => socket.close(code, reason),
    });

    const connected: WsServerMessage = {
      type: 'connected',
      userId,
      username: user.username,
    };
    socket.send(JSON.stringify(connected));
    broadcastPresence(hub, store);

    socket.on('message', (raw: WebSocket.RawData) => {
      let parsed: unknown;
      try {
        parsed = JSON.parse(raw.toString());
      } catch {
        const err: WsServerMessage = { type: 'error', message: 'Invalid JSON' };
        socket.send(JSON.stringify(err));
        return;
      }

      const msg = parsed as WsClientMessage;
      if (!msg || typeof msg !== 'object' || !('type' in msg)) {
        const err: WsServerMessage = { type: 'error', message: 'Invalid message' };
        socket.send(JSON.stringify(err));
        return;
      }

      if (msg.type === 'ping') {
        const out: WsServerMessage = { type: 'pong' };
        socket.send(JSON.stringify(out));
        return;
      }

      if (msg.type === 'chat') {
        const toUserId = typeof msg.toUserId === 'string' ? msg.toUserId : '';
        const text = typeof msg.text === 'string' ? msg.text : '';
        if (!toUserId || !text.trim()) {
          const err: WsServerMessage = {
            type: 'error',
            message: 'chat requires non-empty toUserId and text',
          };
          socket.send(JSON.stringify(err));
          return;
        }
        if (text.length > 16_384) {
          const err: WsServerMessage = {
            type: 'error',
            message: 'Message too long',
          };
          socket.send(JSON.stringify(err));
          return;
        }
        if (toUserId === userId) {
          const err: WsServerMessage = {
            type: 'error',
            message: 'Cannot message yourself',
          };
          socket.send(JSON.stringify(err));
          return;
        }
        const peer = store.getById(toUserId);
        if (!peer) {
          const err: WsServerMessage = {
            type: 'error',
            message: 'Unknown recipient',
          };
          socket.send(JSON.stringify(err));
          return;
        }
        if (!hub.isOnline(toUserId)) {
          const err: WsServerMessage = {
            type: 'error',
            message: 'Recipient is offline',
          };
          socket.send(JSON.stringify(err));
          return;
        }

        const out: WsServerMessage = {
          type: 'chat',
          id: randomUUID(),
          fromUserId: userId,
          fromUsername: user.username,
          toUserId,
          text,
          sentAt: new Date().toISOString(),
        };
        hub.sendTo(userId, out);
        hub.sendTo(toUserId, out);
        return;
      }

      const err: WsServerMessage = { type: 'error', message: 'Unknown message type' };
      socket.send(JSON.stringify(err));
    });

    socket.on('close', () => {
      hub.remove(userId);
      broadcastPresence(hub, store);
    });
  });
}
