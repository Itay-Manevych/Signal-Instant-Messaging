import type { FastifyInstance } from 'fastify';
import type { WebSocket } from 'ws';
import { randomUUID } from 'node:crypto';
import type { ConnectionHub, PendingChatMessage, UserStore } from '../store.js';
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

    // Flush queued messages for this user (offline delivery).
    const pending = store.listPendingMessagesForUser(userId);
    if (pending.length > 0) {
      for (const msg of pending) {
        const out: WsServerMessage = { type: 'chat', ...msg };
        socket.send(JSON.stringify(out));
      }
      store.deletePendingMessages(pending.map((m) => m.id));
    }

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

        const out: PendingChatMessage = {
          id: randomUUID(),
          fromUserId: userId,
          fromUsername: user.username,
          toUserId,
          text,
          sentAt: new Date().toISOString(),
        };

        // Persist message history regardless of recipient online state.
        store.saveMessage(out);

        // Always echo to sender.
        hub.sendTo(userId, { type: 'chat', ...out } satisfies WsServerMessage);

        // If recipient is online, deliver immediately; otherwise enqueue for later.
        const delivered = hub.sendTo(toUserId, { type: 'chat', ...out } satisfies WsServerMessage);
        if (!delivered) {
          store.enqueuePendingMessage(out);
        }
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
