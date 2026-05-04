import type { FastifyInstance } from 'fastify';
import type { WebSocket } from 'ws';
import { randomUUID } from 'node:crypto';
import type { ClientSocket, ConnectionHub, PendingChatMessage, UserStore } from '../store.js';
import { isChatEnvelope, type WsClientMessage, type WsServerMessage } from '../protocol.js';
import { chatLogFields, protocolLog } from '../logging.js';

function parseQueryToken(url: string | undefined): string | null {
  if (!url) return null;
  const q = url.includes('?') ? url.slice(url.indexOf('?')) : '';
  const params = new URLSearchParams(q);
  return params.get('token');
}

function parseQueryDeviceId(url: string | undefined): string {
  if (!url) return 'default';
  const q = url.includes('?') ? url.slice(url.indexOf('?')) : '';
  return new URLSearchParams(q).get('deviceId') || 'default';
}

function parseQueryDeviceSecret(url: string | undefined): string {
  if (!url) return '';
  const q = url.includes('?') ? url.slice(url.indexOf('?')) : '';
  return new URLSearchParams(q).get('deviceSecret') || '';
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
    hub.sendToUserDevices(id, payload);
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
    const deviceId = parseQueryDeviceId(req.url);
    const deviceSecret = parseQueryDeviceSecret(req.url);
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

    if (!deviceSecret) {
      socket.close(4401, 'Missing device secret');
      return;
    }
    store.upsertDevice(userId, deviceId, 'Browser', deviceSecret);
    if (!store.verifyDeviceSecret(userId, deviceId, deviceSecret)) {
      socket.close(4401, 'Invalid device secret');
      return;
    }
    const clientSocket: ClientSocket = {
      send: (data) => socket.send(data),
      close: (code, reason) => socket.close(code, reason),
    };
    hub.add(userId, deviceId, clientSocket);
    protocolLog('ws connected', { user: username, id: userId.slice(0, 8), device: deviceId.slice(0, 8) });

    const connected: WsServerMessage = {
      type: 'connected',
      userId,
      username: user.username,
      deviceId,
    };
    socket.send(JSON.stringify(connected));
    broadcastPresence(hub, store);

    // Flush queued messages for this user (offline delivery).
    const pending = store.listPendingMessagesForDevice(userId, deviceId);
    if (pending.length > 0) {
      protocolLog('offline messages flushed', { user: username, count: pending.length });
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
        const toDeviceId = 'toDeviceId' in msg && typeof msg.toDeviceId === 'string' ? msg.toDeviceId : 'default';
        const text = 'text' in msg && typeof msg.text === 'string' ? msg.text : '';
        const envelope = 'envelope' in msg && isChatEnvelope(msg.envelope) ? msg.envelope : undefined;
        const sesameSessionId = 'sesameSessionId' in msg && typeof msg.sesameSessionId === 'string'
          ? msg.sesameSessionId
          : envelope?.sesameSessionId;
        const clientMessageId = 'clientMessageId' in msg && typeof msg.clientMessageId === 'string'
          ? msg.clientMessageId
          : undefined;
        const syncPeerUserId = 'syncPeerUserId' in msg && typeof msg.syncPeerUserId === 'string'
          ? msg.syncPeerUserId
          : undefined;
        if (!toUserId || (!text.trim() && !envelope)) {
          const err: WsServerMessage = {
            type: 'error',
            message: 'chat requires toUserId and text or envelope',
          };
          socket.send(JSON.stringify(err));
          return;
        }
        const envelopeSize = envelope ? JSON.stringify(envelope).length : 0;
        if (text.length > 16_384 || envelopeSize > 32_768) {
          const err: WsServerMessage = {
            type: 'error',
            message: 'Message too long',
          };
          socket.send(JSON.stringify(err));
          return;
        }
        if (toUserId === userId && !syncPeerUserId) {
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
        if (syncPeerUserId && !store.getById(syncPeerUserId)) {
          socket.send(JSON.stringify({ type: 'error', message: 'Unknown sync peer' } satisfies WsServerMessage));
          return;
        }

        const out: PendingChatMessage = {
          id: randomUUID(),
          fromUserId: userId,
          fromUsername: user.username,
          fromDeviceId: deviceId,
          toUserId,
          toDeviceId,
          ...(sesameSessionId ? { sesameSessionId } : {}),
          ...(clientMessageId ? { clientMessageId } : {}),
          ...(syncPeerUserId ? { syncPeerUserId } : {}),
          senderVisible: !('senderEcho' in msg) || msg.senderEcho !== false,
          ...(text.trim() ? { text } : {}),
          ...(envelope ? { envelope } : {}),
          sentAt: new Date().toISOString(),
        };

        // Persist message history regardless of recipient online state.
        store.saveMessage(out);
        protocolLog('chat stored', chatLogFields(out));

        // Always echo to sender.
        const shouldEcho = !('senderEcho' in msg) || msg.senderEcho !== false;
        if (shouldEcho) hub.sendToDevice(userId, deviceId, { type: 'chat', ...out } satisfies WsServerMessage);

        // If recipient is online, deliver immediately; otherwise enqueue for later.
        const delivered = hub.sendToDevice(toUserId, toDeviceId, { type: 'chat', ...out } satisfies WsServerMessage);
        protocolLog('chat routed', { ...chatLogFields(out), delivered });
        if (!delivered) {
          store.enqueuePendingMessage(out);
          protocolLog('chat queued offline', chatLogFields(out));
        }
        return;
      }

      const err: WsServerMessage = { type: 'error', message: 'Unknown message type' };
      socket.send(JSON.stringify(err));
    });

    socket.on('close', () => {
      hub.remove(userId, deviceId, clientSocket);
      protocolLog('ws disconnected', { user: username, id: userId.slice(0, 8), device: deviceId.slice(0, 8) });
      broadcastPresence(hub, store);
    });
  });
}
