import type { PendingChatMessage } from './store.js';

type LogValue = string | number | boolean | undefined;

function short(value: string | undefined): string | undefined {
  if (!value) return undefined;
  return value.length > 12 ? value.slice(0, 8) : value;
}

function fieldsToText(fields: Record<string, LogValue>): string {
  return Object.entries(fields)
    .filter(([, value]) => value !== undefined)
    .map(([key, value]) => `${key}=${value}`)
    .join(' ');
}

export function protocolLog(event: string, fields: Record<string, LogValue> = {}): void {
  const details = fieldsToText(fields);
  console.log(`[signal] ${event}${details ? ` | ${details}` : ''}`);
}

export function protocolWarn(event: string, fields: Record<string, LogValue> = {}): void {
  const details = fieldsToText(fields);
  console.warn(`[signal] WARN ${event}${details ? ` | ${details}` : ''}`);
}

export function chatLogFields(msg: PendingChatMessage) {
  return {
    msg: short(msg.id),
    from: short(msg.fromUserId),
    to: short(msg.toUserId),
    format: msg.envelope ? 'envelope' : 'legacy-text',
    envelopeKind: msg.envelope?.kind,
  };
}
