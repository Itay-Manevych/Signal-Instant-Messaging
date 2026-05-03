type LogValue = string | number | boolean | undefined | null;

function fieldsToText(fields: Record<string, LogValue>): string {
  return Object.entries(fields)
    .filter(([, value]) => value !== undefined && value !== null)
    .map(([key, value]) => `${key}=${value}`)
    .join(' ');
}

export function shortId(value: string | undefined): string {
  if (!value) return 'unknown';
  return value.length > 12 ? value.slice(0, 8) : value;
}

export function protocolLog(event: string, fields: Record<string, LogValue> = {}): void {
  const details = fieldsToText(fields);
  console.log(`[signal-client] ${event}${details ? ` | ${details}` : ''}`);
}

export function protocolWarn(event: string, fields: Record<string, LogValue> = {}): void {
  const details = fieldsToText(fields);
  console.warn(`[signal-client] WARN ${event}${details ? ` | ${details}` : ''}`);
}

