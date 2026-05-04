export type LocalDevice = {
  deviceId: string;
  deviceSecret: string;
  name: string;
  linkedAt: string;
};

function randomId(): string {
  if (typeof crypto.randomUUID === 'function') return crypto.randomUUID();
  return `dev-${Date.now()}-${Math.random().toString(36).slice(2)}`;
}

function randomSecret(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return btoa(String.fromCharCode(...bytes));
}

function storageKey(userId: string): string {
  return `signal-device-${userId}`;
}

const installKey = 'signal-browser-installation-device';

function defaultName(): string {
  const agent = navigator.userAgent.includes('Firefox')
    ? 'Firefox'
    : navigator.userAgent.includes('Chrome')
      ? 'Chrome'
      : 'Browser';
  return `${agent} device`;
}

export function loadOrCreateDevice(userId: string): LocalDevice {
  try {
    const raw = localStorage.getItem(storageKey(userId));
    if (raw) {
      const parsed = JSON.parse(raw) as Partial<LocalDevice>;
      if (parsed.deviceId && parsed.name) {
        const device = {
          deviceId: parsed.deviceId,
          deviceSecret: parsed.deviceSecret ?? randomSecret(),
          name: parsed.name,
          linkedAt: parsed.linkedAt ?? new Date().toISOString(),
        };
        if (!parsed.linkedAt || !parsed.deviceSecret) localStorage.setItem(storageKey(userId), JSON.stringify(device));
        return device;
      }
    }
  } catch {
    // Regenerate below.
  }
  const device = {
    deviceId: loadOrCreateInstallId(),
    deviceSecret: randomSecret(),
    name: defaultName(),
    linkedAt: new Date().toISOString(),
  };
  localStorage.setItem(storageKey(userId), JSON.stringify(device));
  return device;
}

function loadOrCreateInstallId(): string {
  const existing = localStorage.getItem(installKey);
  if (existing) return existing;
  const next = randomId();
  localStorage.setItem(installKey, next);
  return localStorage.getItem(installKey) ?? next;
}
