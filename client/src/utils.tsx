import { deserializeRatchetState, serializeRatchetState, type RatchetState } from './crypto/doubleRatchet';
import type { Session, Theme, ChatMessage } from './types';

export const SunIcon = () => (
  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/>
  </svg>
);

export const MoonIcon = () => (
  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/>
  </svg>
);

export const dayKey = (iso: string) => iso.split('T')[0];
export const formatDayLabel = (iso: string) => {
  const d = new Date(iso);
  const now = new Date();
  if (dayKey(iso) === dayKey(now.toISOString())) return 'Today';
  return d.toLocaleDateString(undefined, { weekday: 'long', month: 'short', day: 'numeric' });
};

const SESSION_PREFIX = 'signal-session-';

export function getSession(peerId: string): RatchetState | null {
  const data = localStorage.getItem(SESSION_PREFIX + peerId);
  return data ? deserializeRatchetState(data) : null;
}

export function saveSessionState(peerId: string, state: RatchetState) {
  localStorage.setItem(SESSION_PREFIX + peerId, serializeRatchetState(state));
}

export function getKeys(userId: string) {
  const raw = localStorage.getItem(`signal-keys-${userId}`);
  return raw ? JSON.parse(raw) : null;
}

const TOKEN_KEY = 'signal-im-token';
const USER_KEY = 'signal-im-user';
const THEME_KEY = 'signal-im-theme';

export function loadSession(): Session | null {
  try {
    const raw = sessionStorage.getItem(USER_KEY);
    const token = sessionStorage.getItem(TOKEN_KEY);
    if (!raw || !token) return null;
    const u = JSON.parse(raw) as { userId: string; username: string };
    if (!u.userId || !u.username) return null;
    return { token, userId: u.userId, username: u.username };
  } catch {
    return null;
  }
}

export function saveSession(s: Session) {
  sessionStorage.setItem(TOKEN_KEY, s.token);
  sessionStorage.setItem(
    USER_KEY,
    JSON.stringify({ userId: s.userId, username: s.username }),
  );
}

export function clearSession() {
  sessionStorage.removeItem(TOKEN_KEY);
  sessionStorage.removeItem(USER_KEY);
}

export function loadTheme(): Theme | null {
  try {
    const raw = localStorage.getItem(THEME_KEY);
    return raw === 'light' || raw === 'dark' ? raw : null;
  } catch {
    return null;
  }
}

export function saveTheme(theme: Theme) {
  localStorage.setItem(THEME_KEY, theme);
}

export function loadThreads(userId: string): Record<string, ChatMessage[]> {
  try {
    const raw = localStorage.getItem(`signal-threads-${userId}`);
    return raw ? JSON.parse(raw) : {};
  } catch {
    return {};
  }
}

export function saveThreads(userId: string, threads: Record<string, ChatMessage[]>) {
  localStorage.setItem(`signal-threads-${userId}`, JSON.stringify(threads));
}
