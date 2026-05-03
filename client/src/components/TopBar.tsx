import { useChat } from '../context/ChatContext';
import { SunIcon, MoonIcon } from '../utils';
import type { Session } from '../types';

interface TopBarProps {
  session: Session;
  theme: 'dark' | 'light';
  setTheme: (t: 'dark' | 'light') => void;
  onLogout: () => void;
}

export function TopBar({ session, theme, setTheme, onLogout }: TopBarProps) {
  const { wsState } = useChat();

  return (
    <header className="topbar">
      <div>
        <h1>Signal Instant Messaging</h1>
        <p className="tagline">Signed in as {session.username}</p>
        <p className="status-line">
          WebSocket: <span className={wsState === 'open' ? 'ok' : 'warn'}>{wsState}</span>
        </p>
      </div>
      <div className="topbar-actions">
        <button
          type="button"
          className="ghost theme-toggle"
          onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')}
        >
          <span className="theme-icon">{theme === 'dark' ? <SunIcon /> : <MoonIcon />}</span>
          <span className="theme-label">{theme === 'dark' ? 'Light' : 'Dark'}</span>
        </button>
        <button type="button" className="ghost" onClick={onLogout}>
          Sign out
        </button>
      </div>
    </header>
  );
}
