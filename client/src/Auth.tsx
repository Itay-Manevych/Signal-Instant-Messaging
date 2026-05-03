import { useState } from 'react';
import type { Session, Theme } from './types';
import './styles/Auth.css';

interface AuthProps {
  busy: boolean;
  error: string | null;
  onLogin: (u: string, p: string) => void;
  onRegister: (u: string, p: string) => void;
  theme: Theme;
  setTheme: (t: Theme) => void;
  savedSession: Session | null;
  setSession: (s: Session) => void;
  clearSession: () => void;
}

export function Auth({ busy, error, onLogin, onRegister, theme, setTheme, savedSession, setSession, clearSession }: AuthProps) {
  const [mode, setMode] = useState<'login' | 'register'>('login');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [password2, setPassword2] = useState('');

  const submitAuth = () => {
    if (mode === 'register' && password !== password2) return;
    if (mode === 'login') onLogin(username, password);
    else onRegister(username, password);
  };

  return (
    <main className="app">
      <div className="auth-topbar">
        <h1>Signal IM</h1>
        <button
          type="button"
          className="ghost theme-toggle"
          onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')}
        >
          <span className="theme-label">{theme === 'dark' ? 'Light' : 'Dark'}</span>
        </button>
      </div>
      <div className="auth-stack">
        {savedSession && (
          <section className="card resume-card">
            <h2>Resume session?</h2>
            <p className="hint">
              You have a saved session as <b>{savedSession.username}</b>.
            </p>
            <div className="actions">
              <button type="button" onClick={() => setSession(savedSession)}>
                Continue as {savedSession.username}
              </button>
              <button
                type="button"
                className="ghost"
                onClick={() => {
                  clearSession();
                  window.location.reload();
                }}
              >
                Sign in as different user
              </button>
            </div>
          </section>
        )}

        <section className="card">
          <h2>{mode === 'login' ? 'Sign in' : 'Create account'}</h2>
          {error && <p className="error">{error}</p>}
          <div className="field">
            <label htmlFor="user">Username</label>
            <input id="user" value={username} onChange={(e) => setUsername(e.target.value)} />
          </div>
          <div className="field">
            <label htmlFor="pass">Password</label>
            <input id="pass" type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
          </div>
          {mode === 'register' && (
            <div className="field">
              <label htmlFor="pass2">Confirm password</label>
              <input id="pass2" type="password" value={password2} onChange={(e) => setPassword2(e.target.value)} />
            </div>
          )}
          <div className="actions">
            <button type="button" disabled={busy} onClick={submitAuth}>
              {busy ? '…' : mode === 'login' ? 'Sign in' : 'Register'}
            </button>
            <button
              type="button"
              className="ghost"
              onClick={() => setMode(mode === 'login' ? 'register' : 'login')}
            >
              {mode === 'login' ? 'Need an account?' : 'Have an account?'}
            </button>
          </div>
        </section>
      </div>
    </main>
  );
}
