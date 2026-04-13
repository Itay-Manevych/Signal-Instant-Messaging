import { randomUUID } from 'node:crypto';
import bcrypt from 'bcryptjs';

export type PublicUser = { id: string; username: string };

type UserRecord = {
  id: string;
  username: string;
  passwordHash: string;
};

/** In-memory user directory only (no database; data is lost on server restart). */
export class UserStore {
  private users = new Map<string, UserRecord>();
  private byUsername = new Map<string, string>();

  async register(username: string, password: string): Promise<PublicUser> {
    const normalized = username.trim().toLowerCase();
    if (this.byUsername.has(normalized)) {
      throw new Error('Username already taken');
    }
    const id = randomUUID();
    const passwordHash = await bcrypt.hash(password, 10);
    const u: UserRecord = { id, username: username.trim(), passwordHash };
    this.users.set(id, u);
    this.byUsername.set(normalized, id);
    return { id, username: u.username };
  }

  async verifyPassword(username: string, password: string): Promise<PublicUser | null> {
    const normalized = username.trim().toLowerCase();
    const id = this.byUsername.get(normalized);
    if (!id) return null;
    const u = this.users.get(id);
    if (!u) return null;
    const ok = await bcrypt.compare(password, u.passwordHash);
    if (!ok) return null;
    return { id: u.id, username: u.username };
  }

  getById(id: string): PublicUser | null {
    const u = this.users.get(id);
    return u ? { id: u.id, username: u.username } : null;
  }

  listUsers(): PublicUser[] {
    return [...this.users.values()].map((u) => ({ id: u.id, username: u.username }));
  }
}

export type ClientSocket = {
  send(data: string): void;
  close(code?: number, reason?: string): void;
};

export class ConnectionHub {
  private sockets = new Map<string, ClientSocket>();

  add(userId: string, socket: ClientSocket): void {
    const existing = this.sockets.get(userId);
    existing?.close(4000, 'Replaced by new connection');
    this.sockets.set(userId, socket);
  }

  remove(userId: string): void {
    this.sockets.delete(userId);
  }

  isOnline(userId: string): boolean {
    return this.sockets.has(userId);
  }

  sendTo(userId: string, payload: unknown): boolean {
    const socket = this.sockets.get(userId);
    if (!socket) return false;
    socket.send(JSON.stringify(payload));
    return true;
  }

  onlineUserIds(): string[] {
    return [...this.sockets.keys()];
  }
}
