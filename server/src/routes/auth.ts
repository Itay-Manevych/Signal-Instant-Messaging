import type { FastifyInstance } from 'fastify';
import type { UserStore } from '../store.js';

const USERNAME_RE = /^[a-zA-Z0-9._-]{3,32}$/;

function validateUsername(username: string): string | null {
  const t = username.trim();
  if (!USERNAME_RE.test(t)) {
    return 'Username must be 3–32 characters: letters, digits, . _ -';
  }
  return null;
}

function validatePassword(password: string): string | null {
  if (password.length < 8) return 'Password must be at least 8 characters';
  if (password.length > 128) return 'Password is too long';
  return null;
}

export async function registerAuthRoutes(
  app: FastifyInstance,
  store: UserStore,
): Promise<void> {
  app.post('/api/register', async (request, reply) => {
    const body = request.body as { username?: string; password?: string } | undefined;
    const username = body?.username ?? '';
    const password = body?.password ?? '';
    const uErr = validateUsername(username);
    if (uErr) return reply.code(400).send({ error: uErr });
    const pErr = validatePassword(password);
    if (pErr) return reply.code(400).send({ error: pErr });
    try {
      const user = await store.register(username, password);
      const token = await reply.jwtSign(
        { sub: user.id, username: user.username },
        { expiresIn: '7d' },
      );
      return { userId: user.id, username: user.username, token };
    } catch (e) {
      const msg = e instanceof Error ? e.message : 'Registration failed';
      if (msg.includes('taken')) return reply.code(409).send({ error: msg });
      throw e;
    }
  });

  app.post('/api/login', async (request, reply) => {
    const body = request.body as { username?: string; password?: string } | undefined;
    const username = body?.username ?? '';
    const password = body?.password ?? '';
    const user = await store.verifyPassword(username, password);
    if (!user) {
      return reply.code(401).send({ error: 'Invalid username or password' });
    }
    const token = await reply.jwtSign(
      { sub: user.id, username: user.username },
      { expiresIn: '7d' },
    );
    return { userId: user.id, username: user.username, token };
  });

  app.get(
    '/api/users',
    { onRequest: [app.authenticate] },
    async (request) => {
      const me = request.user as { sub: string; username: string };
      const all = store.listUsers().filter((u) => u.id !== me.sub);
      return { users: all };
    },
  );
}
