import Fastify from 'fastify';
import fastifyJwt from '@fastify/jwt';
import fastifyWebsocket from '@fastify/websocket';
import type { FastifyReply, FastifyRequest } from 'fastify';
import { ConnectionHub, UserStore } from './store.js';
import { registerAuthRoutes } from './routes/auth.js';
import { registerWsRoutes } from './routes/ws.js';

const PORT = Number(process.env.PORT) || 3000;
const JWT_SECRET = process.env.JWT_SECRET ?? 'dev-secret-change-in-production';

const app = Fastify({ logger: true });

const store = new UserStore();
const hub = new ConnectionHub();

await app.register(fastifyJwt, {
  secret: JWT_SECRET,
});

app.decorate(
  'authenticate',
  async function (request: FastifyRequest, reply: FastifyReply) {
    try {
      await request.jwtVerify();
    } catch (err) {
      reply.send(err);
    }
  },
);

app.get('/api/health', async () => ({
  ok: true,
  service: 'signal-im-server',
}));

await registerAuthRoutes(app, store);

await app.register(fastifyWebsocket);
registerWsRoutes(app, store, hub);

if (JWT_SECRET === 'dev-secret-change-in-production') {
  app.log.warn('Using default JWT_SECRET; set JWT_SECRET in production.');
}

await app.listen({ port: PORT, host: '0.0.0.0' });
