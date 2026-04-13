import Fastify from 'fastify';

const PORT = Number(process.env.PORT) || 3000;

const app = Fastify({ logger: true });

app.get('/api/health', async () => ({
  ok: true,
  service: 'signal-im-server',
}));

await app.listen({ port: PORT, host: '0.0.0.0' });
