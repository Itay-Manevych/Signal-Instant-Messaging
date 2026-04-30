# Signal Instant Messaging

Instant messaging secured with **end-to-end encryption** using the **Signal protocol** (implemented here with standard crypto libraries, not custom primitives).

**Stack**
- **Server:** Node.js, TypeScript, Fastify, `@fastify/websocket`, `@fastify/jwt`
- **Client:** React, TypeScript, Vite

## Data storage

The server uses **SQLite** for persistence (accounts + published identity public keys).

- **DB file**: set `DB_PATH` (default `./data/dev.sqlite` under `server/`)
- **Passwords**: stored as **bcrypt** hashes
- **WebSocket connections**: still memory-only (presence is ephemeral)

## Run

```bash
npm install
npm run dev
```

- API defaults to port **3000** (set `PORT` to change it).
- The Vite dev server proxies `/api` (including **WebSocket** upgrades) to the API. The proxy target defaults to `http://localhost:3000`; override with **`VITE_API_PROXY`** if you need a different port.
- Set **`JWT_SECRET`** in production (a default is used in development).
- Optional: set **`DB_PATH`** to control where the SQLite file lives (see `server/.env.example`).

**Environment file**

- Copy `server/.env.example` → `server/.env` and edit values as needed.

## Port 3000 already in use (EADDRINUSE)

Something else is already listening on **3000** (often a leftover `node` dev server).

**Option A — stop the process (Windows PowerShell):**

```powershell
Get-NetTCPConnection -LocalPort 3000 -State Listen -ErrorAction SilentlyContinue |
  Select-Object -ExpandProperty OwningProcess -Unique |
  ForEach-Object { Stop-Process -Id $_ -Force }
```

**Option B — run the API on another port** (server and Vite proxy stay in sync):

```bash
npm run dev:3001
```

## Try it

1. Open the app in the browser (Vite dev server URL, usually `http://localhost:5173`).
2. Register two accounts in two windows or incognito windows.
3. Pick an online user and send a message. Traffic is relayed in plaintext until E2EE is implemented.

**REST (examples)**

- `POST /api/register` — `{ "username", "password" }` → `{ userId, username, token }`
- `POST /api/login` — same shape as register response
- `GET /api/users` — `Authorization: Bearer <token>` → list of other users
- `PUT /api/keys/identity` — `Authorization: Bearer <token>` + `{ "publicKeyB64": "<base64 32 bytes>" }` → `{ ok: true }`
- `GET /api/keys/identity/:userId` — `Authorization: Bearer <token>` → `{ userId, username, identityKey }`
- `GET /api/health` — health check

**WebSocket**

- Connect to `ws://<host>/api/ws?token=<JWT>` (through Vite, use the same host as the page).
- Send JSON: `{ "type": "chat", "toUserId": "<uuid>", "text": "..." }` or `{ "type": "ping" }`.