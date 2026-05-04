const headers = (token: string) => ({
  'Content-Type': 'application/json',
  Authorization: `Bearer ${token}`,
});

export async function register(username: string, password: string) {
  const r = await fetch('/api/register', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password }),
  });
  const data = (await r.json()) as unknown;
  if (!r.ok) {
    const err =
      data && typeof data === 'object' && 'error' in data && typeof (data as { error: unknown }).error === 'string'
        ? (data as { error: string }).error
        : `HTTP ${r.status}`;
    throw new Error(err);
  }
  if (
    !data ||
    typeof data !== 'object' ||
    !('token' in data) ||
    !('userId' in data) ||
    !('username' in data)
  ) {
    throw new Error('Invalid response');
  }
  return data as { userId: string; username: string; token: string };
}

export async function login(username: string, password: string) {
  const r = await fetch('/api/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password }),
  });
  const data = (await r.json()) as unknown;
  if (!r.ok) {
    const err =
      data && typeof data === 'object' && 'error' in data && typeof (data as { error: unknown }).error === 'string'
        ? (data as { error: string }).error
        : `HTTP ${r.status}`;
    throw new Error(err);
  }
  if (
    !data ||
    typeof data !== 'object' ||
    !('token' in data) ||
    !('userId' in data) ||
    !('username' in data)
  ) {
    throw new Error('Invalid response');
  }
  return data as { userId: string; username: string; token: string };
}

export async function fetchUsers(token: string) {
  const r = await fetch('/api/users', { headers: headers(token) });
  const data = (await r.json()) as unknown;
  if (!r.ok) {
    const err =
      data && typeof data === 'object' && 'error' in data && typeof (data as { error: unknown }).error === 'string'
        ? (data as { error: string }).error
        : `HTTP ${r.status}`;
    throw new Error(err);
  }
  if (
    !data ||
    typeof data !== 'object' ||
    !('users' in data) ||
    !Array.isArray((data as { users: unknown }).users)
  ) {
    throw new Error('Invalid response');
  }
  return (data as { users: { id: string; username: string }[] }).users;
}

export async function fetchConversation(token: string, peerId: string) {
  const r = await fetch(`/api/messages/${encodeURIComponent(peerId)}`, { headers: headers(token) });
  const data = (await r.json()) as unknown;
  if (!r.ok) {
    const err =
      data && typeof data === 'object' && 'error' in data && typeof (data as { error: unknown }).error === 'string'
        ? (data as { error: string }).error
        : `HTTP ${r.status}`;
    throw new Error(err);
  }
  if (
    !data ||
    typeof data !== 'object' ||
    !('messages' in data) ||
    !Array.isArray((data as { messages: unknown }).messages)
  ) {
    throw new Error('Invalid response');
  }
  return (data as { messages: unknown[] }).messages as {
    id: string;
    fromUserId: string;
    fromUsername: string;
    toUserId: string;
    text: string;
    sentAt: string;
  }[];
}

export async function publishKeys(
  token: string,
  bundle: {
    identityKeyB64: string;
    signedPreKeyB64: string;
    signedPreKeySignatureB64: string;
    oneTimePreKeysB64: string[];
  }
) {
  const r = await fetch('/api/keys/publish', {
    method: 'POST',
    headers: headers(token),
    body: JSON.stringify(bundle),
  });
  if (!r.ok) {
    const data = (await r.json()) as any;
    throw new Error(data?.error || `HTTP ${r.status}`);
  }
  return (await r.json()) as { ok: boolean };
}
