const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:5173/api';

export async function fetchUsers(token: string): Promise<{ id: string; username: string }[]> {
  const res = await fetch(`${API_URL}/users`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!res.ok) throw new Error('Failed to fetch users');
  const data = await res.json();
  return data.users;
}

export async function publishKeys(token: string, bundle: any): Promise<void> {
  const res = await fetch(`${API_URL}/keys`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(bundle),
  });
  if (!res.ok) throw new Error('Failed to publish keys');
}

export async function fetchPreKeyBundle(token: string, userId: string): Promise<any> {
  const res = await fetch(`${API_URL}/keys/${userId}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!res.ok) throw new Error('Failed to fetch pre-key bundle');
  return res.json();
}
