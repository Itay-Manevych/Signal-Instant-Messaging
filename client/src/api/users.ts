import { authHeaders, readJsonOrThrow } from './http';

export type PublicUser = {
  id: string;
  username: string;
};

export async function fetchUsers(token: string): Promise<PublicUser[]> {
  const response = await fetch('/api/users', { headers: authHeaders(token) });
  const data = await readJsonOrThrow(response);
  if (
    !data ||
    typeof data !== 'object' ||
    !('users' in data) ||
    !Array.isArray((data as { users: unknown }).users)
  ) {
    throw new Error('Invalid response');
  }
  return (data as { users: PublicUser[] }).users;
}

