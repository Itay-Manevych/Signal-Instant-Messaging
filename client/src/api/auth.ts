import { readJsonOrThrow } from './http';

export type AuthResponse = {
  userId: string;
  username: string;
  token: string;
};

function assertAuthResponse(data: unknown): AuthResponse {
  if (
    !data ||
    typeof data !== 'object' ||
    !('token' in data) ||
    !('userId' in data) ||
    !('username' in data)
  ) {
    throw new Error('Invalid response');
  }
  return data as AuthResponse;
}

async function authRequest(path: string, username: string, password: string): Promise<AuthResponse> {
  const response = await fetch(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password }),
  });
  return assertAuthResponse(await readJsonOrThrow(response));
}

export function register(username: string, password: string): Promise<AuthResponse> {
  return authRequest('/api/register', username, password);
}

export function login(username: string, password: string): Promise<AuthResponse> {
  return authRequest('/api/login', username, password);
}

