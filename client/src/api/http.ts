export const authHeaders = (token: string) => ({
  'Content-Type': 'application/json',
  Authorization: `Bearer ${token}`,
});

export function errorFromResponse(data: unknown, status: number): Error {
  const error =
    data &&
    typeof data === 'object' &&
    'error' in data &&
    typeof (data as { error: unknown }).error === 'string'
      ? (data as { error: string }).error
      : `HTTP ${status}`;
  return new Error(error);
}

export async function readJsonOrThrow(response: Response): Promise<unknown> {
  const data = (await response.json()) as unknown;
  if (!response.ok) throw errorFromResponse(data, response.status);
  return data;
}

