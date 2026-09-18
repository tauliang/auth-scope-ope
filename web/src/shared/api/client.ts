import type { BootstrapResponse } from './generated';

// ApiError is raised for non-2xx local API responses.
export class ApiError extends Error {
  readonly status: number;
  constructor(status: number, message: string) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
  }
}

// request performs a same-origin JSON request. Credentials are never sent
// cross-origin: every OPE API call is same-origin by construction, and the
// client refuses to attach cookies elsewhere.
async function request<T>(path: string, init?: RequestInit): Promise<T> {
  /* v8 ignore next -- defensive: all call sites use compile-time local paths */
  if (!path.startsWith('/')) {
    throw new Error(`refusing non-local API path: ${path}`);
  }
  const res = await fetch(path, {
    credentials: 'same-origin',
    headers: { Accept: 'application/json' },
    ...init,
  });
  if (!res.ok) {
    throw new ApiError(res.status, `request to ${path} failed with status ${res.status}`);
  }
  return (await res.json()) as T;
}

// fetchBootstrap loads the first-paint product state.
export function fetchBootstrap(): Promise<BootstrapResponse> {
  return request<BootstrapResponse>('/api/v1/bootstrap');
}

// fetchHealth checks process liveness.
export function fetchHealth(): Promise<{ status: string }> {
  return request<{ status: string }>('/healthz');
}
