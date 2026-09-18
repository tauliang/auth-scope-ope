import type {
  BootstrapBeginRequest,
  BootstrapBeginResponse,
  BootstrapCompleteRequest,
  BootstrapRecoveryBeginRequest,
  BootstrapRecoveryBeginResponse,
  BootstrapRegisterBeginRequest,
  BootstrapRegisterFinishResponse,
  BootstrapResponse,
  CeremonyBeginResponse,
  CeremonyFinishRequest,
  ProblemResponse,
  SessionResponse,
} from './generated';

// ApiError is raised for non-2xx local API responses. When the server
// answers with application/problem+json, title carries the server's
// human-readable reason; it never contains credential or challenge
// material.
export class ApiError extends Error {
  readonly status: number;
  readonly title: string;
  constructor(status: number, message: string, title?: string) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.title = title ?? message;
  }
}

// problemTitle extracts the problem title from a failed response, if any.
async function problemTitle(res: Response): Promise<string | undefined> {
  try {
    const body = (await res.json()) as Partial<ProblemResponse>;
    return typeof body.title === 'string' ? body.title : undefined;
  } catch {
    return undefined;
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
    const title = await problemTitle(res);
    throw new ApiError(
      res.status,
      `request to ${path} failed with status ${res.status}`,
      title,
    );
  }
  return (await res.json()) as T;
}

// postJson performs a same-origin JSON POST. The server requires exactly
// application/json.
function postJson<T>(path: string, body: unknown): Promise<T> {
  return request<T>(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
}

// fetchBootstrap loads the first-paint product state.
export function fetchBootstrap(): Promise<BootstrapResponse> {
  return request<BootstrapResponse>('/api/v1/bootstrap');
}

// fetchHealth checks process liveness.
export function fetchHealth(): Promise<{ status: string }> {
  return request<{ status: string }>('/healthz');
}

// authBootstrapBegin opens the enrollment ceremony with the terminal code.
export function authBootstrapBegin(code: string): Promise<BootstrapBeginResponse> {
  const body: BootstrapBeginRequest = { code };
  return postJson<BootstrapBeginResponse>('/api/v1/bootstrap/begin', body);
}

// authBootstrapRegisterBegin issues WebAuthn creation options inside the
// enrollment ceremony.
export function authBootstrapRegisterBegin(displayName?: string): Promise<CeremonyBeginResponse> {
  const body: BootstrapRegisterBeginRequest = displayName ? { display_name: displayName } : {};
  return postJson<CeremonyBeginResponse>('/api/v1/auth/register/begin', body);
}

// authBootstrapRegisterFinish verifies the attestation response.
export function authBootstrapRegisterFinish(
  ceremonyId: string,
  response: unknown,
): Promise<BootstrapRegisterFinishResponse> {
  const body: CeremonyFinishRequest = { ceremony_id: ceremonyId, response };
  return postJson<BootstrapRegisterFinishResponse>('/api/v1/auth/register/finish', body);
}

// authBootstrapRecoveryBegin starts the independent recovery method.
export function authBootstrapRecoveryBegin(
  method: 'passkey' | 'offline_key',
): Promise<BootstrapRecoveryBeginResponse> {
  const body: BootstrapRecoveryBeginRequest = { method };
  return postJson<BootstrapRecoveryBeginResponse>('/api/v1/bootstrap/recovery/begin', body);
}

// authBootstrapComplete confirms the recovery method and creates the
// first founder session, returning the session-bound CSRF token.
export function authBootstrapComplete(recoveryConfirmation?: string): Promise<SessionResponse> {
  const body: BootstrapCompleteRequest =
    recoveryConfirmation !== undefined ? { recovery_confirmation: recoveryConfirmation } : {};
  return postJson<SessionResponse>('/api/v1/bootstrap/complete', body);
}

// authLoginBegin issues WebAuthn request options for the enrolled founder.
export function authLoginBegin(): Promise<CeremonyBeginResponse> {
  return postJson<CeremonyBeginResponse>('/api/v1/auth/login/begin', {});
}

// authLoginFinish verifies the assertion and rotates the founder session,
// returning the session-bound CSRF token.
export function authLoginFinish(ceremonyId: string, response: unknown): Promise<SessionResponse> {
  const body: CeremonyFinishRequest = { ceremony_id: ceremonyId, response };
  return postJson<SessionResponse>('/api/v1/auth/login/finish', body);
}
