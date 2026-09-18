// Browser WebAuthn wrappers for passkey ceremonies.
//
// The server issues opaque ceremony options JSON; this module converts the
// base64url fields the server sends into the ArrayBuffers the WebAuthn API
// requires, and encodes the authenticator response back to the base64url
// JSON the server verifies. Challenges, assertions, and keys live only in
// memory here: nothing is written to localStorage or any other browser
// storage.

function base64UrlToBuffer(input: string): ArrayBuffer {
  const base64 = input.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64 + '='.repeat((4 - (base64.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

function bufferToBase64Url(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.length; i += 1) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

interface CredentialDescriptorJSON {
  type: string;
  id: string;
  transports?: string[];
}

function convertDescriptor(d: CredentialDescriptorJSON): PublicKeyCredentialDescriptor {
  const out: PublicKeyCredentialDescriptor = {
    type: d.type as PublicKeyCredentialType,
    id: base64UrlToBuffer(d.id),
  };
  if (d.transports) out.transports = d.transports as AuthenticatorTransport[];
  return out;
}

// publicKeyOptions unwraps the server's { publicKey: {...} } envelope.
function publicKeyOptions(options: unknown): Record<string, unknown> {
  if (typeof options !== 'object' || options === null) {
    throw new Error('invalid ceremony options');
  }
  const envelope = options as { publicKey?: Record<string, unknown> };
  const publicKey = envelope.publicKey ?? (options as Record<string, unknown>);
  if (typeof publicKey.challenge !== 'string') {
    throw new Error('invalid ceremony options: missing challenge');
  }
  return publicKey;
}

function convertCreationOptions(options: unknown): PublicKeyCredentialCreationOptions {
  const o = publicKeyOptions(options);
  const user = o.user as { id: string; name: string; displayName: string };
  const excludeCredentials = (o.excludeCredentials as CredentialDescriptorJSON[] | undefined) ?? [];
  return {
    ...(o as object),
    challenge: base64UrlToBuffer(o.challenge as string),
    user: {
      ...user,
      id: base64UrlToBuffer(user.id),
    },
    excludeCredentials: excludeCredentials.map(convertDescriptor),
  } as PublicKeyCredentialCreationOptions;
}

function convertRequestOptions(options: unknown): PublicKeyCredentialRequestOptions {
  const o = publicKeyOptions(options);
  const allowCredentials = (o.allowCredentials as CredentialDescriptorJSON[] | undefined) ?? [];
  return {
    ...(o as object),
    challenge: base64UrlToBuffer(o.challenge as string),
    allowCredentials: allowCredentials.map(convertDescriptor),
  } as PublicKeyCredentialRequestOptions;
}

function baseResponse(cred: PublicKeyCredential): Record<string, unknown> {
  return {
    id: cred.id,
    rawId: bufferToBase64Url(cred.rawId),
    type: cred.type,
    authenticatorAttachment: cred.authenticatorAttachment ?? undefined,
    clientExtensionResults: cred.getClientExtensionResults(),
  };
}

// createPasskey runs navigator.credentials.create for a registration
// ceremony and returns the attestation response JSON for the server.
export async function createPasskey(options: unknown): Promise<unknown> {
  if (typeof navigator === 'undefined' || !navigator.credentials?.create) {
    throw new Error('this browser does not support passkeys');
  }
  const publicKey = convertCreationOptions(options);
  const cred = (await navigator.credentials.create({ publicKey })) as PublicKeyCredential | null;
  if (!cred) {
    throw new Error('passkey registration was cancelled');
  }
  const response = cred.response as AuthenticatorAttestationResponse;
  return {
    ...baseResponse(cred),
    response: {
      clientDataJSON: bufferToBase64Url(response.clientDataJSON),
      attestationObject: bufferToBase64Url(response.attestationObject),
      transports: response.getTransports(),
    },
  };
}

// getPasskey runs navigator.credentials.get for a login ceremony and
// returns the assertion response JSON for the server.
export async function getPasskey(options: unknown): Promise<unknown> {
  if (typeof navigator === 'undefined' || !navigator.credentials?.get) {
    throw new Error('this browser does not support passkeys');
  }
  const publicKey = convertRequestOptions(options);
  const cred = (await navigator.credentials.get({ publicKey })) as PublicKeyCredential | null;
  if (!cred) {
    throw new Error('passkey authentication was cancelled');
  }
  const response = cred.response as AuthenticatorAssertionResponse;
  return {
    ...baseResponse(cred),
    response: {
      clientDataJSON: bufferToBase64Url(response.clientDataJSON),
      authenticatorData: bufferToBase64Url(response.authenticatorData),
      signature: bufferToBase64Url(response.signature),
      userHandle: response.userHandle ? bufferToBase64Url(response.userHandle) : null,
    },
  };
}
