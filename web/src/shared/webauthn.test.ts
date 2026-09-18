import { describe, expect, it, vi, afterEach } from 'vitest';
import { createPasskey, getPasskey } from './webauthn';

function b64url(bytes: number[]): string {
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

function stubCredentials(create: unknown, get: unknown) {
  Object.defineProperty(window.navigator, 'credentials', {
    value: { create, get },
    configurable: true,
  });
}

describe('webauthn browser wrappers', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
    // Remove the credentials stub so each test starts without WebAuthn.
    delete (window.navigator as unknown as Record<string, unknown>).credentials;
  });

  it('createPasskey converts options and encodes the attestation', async () => {
    const create = vi.fn().mockResolvedValue({
      id: 'cred-id',
      rawId: new Uint8Array([1, 2, 3]).buffer,
      type: 'public-key',
      authenticatorAttachment: 'platform',
      getClientExtensionResults: () => ({}),
      response: {
        clientDataJSON: new Uint8Array([4]).buffer,
        attestationObject: new Uint8Array([5]).buffer,
        getTransports: () => ['internal'],
      },
    });
    stubCredentials(create, vi.fn());

    const options = {
      publicKey: {
        challenge: b64url([9, 9]),
        rp: { name: 'x', id: 'ope.example.com' },
        user: { id: b64url([7]), name: 'founder', displayName: 'Founder' },
        pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
        excludeCredentials: [{ type: 'public-key', id: b64url([8]), transports: ['internal'] }],
      },
    };
    const response = (await createPasskey(options)) as {
      id: string;
      rawId: string;
      response: { clientDataJSON: string; attestationObject: string; transports: string[] };
    };

    const [args] = create.mock.calls[0] as [{ publicKey: PublicKeyCredentialCreationOptions }];
    expect(args.publicKey.challenge).toBeInstanceOf(ArrayBuffer);
    expect(new Uint8Array(args.publicKey.challenge as ArrayBuffer)).toEqual(new Uint8Array([9, 9]));
    const user = args.publicKey.user as PublicKeyCredentialUserEntity & { id: ArrayBuffer };
    expect(new Uint8Array(user.id)).toEqual(new Uint8Array([7]));
    const excluded = args.publicKey.excludeCredentials as PublicKeyCredentialDescriptor[];
    expect(new Uint8Array(excluded[0].id as ArrayBuffer)).toEqual(new Uint8Array([8]));
    expect(excluded[0].transports).toEqual(['internal']);

    expect(response.id).toBe('cred-id');
    expect(response.rawId).toBe(b64url([1, 2, 3]));
    expect(response.response.clientDataJSON).toBe(b64url([4]));
    expect(response.response.attestationObject).toBe(b64url([5]));
    expect(response.response.transports).toEqual(['internal']);
  });

  it('getPasskey converts options and encodes the assertion', async () => {
    const get = vi.fn().mockResolvedValue({
      id: 'cred-id',
      rawId: new Uint8Array([1]).buffer,
      type: 'public-key',
      authenticatorAttachment: null,
      getClientExtensionResults: () => ({}),
      response: {
        clientDataJSON: new Uint8Array([2]).buffer,
        authenticatorData: new Uint8Array([3]).buffer,
        signature: new Uint8Array([4]).buffer,
        userHandle: null,
      },
    });
    stubCredentials(vi.fn(), get);

    const options = {
      publicKey: {
        challenge: b64url([6]),
        allowCredentials: [{ type: 'public-key', id: b64url([1]) }],
        userVerification: 'required',
      },
    };
    const response = (await getPasskey(options)) as {
      response: { authenticatorData: string; signature: string; userHandle: null };
    };

    const [args] = get.mock.calls[0] as [{ publicKey: PublicKeyCredentialRequestOptions }];
    expect(new Uint8Array(args.publicKey.challenge as ArrayBuffer)).toEqual(new Uint8Array([6]));
    expect(response.response.authenticatorData).toBe(b64url([3]));
    expect(response.response.signature).toBe(b64url([4]));
    expect(response.response.userHandle).toBeNull();
  });

  it('throws a clear error without WebAuthn support', async () => {
    await expect(createPasskey({ publicKey: { challenge: b64url([1]) } })).rejects.toThrow(
      'does not support passkeys',
    );
    await expect(getPasskey({ publicKey: { challenge: b64url([1]) } })).rejects.toThrow(
      'does not support passkeys',
    );
  });

  it('rejects malformed ceremony options', async () => {
    stubCredentials(vi.fn(), vi.fn());
    await expect(createPasskey({})).rejects.toThrow('invalid ceremony options');
    await expect(createPasskey(null)).rejects.toThrow('invalid ceremony options');
  });

  it('throws when the user cancels the ceremony', async () => {
    stubCredentials(vi.fn().mockResolvedValue(null), vi.fn().mockResolvedValue(null));
    const createOptions = {
      publicKey: {
        challenge: b64url([1]),
        user: { id: b64url([2]), name: 'founder', displayName: 'Founder' },
        pubKeyCredParams: [],
      },
    };
    const getOptions = { publicKey: { challenge: b64url([1]) } };
    await expect(createPasskey(createOptions)).rejects.toThrow('cancelled');
    await expect(getPasskey(getOptions)).rejects.toThrow('cancelled');
  });
});
