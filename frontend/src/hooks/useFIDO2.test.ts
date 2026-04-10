import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { renderHook, act } from '@testing-library/react';
import { useFIDO2 } from './useFIDO2';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// Minimal base64url-encoded challenge that parseCreationOptions can decode.
const CHALLENGE_B64 = 'dGVzdC1jaGFsbGVuZ2U'; // base64url for "test-challenge"

function makeCreationOptions() {
  return {
    challenge: CHALLENGE_B64,
    rp: { name: 'Test RP', id: 'localhost' },
    user: { id: 'dXNlcklk', name: 'user@example.com', displayName: 'User' },
    pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
    excludeCredentials: [],
    timeout: 60000,
  };
}

function makeRequestOptions() {
  return {
    challenge: CHALLENGE_B64,
    allowCredentials: [],
    timeout: 60000,
    rpId: 'localhost',
  };
}

// A minimal PublicKeyCredential stub for registration.
function makeAttestationCredential(): PublicKeyCredential {
  const buf = new Uint8Array([1, 2, 3, 4]).buffer;
  return {
    id: 'cred-id',
    rawId: buf,
    type: 'public-key',
    response: {
      attestationObject: buf,
      clientDataJSON: buf,
      // AuthenticatorAttestationResponse shape
    },
    getClientExtensionResults: vi.fn().mockReturnValue({}),
    authenticatorAttachment: null,
  } as unknown as PublicKeyCredential;
}

// A minimal PublicKeyCredential stub for authentication.
function makeAssertionCredential(): PublicKeyCredential {
  const buf = new Uint8Array([5, 6, 7, 8]).buffer;
  return {
    id: 'cred-id',
    rawId: buf,
    type: 'public-key',
    response: {
      authenticatorData: buf,
      clientDataJSON: buf,
      signature: buf,
      userHandle: null,
    } as unknown as AuthenticatorAssertionResponse,
    getClientExtensionResults: vi.fn().mockReturnValue({}),
    authenticatorAttachment: null,
  } as unknown as PublicKeyCredential;
}

// ---------------------------------------------------------------------------
// Setup
// ---------------------------------------------------------------------------

beforeEach(() => {
  vi.stubGlobal('navigator', {
    credentials: {
      create: vi.fn(),
      get: vi.fn(),
    },
  });
});

afterEach(() => {
  vi.restoreAllMocks();
});

// ---------------------------------------------------------------------------
// register
// ---------------------------------------------------------------------------

describe('useFIDO2 – register', () => {
  it('calls beginFn, creates credential, then calls finishFn', async () => {
    const credential = makeAttestationCredential();
    const beginFn = vi.fn().mockResolvedValue(makeCreationOptions());
    const finishFn = vi.fn().mockResolvedValue(undefined);
    vi.mocked(navigator.credentials.create).mockResolvedValue(credential);

    const { result } = renderHook(() => useFIDO2());

    await act(async () => {
      await result.current.register(beginFn, finishFn);
    });

    expect(beginFn).toHaveBeenCalledOnce();
    expect(navigator.credentials.create).toHaveBeenCalledOnce();
    expect(finishFn).toHaveBeenCalledOnce();
    expect(typeof finishFn.mock.calls[0][0]).toBe('string');
  });

  it('sets loading to true during the ceremony and false after', async () => {
    const credential = makeAttestationCredential();
    let resolveBegin!: (v: any) => void;
    const beginFn = vi.fn().mockReturnValue(new Promise((res) => { resolveBegin = res; }));
    const finishFn = vi.fn().mockResolvedValue(undefined);
    vi.mocked(navigator.credentials.create).mockResolvedValue(credential);

    const { result } = renderHook(() => useFIDO2());

    let registerPromise!: Promise<void>;
    act(() => {
      registerPromise = result.current.register(beginFn, finishFn);
    });

    // loading should be true while beginFn hasn't resolved yet.
    expect(result.current.loading).toBe(true);

    await act(async () => {
      resolveBegin(makeCreationOptions());
      await registerPromise;
    });

    expect(result.current.loading).toBe(false);
  });

  it('sets error and rethrows on beginFn failure', async () => {
    const beginFn = vi.fn().mockRejectedValue(new Error('Server unavailable'));
    const finishFn = vi.fn();

    const { result } = renderHook(() => useFIDO2());

    await act(async () => {
      await expect(result.current.register(beginFn, finishFn)).rejects.toThrow('Server unavailable');
    });

    expect(result.current.error).toContain('Server unavailable');
    expect(result.current.loading).toBe(false);
  });

  it('sets error when navigator.credentials.create rejects', async () => {
    const beginFn = vi.fn().mockResolvedValue(makeCreationOptions());
    const finishFn = vi.fn();
    vi.mocked(navigator.credentials.create).mockRejectedValue(
      new DOMException('User cancelled', 'NotAllowedError'),
    );

    const { result } = renderHook(() => useFIDO2());

    await act(async () => {
      await expect(result.current.register(beginFn, finishFn)).rejects.toThrow();
    });

    expect(result.current.error).toBeTruthy();
    expect(finishFn).not.toHaveBeenCalled();
  });
});

// ---------------------------------------------------------------------------
// authenticate
// ---------------------------------------------------------------------------

describe('useFIDO2 – authenticate', () => {
  it('calls beginFn, gets credential, then calls finishFn', async () => {
    const credential = makeAssertionCredential();
    const beginFn = vi.fn().mockResolvedValue(makeRequestOptions());
    const finishFn = vi.fn().mockResolvedValue(undefined);
    vi.mocked(navigator.credentials.get).mockResolvedValue(credential);

    const { result } = renderHook(() => useFIDO2());

    await act(async () => {
      await result.current.authenticate(beginFn, finishFn);
    });

    expect(beginFn).toHaveBeenCalledOnce();
    expect(navigator.credentials.get).toHaveBeenCalledOnce();
    expect(finishFn).toHaveBeenCalledOnce();
    expect(typeof finishFn.mock.calls[0][0]).toBe('string');
  });

  it('sets error when beginFn rejects', async () => {
    const beginFn = vi.fn().mockRejectedValue(new Error('Challenge fetch failed'));
    const finishFn = vi.fn();

    const { result } = renderHook(() => useFIDO2());

    await act(async () => {
      await expect(result.current.authenticate(beginFn, finishFn)).rejects.toThrow();
    });

    expect(result.current.error).toContain('Challenge fetch failed');
    expect(result.current.loading).toBe(false);
  });

  it('sets error when navigator.credentials.get rejects', async () => {
    const beginFn = vi.fn().mockResolvedValue(makeRequestOptions());
    const finishFn = vi.fn();
    vi.mocked(navigator.credentials.get).mockRejectedValue(
      new DOMException('User cancelled', 'NotAllowedError'),
    );

    const { result } = renderHook(() => useFIDO2());

    await act(async () => {
      await expect(result.current.authenticate(beginFn, finishFn)).rejects.toThrow();
    });

    expect(result.current.error).toBeTruthy();
    expect(finishFn).not.toHaveBeenCalled();
  });
});
