import { useState, useCallback } from 'react';

// useFIDO2 provides WebAuthn ceremony helpers for the FIDO2 UI.
// The ceremony flow:
//   1. Go backend calls server to get challenge options
//   2. This hook calls navigator.credentials.create/get in the webview
//   3. The response is sent back to Go backend to complete the ceremony

export function useFIDO2() {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const register = useCallback(async (
    beginFn: () => Promise<any>,
    finishFn: (attestation: string) => Promise<void>,
  ) => {
    setLoading(true);
    setError(null);
    try {
      const options = await beginFn();

      // Convert base64url fields to ArrayBuffer for WebAuthn API.
      const publicKey = parseCreationOptions(options);
      const credential = await navigator.credentials.create({ publicKey });
      if (!credential) throw new Error('No credential returned');

      const attestation = serializeCredential(credential as PublicKeyCredential);
      await finishFn(attestation);
    } catch (err) {
      setError(String(err));
      throw err;
    } finally {
      setLoading(false);
    }
  }, []);

  const authenticate = useCallback(async (
    beginFn: () => Promise<any>,
    finishFn: (assertion: string) => Promise<void>,
  ) => {
    setLoading(true);
    setError(null);
    try {
      const options = await beginFn();

      const publicKey = parseRequestOptions(options);
      const credential = await navigator.credentials.get({ publicKey });
      if (!credential) throw new Error('No credential returned');

      const assertion = serializeAssertion(credential as PublicKeyCredential);
      await finishFn(assertion);
    } catch (err) {
      setError(String(err));
      throw err;
    } finally {
      setLoading(false);
    }
  }, []);

  return { register, authenticate, loading, error };
}

// Helpers for base64url <-> ArrayBuffer conversion.

function base64urlToBuffer(base64url: string): ArrayBuffer {
  const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
  const pad = base64.length % 4 === 0 ? '' : '='.repeat(4 - (base64.length % 4));
  const binary = atob(base64 + pad);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

function bufferToBase64url(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function parseCreationOptions(options: any): PublicKeyCredentialCreationOptions {
  return {
    ...options,
    challenge: base64urlToBuffer(options.challenge),
    user: {
      ...options.user,
      id: base64urlToBuffer(options.user.id),
    },
    excludeCredentials: (options.excludeCredentials || []).map((c: any) => ({
      ...c,
      id: base64urlToBuffer(c.id),
    })),
  };
}

function parseRequestOptions(options: any): PublicKeyCredentialRequestOptions {
  return {
    ...options,
    challenge: base64urlToBuffer(options.challenge),
    allowCredentials: (options.allowCredentials || []).map((c: any) => ({
      ...c,
      id: base64urlToBuffer(c.id),
    })),
  };
}

function serializeCredential(credential: PublicKeyCredential): string {
  const response = credential.response as AuthenticatorAttestationResponse;
  return JSON.stringify({
    id: credential.id,
    rawId: bufferToBase64url(credential.rawId),
    type: credential.type,
    response: {
      attestationObject: bufferToBase64url(response.attestationObject),
      clientDataJSON: bufferToBase64url(response.clientDataJSON),
    },
  });
}

function serializeAssertion(credential: PublicKeyCredential): string {
  const response = credential.response as AuthenticatorAssertionResponse;
  return JSON.stringify({
    id: credential.id,
    rawId: bufferToBase64url(credential.rawId),
    type: credential.type,
    response: {
      authenticatorData: bufferToBase64url(response.authenticatorData),
      clientDataJSON: bufferToBase64url(response.clientDataJSON),
      signature: bufferToBase64url(response.signature),
      userHandle: response.userHandle ? bufferToBase64url(response.userHandle) : null,
    },
  });
}
