import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { WebAdapter } from './WebAdapter';
import type { Message, Conversation, Account, VerificationSession } from './ISignalClient';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeResponse(body: unknown, ok = true, contentType = 'application/json'): Response {
  return {
    ok,
    status: ok ? 200 : 400,
    text: vi.fn().mockResolvedValue('error body'),
    json: vi.fn().mockResolvedValue(body),
    headers: { get: (key: string) => (key === 'content-type' ? contentType : null) },
  } as unknown as Response;
}

// ---------------------------------------------------------------------------
// Setup
// ---------------------------------------------------------------------------

let adapter: WebAdapter;

beforeEach(() => {
  adapter = new WebAdapter('http://localhost:8080');
  vi.stubGlobal('fetch', vi.fn());
  vi.stubGlobal('WebSocket', vi.fn().mockImplementation(() => ({
    onopen: null,
    onclose: null,
    onerror: null,
    onmessage: null,
    close: vi.fn(),
    send: vi.fn(),
    readyState: 1,
  })));
});

afterEach(() => {
  adapter.destroy();
  vi.restoreAllMocks();
  vi.useRealTimers();
});

// ---------------------------------------------------------------------------
// isRegistered
// ---------------------------------------------------------------------------

describe('WebAdapter – isRegistered', () => {
  it('returns true when the API responds with true', async () => {
    vi.mocked(fetch).mockResolvedValueOnce(makeResponse(true));
    expect(await adapter.isRegistered()).toBe(true);
  });

  it('returns false when the API responds with false', async () => {
    vi.mocked(fetch).mockResolvedValueOnce(makeResponse(false));
    expect(await adapter.isRegistered()).toBe(false);
  });

  it('returns false on network error', async () => {
    vi.mocked(fetch).mockRejectedValueOnce(new Error('Network failure'));
    expect(await adapter.isRegistered()).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// createVerificationSession
// ---------------------------------------------------------------------------

describe('WebAdapter – createVerificationSession', () => {
  it('sends POST with the phone number', async () => {
    const session: VerificationSession = { id: 'sess-1' };
    vi.mocked(fetch).mockResolvedValueOnce(makeResponse(session));

    const result = await adapter.createVerificationSession('+15551234567');

    expect(result).toEqual(session);
    expect(vi.mocked(fetch)).toHaveBeenCalledWith(
      'http://localhost:8080/api/v1/account/verify/session',
      expect.objectContaining({
        method: 'POST',
        body: JSON.stringify({ number: '+15551234567' }),
      }),
    );
  });
});

// ---------------------------------------------------------------------------
// register
// ---------------------------------------------------------------------------

describe('WebAdapter – register', () => {
  it('sends POST and returns an Account', async () => {
    const account: Account = { number: '+15551234567', uuid: 'uuid-1', deviceId: 1 };
    vi.mocked(fetch).mockResolvedValueOnce(makeResponse(account));

    const result = await adapter.register('+15551234567', 'sess-1');

    expect(result).toEqual(account);
    expect(vi.mocked(fetch)).toHaveBeenCalledWith(
      'http://localhost:8080/api/v1/account/register',
      expect.objectContaining({
        method: 'POST',
        body: JSON.stringify({ number: '+15551234567', sessionId: 'sess-1' }),
      }),
    );
  });
});

// ---------------------------------------------------------------------------
// sendMessage
// ---------------------------------------------------------------------------

describe('WebAdapter – sendMessage', () => {
  it('sends POST with recipient and text', async () => {
    vi.mocked(fetch).mockResolvedValueOnce(makeResponse({ timestamp: 1000, needsSync: false }));

    const result = await adapter.sendMessage('recipient-uuid', 'Hello');

    expect(result).toEqual({ timestamp: 1000, needsSync: false });
    expect(vi.mocked(fetch)).toHaveBeenCalledWith(
      'http://localhost:8080/api/v1/messages/send',
      expect.objectContaining({
        method: 'POST',
        body: JSON.stringify({ recipient: 'recipient-uuid', text: 'Hello' }),
      }),
    );
  });
});

// ---------------------------------------------------------------------------
// getConversations
// ---------------------------------------------------------------------------

describe('WebAdapter – getConversations', () => {
  it('returns an array of conversations', async () => {
    const convs: Conversation[] = [
      {
        id: 1,
        conversationId: 'c1',
        type: 0,
        name: 'Alice',
        unreadCount: 0,
        lastMessageTimestamp: 1000,
        lastMessageBody: 'Hi',
        isPinned: false,
        isArchived: false,
      },
    ];
    vi.mocked(fetch).mockResolvedValueOnce(makeResponse(convs));

    const result = await adapter.getConversations();

    expect(result).toEqual(convs);
    expect(vi.mocked(fetch)).toHaveBeenCalledWith(
      'http://localhost:8080/api/v1/conversations',
      expect.anything(),
    );
  });
});

// ---------------------------------------------------------------------------
// getMessages
// ---------------------------------------------------------------------------

describe('WebAdapter – getMessages', () => {
  it('passes conversationId and limit as query params', async () => {
    vi.mocked(fetch).mockResolvedValueOnce(makeResponse([]));

    await adapter.getMessages('conv-1', 50);

    const url = vi.mocked(fetch).mock.calls[0][0] as string;
    expect(url).toContain('conversationId=conv-1');
    expect(url).toContain('limit=50');
  });

  it('includes the before param when provided', async () => {
    vi.mocked(fetch).mockResolvedValueOnce(makeResponse([]));

    await adapter.getMessages('conv-1', 20, 9999);

    const url = vi.mocked(fetch).mock.calls[0][0] as string;
    expect(url).toContain('before=9999');
  });
});

// ---------------------------------------------------------------------------
// getTurnCredentials
// ---------------------------------------------------------------------------

describe('WebAdapter – getTurnCredentials', () => {
  it('calls /v2/calling/relays', async () => {
    const creds = { relays: [] };
    vi.mocked(fetch).mockResolvedValueOnce(makeResponse(creds));

    const result = await adapter.getTurnCredentials();

    expect(result).toEqual(creds);
    expect(vi.mocked(fetch)).toHaveBeenCalledWith(
      'http://localhost:8080/v2/calling/relays',
      expect.anything(),
    );
  });
});

// ---------------------------------------------------------------------------
// sendCallSignal
// ---------------------------------------------------------------------------

describe('WebAdapter – sendCallSignal', () => {
  const base = { callId: 'call-1', calleeUuid: 'callee', callType: 'video', payload: {} };

  const noContentResponse = (): Response => ({
    ok: true,
    status: 204,
    text: vi.fn().mockResolvedValue(''),
    headers: { get: () => null },
  } as unknown as Response);

  it('routes offer to /api/v1/call/offer', async () => {
    vi.mocked(fetch).mockResolvedValueOnce(noContentResponse());
    await adapter.sendCallSignal({ type: 'offer', ...base });
    const url = vi.mocked(fetch).mock.calls[0][0] as string;
    expect(url).toContain('/api/v1/call/offer');
  });

  it('routes answer to /api/v1/call/answer', async () => {
    vi.mocked(fetch).mockResolvedValueOnce(noContentResponse());
    await adapter.sendCallSignal({ type: 'answer', ...base });
    const url = vi.mocked(fetch).mock.calls[0][0] as string;
    expect(url).toContain('/api/v1/call/answer');
  });

  it('routes ice to /api/v1/call/ice', async () => {
    vi.mocked(fetch).mockResolvedValueOnce(noContentResponse());
    await adapter.sendCallSignal({ type: 'ice', ...base });
    const url = vi.mocked(fetch).mock.calls[0][0] as string;
    expect(url).toContain('/api/v1/call/ice');
  });

  it('routes hangup to /api/v1/call/hangup', async () => {
    vi.mocked(fetch).mockResolvedValueOnce(noContentResponse());
    await adapter.sendCallSignal({ type: 'hangup', ...base });
    const url = vi.mocked(fetch).mock.calls[0][0] as string;
    expect(url).toContain('/api/v1/call/hangup');
  });

  it('throws on unknown signal type', async () => {
    await expect(adapter.sendCallSignal({ type: 'unknown', ...base })).rejects.toThrow(
      'Unknown call signal type: unknown',
    );
  });
});

// ---------------------------------------------------------------------------
// fetch helpers – content-type validation and non-OK responses
// ---------------------------------------------------------------------------

describe('WebAdapter – internal fetch', () => {
  it('throws when response Content-Type is not JSON', async () => {
    vi.mocked(fetch).mockResolvedValueOnce(makeResponse('plain text', true, 'text/plain'));
    await expect(adapter.getConversations()).rejects.toThrow('Expected JSON response');
  });

  it('throws on non-OK HTTP response', async () => {
    vi.mocked(fetch).mockResolvedValueOnce(makeResponse('Bad Request', false, 'text/plain'));
    await expect(adapter.getConversations()).rejects.toThrow('HTTP 400');
  });
});

// ---------------------------------------------------------------------------
// onMessage / onConnectionStatus – handler subscription
// ---------------------------------------------------------------------------

describe('WebAdapter – event subscriptions', () => {
  it('onMessage returns an unsubscribe function that removes the handler', () => {
    const handler = vi.fn();
    const unsub = adapter.onMessage(handler);
    unsub();
    // After unsubscribing, destroy should not throw.
    expect(() => adapter.destroy()).not.toThrow();
  });

  it('onConnectionStatus returns an unsubscribe function', () => {
    const handler = vi.fn();
    const unsub = adapter.onConnectionStatus(handler);
    expect(typeof unsub).toBe('function');
    unsub();
  });
});

// ---------------------------------------------------------------------------
// destroy
// ---------------------------------------------------------------------------

describe('WebAdapter – destroy', () => {
  it('closes the WebSocket and clears all handler sets', () => {
    const mockWs = { close: vi.fn(), onopen: null, onclose: null, onerror: null, onmessage: null };
    vi.mocked(WebSocket).mockReturnValueOnce(mockWs as unknown as WebSocket);

    // Trigger WebSocket creation via subscription.
    adapter.onMessage(vi.fn());
    adapter.destroy();

    expect(mockWs.close).toHaveBeenCalled();
  });
});

// ---------------------------------------------------------------------------
// WebSocket reconnect on close
// ---------------------------------------------------------------------------

describe('WebAdapter – WebSocket reconnect', () => {
  it('schedules reconnect after close with 5 s delay', () => {
    vi.useFakeTimers();

    let storedOnClose: (() => void) | null = null;
    let callCount = 0;

    vi.mocked(WebSocket).mockImplementation(() => {
      callCount++;
      const ws = {
        close: vi.fn(),
        onopen: null as any,
        onclose: null as any,
        onerror: null as any,
        onmessage: null as any,
        set onclose(fn: any) { storedOnClose = fn; },
        get onclose() { return storedOnClose; },
      };
      return ws as unknown as WebSocket;
    });

    adapter.onMessage(vi.fn());
    expect(callCount).toBe(1);

    // Simulate close.
    storedOnClose?.();

    // Not reconnected yet.
    expect(callCount).toBe(1);

    vi.advanceTimersByTime(5000);
    expect(callCount).toBe(2);
  });
});
