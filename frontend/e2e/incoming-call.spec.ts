import { test, expect } from './fixtures/live';
import type { WSController } from './fixtures/live';
import type { Page } from '@playwright/test';

/**
 * incoming-call.spec.ts
 *
 * Exercises IncomingCallBar and the inbound call path in useCallManager,
 * driven by signal:call:incoming events over the mock WebSocket. None of
 * this is reachable with the HTTP-only mock (the WS is aborted there).
 */

function audioOffer() {
  return { type: 'offer' as const, sdp: 'mock-sdp-offer' };
}

async function pushIncoming(
  ws: WSController,
  overrides: Record<string, unknown> = {},
) {
  await ws.connected;
  ws.send('signal:call:incoming', {
    callId: 'incoming-call-1',
    callerUuid: 'conv-1',
    callType: 'audio',
    offer: audioOffer(),
    ...overrides,
  });
}

async function openInbox(page: Page, ws: WSController) {
  await ws.connected;
  await expect(page.getByText('Alice')).toBeVisible();
}

test.describe('IncomingCallBar — appearance', () => {
  test('incoming audio call shows the incoming call bar', async ({ page, ws }) => {
    await openInbox(page, ws);
    await pushIncoming(ws);
    await expect(page.getByTestId('incoming-call-bar')).toBeVisible();
  });

  test('incoming call bar has role="alert"', async ({ page, ws }) => {
    await openInbox(page, ws);
    await pushIncoming(ws);
    await expect(page.getByTestId('incoming-call-bar')).toHaveAttribute('role', 'alert');
  });

  test('audio call bar shows the "Audio call" label', async ({ page, ws }) => {
    await openInbox(page, ws);
    await pushIncoming(ws);
    await expect(page.getByTestId('incoming-call-bar')).toContainText('Audio call');
  });

  test('video call bar shows the "Video call" label', async ({ page, ws }) => {
    await openInbox(page, ws);
    await pushIncoming(ws, { callType: 'video' });
    await expect(page.getByTestId('incoming-call-bar')).toContainText('Video call');
  });

  test('exposes Accept and Decline buttons', async ({ page, ws }) => {
    await openInbox(page, ws);
    await pushIncoming(ws);
    await expect(page.getByTestId('call-accept')).toBeVisible();
    await expect(page.getByTestId('call-decline')).toBeVisible();
  });
});

test.describe('IncomingCallBar — caller name resolution', () => {
  test('resolves caller name from the conversation list by uuid', async ({ page, ws }) => {
    await openInbox(page, ws);
    // callerUuid conv-1 matches the Alice conversation; no explicit callerName.
    await pushIncoming(ws, { callerUuid: 'conv-1' });
    await expect(page.getByTestId('incoming-call-bar')).toContainText('Alice');
  });

  test('explicit callerName takes precedence over the conversation name', async ({ page, ws }) => {
    await openInbox(page, ws);
    await pushIncoming(ws, { callerUuid: 'conv-1', callerName: 'Override Name' });
    await expect(page.getByTestId('incoming-call-bar')).toContainText('Override Name');
  });

  test('falls back to the raw uuid for unknown callers', async ({ page, ws }) => {
    await openInbox(page, ws);
    await pushIncoming(ws, { callerUuid: 'unknown-caller-xyz' });
    await expect(page.getByTestId('incoming-call-bar')).toContainText('unknown-caller-xyz');
  });
});

test.describe('IncomingCallBar — decline', () => {
  test('declining hides the incoming call bar', async ({ page, ws }) => {
    await openInbox(page, ws);
    await pushIncoming(ws);
    await page.getByTestId('call-decline').click();
    await expect(page.getByTestId('incoming-call-bar')).not.toBeVisible();
  });

  test('declining posts a hangup signal to the server', async ({ page, ws }) => {
    await openInbox(page, ws);

    const hangup = page.waitForRequest('**/api/v1/call/hangup');
    await pushIncoming(ws);
    await page.getByTestId('call-decline').click();

    const req = await hangup;
    expect(req.method()).toBe('POST');
  });
});

test.describe('IncomingCallBar — accept', () => {
  test('accepting hides the bar and opens the call screen', async ({ page, ws }) => {
    await openInbox(page, ws);
    await pushIncoming(ws);

    await page.getByTestId('call-accept').click();

    await expect(page.getByTestId('incoming-call-bar')).not.toBeVisible();
    await expect(page.getByTestId('call-screen')).toBeVisible({ timeout: 5000 });
  });

  test('accepting an audio call reaches the connected state', async ({ page, ws }) => {
    await openInbox(page, ws);
    await pushIncoming(ws);
    await page.getByTestId('call-accept').click();

    // The mock RTCPeerConnection flips to "connected" shortly after the
    // answer's remote description is applied; the status then shows a timer.
    await expect(page.getByTestId('call-status')).toHaveText(/\d{2}:\d{2}/, { timeout: 5000 });
  });
});

test.describe('IncomingCallBar — busy handling', () => {
  test('a second incoming call is ignored while a call is active', async ({ page, ws }) => {
    await openInbox(page, ws);
    await pushIncoming(ws);
    await page.getByTestId('call-accept').click();
    await expect(page.getByTestId('call-screen')).toBeVisible({ timeout: 5000 });

    // Push a competing incoming call — it must be suppressed (busy).
    ws.send('signal:call:incoming', {
      callId: 'incoming-call-2',
      callerUuid: 'conv-2',
      callType: 'audio',
      offer: audioOffer(),
    });

    await expect(page.getByTestId('incoming-call-bar')).not.toBeVisible();
  });
});
