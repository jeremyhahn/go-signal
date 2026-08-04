import { test, expect } from './fixtures/live';
import type { WSController } from './fixtures/live';
import type { Page } from '@playwright/test';

/**
 * call-connected.spec.ts
 *
 * Drives an outgoing call all the way to the connected state by feeding the
 * answer signal over the mock WebSocket. This exercises:
 *   - CallScreen "connecting" -> "connected" status + duration timer
 *   - CallControls inside an active call (audio + video toggles, hangup)
 *   - remote hangup via signal:call:ended -> teardown
 *
 * The HTTP-only mock can never reach these states because the answer signal
 * is delivered over the (aborted) WebSocket.
 */

async function startOutgoingCall(page: Page, ws: WSController, type: 'audio' | 'video') {
  await ws.connected;
  await page.getByText('Alice').click();
  await expect(page.locator('.conversation-header')).toBeVisible();

  const testId = type === 'video' ? 'call-video-button' : 'call-audio-button';
  await page.getByTestId(testId).click();

  await expect(page.getByTestId('lobby-start-call')).toBeEnabled({ timeout: 5000 });
  await page.getByTestId('lobby-start-call').click();

  await expect(page.getByTestId('call-screen')).toBeVisible({ timeout: 5000 });
  await expect(page.getByTestId('call-status')).toContainText('Ringing');
}

function deliverAnswer(ws: WSController) {
  ws.send('signal:call:signal', {
    type: 'answer',
    callId: 'ignored-by-mock',
    payload: { type: 'answer', sdp: 'mock-sdp-answer' },
  });
}

test.describe('CallScreen — connected lifecycle (audio)', () => {
  test('answer signal transitions the call to a running timer', async ({ page, ws }) => {
    await startOutgoingCall(page, ws, 'audio');
    deliverAnswer(ws);

    await expect(page.getByTestId('call-status')).toHaveText(/\d{2}:\d{2}/, { timeout: 5000 });
  });

  test('connected call shows the peer name', async ({ page, ws }) => {
    await startOutgoingCall(page, ws, 'audio');
    deliverAnswer(ws);
    await expect(page.getByTestId('call-status')).toHaveText(/\d{2}:\d{2}/, { timeout: 5000 });
    await expect(page.locator('.calling-screen__name')).toHaveText('Alice');
  });

  test('audio-only connected call renders the avatar (no remote video)', async ({ page, ws }) => {
    await startOutgoingCall(page, ws, 'audio');
    deliverAnswer(ws);
    await expect(page.getByTestId('call-status')).toHaveText(/\d{2}:\d{2}/, { timeout: 5000 });
    await expect(page.locator('.calling-screen__avatar-circle')).toBeVisible();
    await expect(page.getByTestId('call-remote-video')).toHaveCount(0);
  });

  test('duration timer advances past zero', async ({ page, ws }) => {
    await startOutgoingCall(page, ws, 'audio');
    deliverAnswer(ws);
    await expect(page.getByTestId('call-status')).toHaveText(/\d{2}:\d{2}/, { timeout: 5000 });
    // After a couple of seconds the formatted timer must read past 00:00.
    await expect(page.getByTestId('call-status')).not.toHaveText('00:00', { timeout: 4000 });
  });
});

test.describe('CallControls — inside an active call', () => {
  test('hangup button is present and ends the call', async ({ page, ws }) => {
    await startOutgoingCall(page, ws, 'audio');
    deliverAnswer(ws);
    await expect(page.getByTestId('call-hangup')).toBeVisible();

    await page.getByTestId('call-hangup').click();
    await expect(page.getByTestId('call-screen')).not.toBeVisible({ timeout: 5000 });
  });

  test('audio mute toggle flips its accessible label', async ({ page, ws }) => {
    await startOutgoingCall(page, ws, 'audio');
    deliverAnswer(ws);
    const toggle = page.getByTestId('call-toggle-audio');
    await expect(toggle).toHaveAttribute('aria-label', 'Mute microphone');
    await toggle.click();
    await expect(toggle).toHaveAttribute('aria-label', 'Unmute microphone');
    await toggle.click();
    await expect(toggle).toHaveAttribute('aria-label', 'Mute microphone');
  });

  test('audio-only call hides the video toggle control', async ({ page, ws }) => {
    await startOutgoingCall(page, ws, 'audio');
    deliverAnswer(ws);
    await expect(page.getByTestId('call-toggle-video')).toHaveCount(0);
  });
});

test.describe('CallScreen — connected lifecycle (video)', () => {
  test('video call shows the local PiP video and a working video toggle', async ({ page, ws }) => {
    await startOutgoingCall(page, ws, 'video');
    deliverAnswer(ws);
    await expect(page.getByTestId('call-status')).toHaveText(/\d{2}:\d{2}/, { timeout: 5000 });

    await expect(page.getByTestId('call-local-video')).toBeVisible();

    const videoToggle = page.getByTestId('call-toggle-video');
    await expect(videoToggle).toHaveAttribute('aria-label', 'Turn off camera');
    await videoToggle.click();
    await expect(videoToggle).toHaveAttribute('aria-label', 'Turn on camera');
  });
});

test.describe('CallScreen — remote hangup', () => {
  test('signal:call:ended tears down the active call screen', async ({ page, ws }) => {
    await startOutgoingCall(page, ws, 'audio');
    deliverAnswer(ws);
    await expect(page.getByTestId('call-status')).toHaveText(/\d{2}:\d{2}/, { timeout: 5000 });

    ws.send('signal:call:ended', { callId: 'ignored', reason: 'remote-hangup' });

    await expect(page.getByTestId('call-screen')).not.toBeVisible({ timeout: 5000 });
  });

  test('after remote hangup the conversation call buttons return', async ({ page, ws }) => {
    await startOutgoingCall(page, ws, 'audio');
    deliverAnswer(ws);
    await expect(page.getByTestId('call-status')).toHaveText(/\d{2}:\d{2}/, { timeout: 5000 });

    ws.send('signal:call:ended', { callId: 'ignored', reason: 'remote-hangup' });
    await expect(page.getByTestId('call-screen')).not.toBeVisible({ timeout: 5000 });
    await expect(page.getByTestId('call-audio-button')).toBeVisible();
  });
});
