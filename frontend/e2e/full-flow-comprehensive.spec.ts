import { test, expect, type WebSocketRoute } from '@playwright/test';
import { setupMockAPI } from './fixtures/mock-api';
import { setupMockWebRTC } from './fixtures/mock-webrtc';

/**
 * full-flow-comprehensive.spec.ts
 *
 * A single end-to-end journey that walks the widest possible slice of the UI
 * in one run, with a live mock WebSocket so real-time delivery and a fully
 * connected call are part of the path:
 *
 *   register -> inbox -> open conversation -> send -> receive (live) ->
 *   search -> settings theme change -> responsive resize ->
 *   calling (lobby -> ringing -> connected -> hangup) -> theme back.
 */

test('comprehensive happy-path walkthrough', async ({ page }) => {
  await setupMockWebRTC(page);
  await setupMockAPI(page);

  // Live WebSocket so the connected state + real-time receive are reachable.
  let routeHandle: WebSocketRoute | null = null;
  let resolveConnected!: () => void;
  const wsConnected = new Promise<void>((r) => (resolveConnected = r));
  await page.routeWebSocket('**/api/v1/events', (ws) => {
    routeHandle = ws;
    ws.onMessage(() => {});
    resolveConnected();
  });
  const wsSend = (type: string, payload: unknown) => {
    if (!routeHandle) throw new Error('WS not connected');
    routeHandle.send(JSON.stringify({ type, payload }));
  };

  await page.goto('/');

  // 1. Registration.
  await expect(page.getByRole('heading', { name: 'Register Your Phone' })).toBeVisible();
  await page.getByLabel('Phone Number').fill('+15555550100');
  await page.getByRole('button', { name: 'Request Code' }).click();
  await page.getByPlaceholder('123456').fill('654321');
  await page.getByRole('button', { name: 'Verify' }).click();

  // 2. Inbox loads; the live socket clears the connecting banner.
  await expect(page.getByText('Alice')).toBeVisible({ timeout: 10_000 });
  await wsConnected;
  await expect(page.locator('.connection-banner')).toHaveCount(0);

  // 3. Open a conversation.
  await page.getByText('Alice').click();
  await expect(page.locator('.conversation-header')).toBeVisible();
  await expect(page.locator('.conversation-header')).toContainText('Alice');

  // 4. Send a message.
  const input = page.getByLabel('Message input');
  await input.fill('Hello from the full flow');
  await page.getByRole('button', { name: 'Send message' }).click();
  await expect(input).toHaveValue('');

  // 5. Receive a message in real time.
  wsSend('signal:message:received', {
    id: 5001,
    guid: 'flow-rt-1',
    conversationId: 'conv-1',
    sourceUuid: 'alice-uuid',
    timestamp: Date.now(),
    type: 1,
    body: 'Reply over the socket',
    isRead: false,
    sendState: 2,
  });
  await expect(page.getByText('Reply over the socket')).toBeVisible();

  // 6. Search input accepts a query.
  const search = page.getByPlaceholder('Search conversations');
  await search.fill('Bob');
  await expect(search).toHaveValue('Bob');
  await search.fill('');

  // 7. Settings: switch to dark theme.
  await page.getByRole('button', { name: 'Settings' }).click();
  await page.getByLabel('Theme').selectOption('dark');
  await expect
    .poll(() => page.evaluate(() => document.documentElement.getAttribute('data-theme')))
    .toBe('dark');
  await page.getByRole('button', { name: 'Chats' }).click();

  // 8. Responsive resize — the app must keep rendering across breakpoints.
  // At <=600px the NavTabs icon bar collapses and the left pane goes
  // full-width, so assert the left pane rather than the (hidden) NavTabs.
  await page.setViewportSize({ width: 480, height: 900 });
  await expect(page.locator('.left-pane')).toBeVisible();
  await page.setViewportSize({ width: 1920, height: 1080 });
  await expect(page.locator('.NavTabs')).toBeVisible();
  // A conversation is already active, so "Alice" appears in both the list and
  // the header; scope to the conversation list item to stay unambiguous.
  await expect(page.locator('.conv-name', { hasText: 'Alice' })).toBeVisible();

  // 9. Calling: lobby -> ringing -> connected -> hangup.
  await page.locator('.conversation-item', { hasText: 'Alice' }).click();
  await expect(page.locator('.conversation-header')).toBeVisible();
  await page.getByTestId('call-audio-button').click();
  await expect(page.getByTestId('calling-lobby')).toBeVisible();
  await expect(page.getByTestId('lobby-start-call')).toBeEnabled({ timeout: 5000 });
  await page.getByTestId('lobby-start-call').click();
  await expect(page.getByTestId('call-screen')).toBeVisible({ timeout: 5000 });
  await expect(page.getByTestId('call-status')).toContainText('Ringing');

  wsSend('signal:call:signal', {
    type: 'answer',
    callId: 'flow-call',
    payload: { type: 'answer', sdp: 'mock-sdp-answer' },
  });
  await expect(page.getByTestId('call-status')).toHaveText(/\d{2}:\d{2}/, { timeout: 5000 });

  await page.getByTestId('call-hangup').click();
  await expect(page.getByTestId('call-screen')).not.toBeVisible({ timeout: 5000 });

  // 10. Theme back to light to prove settings remain reachable post-call.
  await page.getByRole('button', { name: 'Settings' }).click();
  await page.getByLabel('Theme').selectOption('light');
  await expect
    .poll(() => page.evaluate(() => document.documentElement.getAttribute('data-theme')))
    .toBe('light');
});
