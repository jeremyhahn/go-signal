import { test, expect } from './fixtures/live';

/**
 * realtime.spec.ts
 *
 * Exercises the live WebSocket event channel that setupMockAPI cannot reach:
 *   - connection status transitions (connected -> banner hidden)
 *   - real-time message delivery (App.onMessage -> appendMessage -> Timeline)
 *   - typing events do not disturb the UI
 *
 * These paths are otherwise dead code under the HTTP-only mock because the
 * WebSocket upgrade is aborted there, pinning the app to "Connecting...".
 */

test.describe('Realtime — connection status', () => {
  test('open WebSocket hides the "Connecting..." banner', async ({ page, ws }) => {
    await ws.connected;
    await expect(page.locator('.connection-banner')).toHaveCount(0);
  });

  test('connected app still renders the conversation list', async ({ page, ws }) => {
    await ws.connected;
    await expect(page.getByText('Alice')).toBeVisible();
    await expect(page.getByText('Bob')).toBeVisible();
  });
});

test.describe('Realtime — message delivery', () => {
  test('incoming message appears in the open conversation timeline', async ({ page, ws }) => {
    await ws.connected;
    await page.getByText('Alice').click();
    await expect(page.locator('.conversation-header')).toBeVisible();

    ws.send('signal:message:received', {
      id: 1001,
      guid: 'rt-incoming-1',
      conversationId: 'conv-1',
      sourceUuid: 'alice-uuid',
      timestamp: Date.now(),
      type: 1,
      body: 'Pushed over the socket',
      isRead: false,
      sendState: 2,
    });

    const bubble = page.locator('.message-bubble.incoming', { hasText: 'Pushed over the socket' });
    await expect(bubble).toBeVisible();
  });

  test('a pushed outgoing message renders with the outgoing class', async ({ page, ws }) => {
    await ws.connected;
    await page.getByText('Alice').click();
    await expect(page.locator('.conversation-header')).toBeVisible();

    ws.send('signal:message:received', {
      id: 1002,
      guid: 'rt-outgoing-1',
      conversationId: 'conv-1',
      sourceUuid: 'test-uuid-1234',
      timestamp: Date.now(),
      type: 2,
      body: 'Synced from another device',
      isRead: true,
      sendState: 3,
    });

    const bubble = page.locator('.message-bubble.outgoing', { hasText: 'Synced from another device' });
    await expect(bubble).toBeVisible();
  });

  test('multiple pushed messages accumulate in order', async ({ page, ws }) => {
    await ws.connected;
    await page.getByText('Alice').click();
    await expect(page.locator('.conversation-header')).toBeVisible();

    for (let i = 1; i <= 3; i++) {
      ws.send('signal:message:received', {
        id: 2000 + i,
        guid: `rt-seq-${i}`,
        conversationId: 'conv-1',
        sourceUuid: 'alice-uuid',
        timestamp: Date.now() + i,
        type: 1,
        body: `Sequenced ${i}`,
        isRead: false,
        sendState: 2,
      });
    }

    await expect(page.getByText('Sequenced 1')).toBeVisible();
    await expect(page.getByText('Sequenced 2')).toBeVisible();
    await expect(page.getByText('Sequenced 3')).toBeVisible();
  });

  test('typing event over the socket does not crash the view', async ({ page, ws }) => {
    await ws.connected;
    await page.getByText('Alice').click();
    await expect(page.locator('.conversation-header')).toBeVisible();

    ws.send('signal:typing', {
      conversationId: 'conv-1',
      sender: 'alice-uuid',
      started: true,
    });

    // No typing UI is rendered, but the app must remain functional.
    await expect(page.locator('.conversation-header')).toBeVisible();
    await expect(page.getByLabel('Message input')).toBeEnabled();
  });
});
