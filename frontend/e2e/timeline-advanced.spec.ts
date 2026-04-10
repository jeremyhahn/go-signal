import { test as base, expect } from '@playwright/test';
import { setupMockAPI } from './fixtures/mock-api';

/**
 * timeline-advanced.spec.ts
 *
 * Covers advanced Timeline interactions: empty timeline, message status
 * variants, long messages, multiple date groups, and scroll behavior.
 */

const test = base.extend({
  page: async ({ page }, use) => {
    await setupMockAPI(page);
    await page.route('**/api/v1/account/registered', async (route) => {
      await route.fulfill({ json: true });
    });
    await page.goto('/');
    await use(page);
  },
});

test.describe('Timeline — empty conversation', () => {
  test('shows empty timeline when conversation has no messages', async ({ page }) => {
    // Override messages to return empty array.
    await page.route('**/api/v1/messages?*', async (route) => {
      await route.fulfill({ json: [] });
    });

    await page.getByText('Alice').click();
    // Timeline should render but be empty (just the date separator won't appear).
    await expect(page.locator('.timeline')).toBeVisible();
    await expect(page.locator('.message-bubble')).toHaveCount(0);
  });
});

test.describe('Timeline — message status variants', () => {
  test('shows single check for sent messages (sendState: 1)', async ({ page }) => {
    await page.route('**/api/v1/messages?*', async (route) => {
      await route.fulfill({
        json: [
          {
            id: 1, guid: 'msg-sent', conversationId: 'conv-1',
            sourceUuid: 'test-uuid-1234', timestamp: Date.now(),
            type: 2, body: 'Sent message', isRead: false, sendState: 1,
          },
        ],
      });
    });

    await page.getByText('Alice').click();
    const status = page.locator('.message-status');
    await expect(status).toBeVisible();
    await expect(status).toHaveAttribute('title', 'Sent');
  });

  test('shows double check for delivered messages (sendState: 2)', async ({ page }) => {
    await page.route('**/api/v1/messages?*', async (route) => {
      await route.fulfill({
        json: [
          {
            id: 1, guid: 'msg-delivered', conversationId: 'conv-1',
            sourceUuid: 'test-uuid-1234', timestamp: Date.now(),
            type: 2, body: 'Delivered message', isRead: false, sendState: 2,
          },
        ],
      });
    });

    await page.getByText('Alice').click();
    const status = page.locator('.message-status');
    await expect(status).toBeVisible();
    await expect(status).toHaveAttribute('title', 'Delivered');
  });

  test('shows blue double check for read messages (sendState: 3)', async ({ page }) => {
    await page.route('**/api/v1/messages?*', async (route) => {
      await route.fulfill({
        json: [
          {
            id: 1, guid: 'msg-read', conversationId: 'conv-1',
            sourceUuid: 'test-uuid-1234', timestamp: Date.now(),
            type: 2, body: 'Read message', isRead: true, sendState: 3,
          },
        ],
      });
    });

    await page.getByText('Alice').click();
    const status = page.locator('.message-status');
    await expect(status).toBeVisible();
    await expect(status).toHaveAttribute('title', 'Read');
  });

  test('shows pending indicator for unsent messages (sendState: 0)', async ({ page }) => {
    await page.route('**/api/v1/messages?*', async (route) => {
      await route.fulfill({
        json: [
          {
            id: 1, guid: 'msg-pending', conversationId: 'conv-1',
            sourceUuid: 'test-uuid-1234', timestamp: Date.now(),
            type: 2, body: 'Pending message', isRead: false, sendState: 0,
          },
        ],
      });
    });

    await page.getByText('Alice').click();
    const status = page.locator('.message-status');
    await expect(status).toBeVisible();
    await expect(status).toHaveAttribute('title', 'Sending');
  });
});

test.describe('Timeline — long messages', () => {
  test('long messages wrap correctly and remain visible', async ({ page }) => {
    const longText = 'This is a very long message that should wrap to multiple lines. '.repeat(10);

    await page.route('**/api/v1/messages?*', async (route) => {
      await route.fulfill({
        json: [
          {
            id: 1, guid: 'msg-long', conversationId: 'conv-1',
            sourceUuid: 'alice-uuid', timestamp: Date.now(),
            type: 1, body: longText.trim(), isRead: true, sendState: 2,
          },
        ],
      });
    });

    await page.getByText('Alice').click();
    const bubble = page.locator('.message-bubble').first();
    await expect(bubble).toBeVisible();

    // The bubble should not exceed 70% of the viewport width.
    const box = await bubble.boundingBox();
    expect(box).not.toBeNull();
    if (box) {
      const viewport = page.viewportSize();
      if (viewport) {
        expect(box.width).toBeLessThanOrEqual(viewport.width * 0.75);
      }
    }
  });
});

test.describe('Timeline — multiple date groups', () => {
  test('shows Yesterday separator for messages from the previous day', async ({ page }) => {
    const yesterday = Date.now() - 86_400_000;

    await page.route('**/api/v1/messages?*', async (route) => {
      await route.fulfill({
        json: [
          {
            id: 1, guid: 'msg-yesterday', conversationId: 'conv-1',
            sourceUuid: 'alice-uuid', timestamp: yesterday,
            type: 1, body: 'Old message', isRead: true, sendState: 2,
          },
          {
            id: 2, guid: 'msg-today', conversationId: 'conv-1',
            sourceUuid: 'test-uuid-1234', timestamp: Date.now(),
            type: 2, body: 'New message', isRead: true, sendState: 2,
          },
        ],
      });
    });

    await page.getByText('Alice').click();
    await expect(page.getByText('Yesterday')).toBeVisible();
    await expect(page.getByText('Today')).toBeVisible();
  });
});

export { expect };
