import { test, expect } from '@playwright/test';
import { setupMockAPI } from './fixtures/mock-api';

/**
 * inbox-edge-cases.spec.ts
 *
 * Covers Inbox edge cases that require custom mock data:
 *   - Empty conversation list
 *   - Conversation without a name (fallback to conversationId)
 *   - Conversation without a lastMessageBody (no preview)
 *   - Conversation timestamp on a previous day (date format vs time)
 */

test.describe('Inbox — empty conversation list', () => {
  test('shows "No conversations yet" when the list is empty', async ({ page }) => {
    await setupMockAPI(page);

    // Override registered to true.
    await page.route('**/api/v1/account/registered', async (route) => {
      await route.fulfill({ json: true });
    });

    // Override conversations to return an empty array.
    await page.route('**/api/v1/conversations', async (route) => {
      await route.fulfill({ json: [] });
    });

    await page.goto('/');

    await expect(page.getByText('No conversations yet')).toBeVisible();
  });
});

test.describe('Inbox — conversation without a name', () => {
  test('falls back to conversationId when name is empty', async ({ page }) => {
    await setupMockAPI(page);

    await page.route('**/api/v1/account/registered', async (route) => {
      await route.fulfill({ json: true });
    });

    await page.route('**/api/v1/conversations', async (route) => {
      await route.fulfill({
        json: [
          {
            id: 1,
            conversationId: 'conv-no-name',
            type: 1,
            name: '',
            unreadCount: 0,
            lastMessageTimestamp: Date.now(),
            lastMessageBody: 'Hello',
            isPinned: false,
            isArchived: false,
          },
        ],
      });
    });

    await page.goto('/');

    // The conversation list item should show the conversationId as the name.
    await expect(page.getByText('conv-no-name')).toBeVisible();
  });

  test('conversation header falls back to conversationId when name is empty', async ({ page }) => {
    await setupMockAPI(page);

    await page.route('**/api/v1/account/registered', async (route) => {
      await route.fulfill({ json: true });
    });

    await page.route('**/api/v1/conversations', async (route) => {
      await route.fulfill({
        json: [
          {
            id: 1,
            conversationId: 'conv-no-name',
            type: 1,
            name: '',
            unreadCount: 0,
            lastMessageTimestamp: Date.now(),
            lastMessageBody: 'Hello',
            isPinned: false,
            isArchived: false,
          },
        ],
      });
    });

    await page.goto('/');
    await page.getByText('conv-no-name').click();

    await expect(
      page.locator('.conversation-header').getByText('conv-no-name'),
    ).toBeVisible();
  });
});

test.describe('Inbox — conversation without lastMessageBody', () => {
  test('does not render a preview when lastMessageBody is empty', async ({ page }) => {
    await setupMockAPI(page);

    await page.route('**/api/v1/account/registered', async (route) => {
      await route.fulfill({ json: true });
    });

    await page.route('**/api/v1/conversations', async (route) => {
      await route.fulfill({
        json: [
          {
            id: 1,
            conversationId: 'conv-1',
            type: 1,
            name: 'Charlie',
            unreadCount: 0,
            lastMessageTimestamp: Date.now(),
            lastMessageBody: '',
            isPinned: false,
            isArchived: false,
          },
        ],
      });
    });

    await page.goto('/');

    await expect(page.getByText('Charlie')).toBeVisible();
    // The conv-preview paragraph should not exist when body is empty.
    await expect(page.locator('.conv-preview')).not.toBeVisible();
  });
});

test.describe('Inbox — conversation timestamp formatting', () => {
  test('shows date (not time) for conversations from a previous day', async ({ page }) => {
    await setupMockAPI(page);

    await page.route('**/api/v1/account/registered', async (route) => {
      await route.fulfill({ json: true });
    });

    // Use a timestamp from 3 days ago.
    const threeDaysAgo = Date.now() - 3 * 24 * 60 * 60 * 1000;

    await page.route('**/api/v1/conversations', async (route) => {
      await route.fulfill({
        json: [
          {
            id: 1,
            conversationId: 'conv-1',
            type: 1,
            name: 'OldChat',
            unreadCount: 0,
            lastMessageTimestamp: threeDaysAgo,
            lastMessageBody: 'Old message',
            isPinned: false,
            isArchived: false,
          },
        ],
      });
    });

    await page.goto('/');

    // The time display should contain a month abbreviation (e.g., "Mar", "Apr")
    // rather than a HH:MM time format, since it's from a different day.
    const timeEl = page.locator('.conv-time');
    await expect(timeEl).toBeVisible();
    const timeText = await timeEl.textContent();
    // Should match "Mon DD" format like "Mar 31" not "06:19 PM".
    expect(timeText).toMatch(/[A-Z][a-z]{2}\s+\d{1,2}/);
  });
});
