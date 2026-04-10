import { test, expect } from './fixtures/registered';

/**
 * inbox.spec.ts
 *
 * Covers the main Inbox view rendered when the account is already registered.
 * All tests use the `registered` fixture which sets up mock API routes and
 * navigates to '/' with the registered state pre-set.
 */

test.describe('Inbox — left pane', () => {
  test('shows the search input', async ({ page }) => {
    await expect(page.getByPlaceholder('Search conversations')).toBeVisible();
  });

  test('search input has correct accessible label', async ({ page }) => {
    await expect(
      page.getByRole('searchbox', { name: 'Search conversations' }),
    ).toBeVisible();
  });

  test('shows the conversation list with Alice and Bob', async ({ page }) => {
    await expect(page.getByText('Alice')).toBeVisible();
    await expect(page.getByText('Bob')).toBeVisible();
  });

  test('shows the last message preview for each conversation', async ({ page }) => {
    await expect(page.getByText('Hey there!')).toBeVisible();
    await expect(page.getByText('See you later')).toBeVisible();
  });

  test('shows unread badge for conversations with unread messages', async ({ page }) => {
    // Alice has unreadCount: 2
    await expect(page.locator('.badge')).toBeVisible();
    await expect(page.locator('.badge')).toHaveText('2');
  });
});

test.describe('Inbox — placeholder state', () => {
  test('shows "Select a conversation" placeholder when no conversation is active', async ({ page }) => {
    await expect(page.getByText('Select a conversation')).toBeVisible();
  });

  test('does not show a conversation header when none is selected', async ({ page }) => {
    // The conversation-header h3 element should not exist initially.
    await expect(page.locator('.conversation-header')).not.toBeVisible();
  });
});

test.describe('Inbox — selecting a conversation', () => {
  test('clicking a conversation removes the placeholder', async ({ page }) => {
    await page.getByText('Alice').click();

    await expect(page.getByText('Select a conversation')).not.toBeVisible();
  });

  test('clicking a conversation shows the conversation header with the contact name', async ({ page }) => {
    await page.getByText('Alice').click();

    await expect(page.locator('.conversation-header').getByText('Alice')).toBeVisible();
  });

  test('clicking a conversation shows the timeline', async ({ page }) => {
    await page.getByText('Alice').click();

    await expect(page.locator('.timeline')).toBeVisible();
  });

  test('timeline shows messages for the selected conversation', async ({ page }) => {
    await page.getByText('Alice').click();

    // Scope to the timeline container to avoid matching the conversation list preview.
    const timeline = page.locator('.timeline');
    await expect(timeline.getByText('Hey there!')).toBeVisible();
    await expect(timeline.getByText('Hi Alice!')).toBeVisible();
  });

  test('clicking a conversation shows the composition area', async ({ page }) => {
    await page.getByText('Alice').click();

    await expect(page.getByLabel('Message input')).toBeVisible();
    await expect(page.getByRole('button', { name: 'Send message' })).toBeVisible();
  });

  test('switching conversations updates the header name', async ({ page }) => {
    await page.getByText('Alice').click();
    await expect(page.locator('.conversation-header').getByText('Alice')).toBeVisible();

    await page.getByText('Bob').click();
    await expect(page.locator('.conversation-header').getByText('Bob')).toBeVisible();
  });

  test('keyboard Enter on a conversation item selects it', async ({ page }) => {
    const aliceItem = page.locator('.conversation-item').first();
    await aliceItem.focus();
    await aliceItem.press('Enter');

    await expect(page.locator('.conversation-header').getByText('Alice')).toBeVisible();
  });
});

test.describe('Inbox — message bubble types', () => {
  test('incoming messages have the incoming class', async ({ page }) => {
    await page.getByText('Alice').click();

    const timeline = page.locator('.timeline');
    await expect(timeline.locator('.message-bubble.incoming')).toHaveCount(1);
  });

  test('outgoing messages have the outgoing class', async ({ page }) => {
    await page.getByText('Alice').click();

    const timeline = page.locator('.timeline');
    await expect(timeline.locator('.message-bubble.outgoing')).toHaveCount(1);
  });
});

test.describe('Inbox — composition area visibility', () => {
  test('composition area is not visible when no conversation is selected', async ({ page }) => {
    await expect(page.getByLabel('Message input')).not.toBeVisible();
    await expect(page.getByRole('button', { name: 'Send message' })).not.toBeVisible();
  });
});

test.describe('Inbox — search input', () => {
  test('typing in the search input updates the value', async ({ page }) => {
    const searchInput = page.getByRole('searchbox', { name: 'Search conversations' });
    await searchInput.fill('Alice');
    await expect(searchInput).toHaveValue('Alice');
  });
});
