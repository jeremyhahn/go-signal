import { test, expect } from './fixtures/registered';

/**
 * timeline-features.spec.ts
 *
 * Covers Timeline production features: date separators, message status
 * indicators, and the scroll-to-bottom button.
 */

test.describe('Timeline — date separators', () => {
  test.beforeEach(async ({ page }) => {
    await page.getByText('Alice').click();
    await expect(page.locator('.timeline')).toBeVisible();
  });

  test('shows a "Today" date separator for today\'s messages', async ({ page }) => {
    await expect(page.getByText('Today')).toBeVisible();
  });
});

test.describe('Timeline — message status', () => {
  test.beforeEach(async ({ page }) => {
    await page.getByText('Alice').click();
    await expect(page.locator('.timeline')).toBeVisible();
  });

  test('outgoing messages show a delivery status indicator', async ({ page }) => {
    const outgoing = page.locator('.message-bubble.outgoing').first();
    await expect(outgoing.locator('.message-status')).toBeVisible();
  });

  test('incoming messages do not show a delivery status indicator', async ({ page }) => {
    const incoming = page.locator('.message-bubble.incoming').first();
    await expect(incoming.locator('.message-status')).not.toBeVisible();
  });
});

test.describe('Timeline — message meta', () => {
  test.beforeEach(async ({ page }) => {
    await page.getByText('Alice').click();
    await expect(page.locator('.timeline')).toBeVisible();
  });

  test('messages display timestamp in the meta area', async ({ page }) => {
    const meta = page.locator('.message-meta').first();
    await expect(meta.locator('.message-time')).toBeVisible();
  });
});
