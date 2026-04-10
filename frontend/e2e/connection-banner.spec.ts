import { test as base, expect } from '@playwright/test';
import { setupMockAPI } from './fixtures/mock-api';

/**
 * connection-banner.spec.ts
 *
 * Covers the connection status banner shown when the WebSocket is
 * disconnected (which it always is in tests since we abort the WS route).
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

test.describe('Connection banner', () => {
  test('shows "Connecting..." banner when disconnected', async ({ page }) => {
    await expect(page.getByText('Connecting...')).toBeVisible();
  });

  test('connection banner has alert role for accessibility', async ({ page }) => {
    await expect(page.getByRole('alert')).toBeVisible();
  });
});

export { expect };
