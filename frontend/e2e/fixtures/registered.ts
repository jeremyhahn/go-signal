import { test as base } from '@playwright/test';
import { setupMockAPI } from './mock-api';

/**
 * registered extends the base Playwright test fixture with a page that
 * starts in the fully-registered state, bypassing the InstallScreen.
 *
 * Usage:
 *   import { test } from '../fixtures/registered';
 *   test('inbox is shown', async ({ page }) => { ... });
 */
export const test = base.extend<{ page: ReturnType<typeof base['extend']> }>({
  page: async ({ page }, use) => {
    // Set up all API mocks first so routes are in place before navigation.
    await setupMockAPI(page);

    // Override the registered endpoint to return true — must be registered
    // after setupMockAPI to take priority over its catch-all handler.
    await page.route('**/api/v1/account/registered', async (route) => {
      await route.fulfill({ json: true });
    });

    await page.goto('/');

    await use(page);
  },
});

export { expect } from '@playwright/test';
