import { test as base, expect } from '@playwright/test';
import { setupMockAPI } from './fixtures/mock-api';

/**
 * theme-persistence.spec.ts
 *
 * Covers theme persistence across page reloads via localStorage.
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

test.describe('Theme — persistence', () => {
  test('dark theme persists after page reload', async ({ page }) => {
    // Switch to Settings and change theme.
    await page.getByRole('button', { name: 'Settings' }).click();
    await page.getByLabel('Theme').selectOption('dark');

    // Verify it took effect.
    let dataTheme = await page.evaluate(() =>
      document.documentElement.getAttribute('data-theme'),
    );
    expect(dataTheme).toBe('dark');

    // Reload the page.
    await page.reload();

    // Theme should still be dark after reload.
    dataTheme = await page.evaluate(() =>
      document.documentElement.getAttribute('data-theme'),
    );
    expect(dataTheme).toBe('dark');
  });

  test('light theme persists after page reload', async ({ page }) => {
    await page.getByRole('button', { name: 'Settings' }).click();
    await page.getByLabel('Theme').selectOption('light');

    await page.reload();

    const dataTheme = await page.evaluate(() =>
      document.documentElement.getAttribute('data-theme'),
    );
    expect(dataTheme).toBe('light');
  });

  test('theme is stored in localStorage', async ({ page }) => {
    await page.getByRole('button', { name: 'Settings' }).click();
    await page.getByLabel('Theme').selectOption('dark');

    const stored = await page.evaluate(() =>
      localStorage.getItem('go-signal-theme'),
    );
    expect(stored).toBe('dark');
  });
});

test.describe('Theme — visual application', () => {
  test('dark theme applies dark background to the app', async ({ page }) => {
    await page.getByRole('button', { name: 'Settings' }).click();
    await page.getByLabel('Theme').selectOption('dark');

    // Check that the body background color changes.
    const bgColor = await page.evaluate(() =>
      getComputedStyle(document.body).backgroundColor,
    );
    // Dark theme should have a dark background (not white).
    expect(bgColor).not.toBe('rgb(255, 255, 255)');
  });
});

export { expect };
