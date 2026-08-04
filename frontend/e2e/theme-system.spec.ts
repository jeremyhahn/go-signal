import { test as base, expect } from '@playwright/test';
import { setupMockAPI } from './fixtures/mock-api';

/**
 * theme-system.spec.ts
 *
 * Exercises the "system" branch of App.useThemeEffect, including the
 * prefers-color-scheme media-query listener that other theme specs (which
 * only assert explicit light/dark) never reach. page.emulateMedia drives the
 * OS-level colour scheme deterministically.
 */

const test = base.extend({
  page: async ({ page }, use) => {
    await setupMockAPI(page);
    await page.route('**/api/v1/account/registered', async (route) => {
      await route.fulfill({ json: true });
    });
    await use(page);
  },
});

async function selectSystemTheme(page: import('@playwright/test').Page) {
  await page.getByRole('button', { name: 'Settings' }).click();
  await page.getByLabel('Theme').selectOption('system');
  await page.getByRole('button', { name: 'Chats' }).click();
}

test.describe('Theme — system mode', () => {
  test('system theme resolves to dark when the OS prefers dark', async ({ page }) => {
    await page.emulateMedia({ colorScheme: 'dark' });
    await page.goto('/');
    await selectSystemTheme(page);

    await expect
      .poll(() => page.evaluate(() => document.documentElement.getAttribute('data-theme')))
      .toBe('dark');
  });

  test('system theme resolves to light when the OS prefers light', async ({ page }) => {
    await page.emulateMedia({ colorScheme: 'light' });
    await page.goto('/');
    await selectSystemTheme(page);

    await expect
      .poll(() => page.evaluate(() => document.documentElement.getAttribute('data-theme')))
      .toBe('light');
  });

  test('changing the OS scheme live updates data-theme while in system mode', async ({ page }) => {
    await page.emulateMedia({ colorScheme: 'dark' });
    await page.goto('/');
    await selectSystemTheme(page);
    await expect
      .poll(() => page.evaluate(() => document.documentElement.getAttribute('data-theme')))
      .toBe('dark');

    // Flip the OS preference — the media-query change listener must react.
    await page.emulateMedia({ colorScheme: 'light' });
    await expect
      .poll(() => page.evaluate(() => document.documentElement.getAttribute('data-theme')))
      .toBe('light');

    await page.emulateMedia({ colorScheme: 'dark' });
    await expect
      .poll(() => page.evaluate(() => document.documentElement.getAttribute('data-theme')))
      .toBe('dark');
  });

  test('switching away from system stops following the OS scheme', async ({ page }) => {
    await page.emulateMedia({ colorScheme: 'dark' });
    await page.goto('/');

    await page.getByRole('button', { name: 'Settings' }).click();
    await page.getByLabel('Theme').selectOption('light');
    await expect
      .poll(() => page.evaluate(() => document.documentElement.getAttribute('data-theme')))
      .toBe('light');

    // OS flips to dark, but an explicit light theme must not follow it.
    await page.emulateMedia({ colorScheme: 'dark' });
    await expect
      .poll(() => page.evaluate(() => document.documentElement.getAttribute('data-theme')))
      .toBe('light');
  });
});
