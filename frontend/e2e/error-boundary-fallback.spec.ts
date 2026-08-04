import { test as base, expect } from '@playwright/test';
import { setupMockAPI } from './fixtures/mock-api';

/**
 * error-boundary-fallback.spec.ts
 *
 * The existing error-boundary.spec only asserts the app does not white-screen.
 * This spec drives the ErrorBoundary's *fallback* render path and its retry
 * handler by forcing a genuine React render error: returning a non-iterable
 * object from the messages endpoint makes Timeline's groupByDate() throw
 * during render, which the boundary catches.
 */

const test = base.extend({
  page: async ({ page }, use) => {
    await setupMockAPI(page);
    await page.route('**/api/v1/account/registered', async (route) => {
      await route.fulfill({ json: true });
    });
    // Non-iterable payload -> `for (const msg of messages)` throws in render.
    await page.route('**/api/v1/messages?*', async (route) => {
      await route.fulfill({ status: 200, json: { not: 'an array' } });
    });
    await page.goto('/');
    await use(page);
  },
});

test.describe('ErrorBoundary — fallback UI', () => {
  test('a render error shows the "Something went wrong" fallback', async ({ page }) => {
    await page.getByText('Alice').click();
    await expect(page.getByRole('heading', { name: 'Something went wrong' })).toBeVisible();
  });

  test('fallback shows a descriptive error message', async ({ page }) => {
    await page.getByText('Alice').click();
    await expect(page.locator('.error-boundary__message')).toBeVisible();
    await expect(page.locator('.error-boundary__message')).not.toBeEmpty();
  });

  test('fallback exposes a "Try Again" retry button', async ({ page }) => {
    await page.getByText('Alice').click();
    await expect(page.getByRole('button', { name: 'Try Again' })).toBeVisible();
  });

  test('clicking "Try Again" re-runs render via the retry handler', async ({ page }) => {
    await page.getByText('Alice').click();
    const retry = page.getByRole('button', { name: 'Try Again' });
    await expect(retry).toBeVisible();

    // The underlying cause persists, so the boundary re-catches and the
    // fallback stays — but handleRetry (setState) is exercised and the app
    // never white-screens.
    await retry.click();
    await expect(page.getByRole('heading', { name: 'Something went wrong' })).toBeVisible();

    const rootContent = await page.locator('#root').innerHTML();
    expect(rootContent.length).toBeGreaterThan(0);
  });
});
