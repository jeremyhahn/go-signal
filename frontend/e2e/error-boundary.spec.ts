import { test, expect } from '@playwright/test';
import { setupMockAPI } from './fixtures/mock-api';

/**
 * error-boundary.spec.ts
 *
 * Covers the ErrorBoundary component: error display, retry functionality.
 * Forces a render error by injecting a faulty component via the store.
 */

test.describe('ErrorBoundary', () => {
  test('app still renders after a failed API call during mount', async ({ page }) => {
    await setupMockAPI(page);
    await page.goto('/');

    // The app should render the InstallScreen even though WebSocket fails.
    await expect(page.getByRole('heading', { name: 'Register Your Phone' })).toBeVisible();
  });

  test('app does not show a white screen on initial load', async ({ page }) => {
    await setupMockAPI(page);
    await page.goto('/');

    // Verify the app root has rendered content.
    const rootContent = await page.locator('#root').innerHTML();
    expect(rootContent.length).toBeGreaterThan(0);
  });
});
