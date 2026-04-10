import { test, expect } from './fixtures/registered';

/**
 * nav-tabs.spec.ts
 *
 * Covers the NavTabs sidebar navigation component.
 */

test.describe('NavTabs', () => {
  test('shows the Chats tab button', async ({ page }) => {
    await expect(page.getByRole('button', { name: 'Chats' })).toBeVisible();
  });

  test('shows the Settings tab button', async ({ page }) => {
    await expect(page.getByRole('button', { name: 'Settings' })).toBeVisible();
  });

  test('Chats tab is active by default', async ({ page }) => {
    const chatsButton = page.getByRole('button', { name: 'Chats' });
    await expect(chatsButton).toHaveAttribute('aria-current', 'page');
  });

  test('clicking Settings tab marks it as active', async ({ page }) => {
    await page.getByRole('button', { name: 'Settings' }).click();

    const settingsButton = page.getByRole('button', { name: 'Settings' });
    await expect(settingsButton).toHaveAttribute('aria-current', 'page');
  });

  test('NavTabs is rendered as a nav element', async ({ page }) => {
    await expect(page.locator('nav.NavTabs')).toBeVisible();
  });
});
