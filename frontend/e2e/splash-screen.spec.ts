import { test, expect } from './fixtures/registered';

/**
 * splash-screen.spec.ts
 *
 * Covers the no-conversation splash screen shown when no conversation is
 * selected in the Inbox.
 */

test.describe('Splash screen', () => {
  test('shows splash screen with message text when no conversation is active', async ({ page }) => {
    await expect(
      page.getByText('Select a conversation to start messaging'),
    ).toBeVisible();
  });

  test('splash screen has the Signal icon', async ({ page }) => {
    await expect(page.locator('.no-conversation-splash__icon')).toBeVisible();
  });

  test('splash screen disappears when a conversation is selected', async ({ page }) => {
    await page.getByText('Alice').click();

    await expect(
      page.getByText('Select a conversation to start messaging'),
    ).not.toBeVisible();
  });
});
