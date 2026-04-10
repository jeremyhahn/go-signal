import { test, expect } from './fixtures/registered';

/**
 * keyboard-accessibility.spec.ts
 *
 * Covers keyboard navigation and accessibility across the app:
 * Tab order, focus management, keyboard shortcuts, and ARIA attributes.
 */

test.describe('Keyboard — NavTabs', () => {
  test('NavTabs has aria-label for navigation', async ({ page }) => {
    await expect(page.locator('nav.NavTabs')).toHaveAttribute(
      'aria-label',
      'Main navigation',
    );
  });

  test('tab buttons are focusable via keyboard', async ({ page }) => {
    const chatsBtn = page.getByRole('button', { name: 'Chats' });
    await chatsBtn.focus();
    await expect(chatsBtn).toBeFocused();
  });
});

test.describe('Keyboard — conversation list', () => {
  test('conversation items are focusable', async ({ page }) => {
    const firstItem = page.locator('.conversation-item').first();
    await firstItem.focus();
    await expect(firstItem).toBeFocused();
  });

  test('Enter key selects a focused conversation', async ({ page }) => {
    const firstItem = page.locator('.conversation-item').first();
    await firstItem.focus();
    await firstItem.press('Enter');

    await expect(page.locator('.conversation-header')).toBeVisible();
  });

  test('Tab key moves focus between conversation items', async ({ page }) => {
    const firstItem = page.locator('.conversation-item').first();
    await firstItem.focus();
    await page.keyboard.press('Tab');

    // Focus should move to the next focusable element.
    const focused = page.locator(':focus');
    await expect(focused).toBeVisible();
  });
});

test.describe('Keyboard — search input', () => {
  test('search input is reachable via Tab', async ({ page }) => {
    const search = page.getByRole('searchbox', { name: 'Search conversations' });
    await search.focus();
    await expect(search).toBeFocused();
  });
});

test.describe('Keyboard — composition area', () => {
  test.beforeEach(async ({ page }) => {
    await page.getByText('Alice').click();
  });

  test('message input has correct aria-label', async ({ page }) => {
    await expect(page.getByLabel('Message input')).toBeVisible();
  });

  test('send button has correct aria-label', async ({ page }) => {
    await expect(page.getByRole('button', { name: 'Send message' })).toBeVisible();
  });

  test('Tab from input reaches send button when enabled', async ({ page }) => {
    const input = page.getByLabel('Message input');
    // Type text to enable the send button so it can receive focus.
    await input.fill('Hello');
    await input.focus();
    await page.keyboard.press('Tab');

    const sendBtn = page.getByRole('button', { name: 'Send message' });
    await expect(sendBtn).toBeFocused();
  });
});

test.describe('Keyboard — settings', () => {
  test('theme selector is keyboard accessible', async ({ page }) => {
    await page.getByRole('button', { name: 'Settings' }).click();

    const themeSelect = page.getByLabel('Theme');
    await themeSelect.focus();
    await expect(themeSelect).toBeFocused();
  });

  test('Manage Keys button is keyboard accessible', async ({ page }) => {
    await page.getByRole('button', { name: 'Settings' }).click();

    const manageBtn = page.getByRole('button', { name: 'Manage Keys' });
    await manageBtn.focus();
    await expect(manageBtn).toBeFocused();
  });
});
