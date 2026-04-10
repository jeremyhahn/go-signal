import { test, expect } from './fixtures/registered';

/**
 * header-buttons.spec.ts
 *
 * Covers the Inbox header buttons: Compose, conversation search, more options,
 * and the "Chats" heading in the left pane.
 */

test.describe('Inbox — left pane header', () => {
  test('shows the "Chats" heading', async ({ page }) => {
    await expect(page.getByRole('heading', { name: 'Chats' })).toBeVisible();
  });

  test('shows the Compose button', async ({ page }) => {
    await expect(page.getByRole('button', { name: 'Compose' })).toBeVisible();
  });

  test('Compose button is clickable', async ({ page }) => {
    const compose = page.getByRole('button', { name: 'Compose' });
    await expect(compose).toBeEnabled();
    await compose.click();
    // Button should not cause errors (no handler yet but click shouldn't crash).
  });
});

test.describe('Inbox — conversation header buttons', () => {
  test.beforeEach(async ({ page }) => {
    await page.getByText('Alice').click();
    await expect(page.locator('.conversation-header')).toBeVisible();
  });

  test('shows the Search in conversation button', async ({ page }) => {
    await expect(
      page.getByRole('button', { name: 'Search in conversation' }),
    ).toBeVisible();
  });

  test('shows the More options button', async ({ page }) => {
    await expect(
      page.getByRole('button', { name: 'More options' }),
    ).toBeVisible();
  });

  test('Search button is clickable without error', async ({ page }) => {
    const searchBtn = page.getByRole('button', { name: 'Search in conversation' });
    await expect(searchBtn).toBeEnabled();
    await searchBtn.click();
  });

  test('More options button is clickable without error', async ({ page }) => {
    const moreBtn = page.getByRole('button', { name: 'More options' });
    await expect(moreBtn).toBeEnabled();
    await moreBtn.click();
  });

  test('conversation header shows avatar with contact initial', async ({ page }) => {
    const avatar = page.locator('.conversation-header__avatar');
    await expect(avatar).toBeVisible();
    const text = await avatar.textContent();
    expect(text).toBe('A');
  });
});
