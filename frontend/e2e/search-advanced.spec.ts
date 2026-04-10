import { test, expect } from './fixtures/registered';

/**
 * search-advanced.spec.ts
 *
 * Covers advanced SearchInput interactions: clear, special characters,
 * focus behavior, and paste.
 */

test.describe('SearchInput — interactions', () => {
  test('clearing the search input resets the value', async ({ page }) => {
    const searchInput = page.getByRole('searchbox', { name: 'Search conversations' });
    await searchInput.fill('Alice');
    await expect(searchInput).toHaveValue('Alice');

    await searchInput.fill('');
    await expect(searchInput).toHaveValue('');
  });

  test('search input accepts special characters', async ({ page }) => {
    const searchInput = page.getByRole('searchbox', { name: 'Search conversations' });
    await searchInput.fill('test@#$%');
    await expect(searchInput).toHaveValue('test@#$%');
  });

  test('search input is focusable', async ({ page }) => {
    const searchInput = page.getByRole('searchbox', { name: 'Search conversations' });
    await searchInput.focus();
    await expect(searchInput).toBeFocused();
  });

  test('search input has correct placeholder', async ({ page }) => {
    const searchInput = page.getByRole('searchbox', { name: 'Search conversations' });
    await expect(searchInput).toHaveAttribute('placeholder', 'Search conversations');
  });

  test('search input has the magnifying glass icon', async ({ page }) => {
    await expect(page.locator('.search-input__icon')).toBeVisible();
  });
});
