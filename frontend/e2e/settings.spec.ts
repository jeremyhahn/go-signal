import { test, expect } from './fixtures/registered';

/**
 * settings.spec.ts
 *
 * Covers the Settings page: navigation, theme toggle, and FIDO2 section.
 */

test.describe('Settings — navigation', () => {
  test('clicking the Settings tab shows the Settings page', async ({ page }) => {
    await page.getByRole('button', { name: 'Settings' }).click();

    await expect(page.getByRole('heading', { name: 'Settings' })).toBeVisible();
  });

  test('Settings page shows Appearance section', async ({ page }) => {
    await page.getByRole('button', { name: 'Settings' }).click();

    await expect(page.getByText('Appearance')).toBeVisible();
  });

  test('Settings page shows Security section with FIDO2', async ({ page }) => {
    await page.getByRole('button', { name: 'Settings' }).click();

    await expect(page.getByText('FIDO2 / WebAuthn')).toBeVisible();
    await expect(page.getByRole('button', { name: 'Manage Keys' })).toBeVisible();
  });

  test('Settings page shows About section', async ({ page }) => {
    await page.getByRole('button', { name: 'Settings' }).click();

    await expect(page.getByText('About')).toBeVisible();
  });

  test('switching back to Chats tab shows the conversation list', async ({ page }) => {
    await page.getByRole('button', { name: 'Settings' }).click();
    await expect(page.getByRole('heading', { name: 'Settings' })).toBeVisible();

    await page.getByRole('button', { name: 'Chats' }).click();
    await expect(page.getByText('Alice')).toBeVisible();
  });
});

test.describe('Settings — theme', () => {
  test('theme selector defaults to System', async ({ page }) => {
    await page.getByRole('button', { name: 'Settings' }).click();

    const themeSelect = page.getByLabel('Theme');
    await expect(themeSelect).toHaveValue('system');
  });

  test('changing theme to Dark sets data-theme attribute', async ({ page }) => {
    await page.getByRole('button', { name: 'Settings' }).click();

    await page.getByLabel('Theme').selectOption('dark');

    const dataTheme = await page.evaluate(() =>
      document.documentElement.getAttribute('data-theme'),
    );
    expect(dataTheme).toBe('dark');
  });

  test('changing theme to Light sets data-theme attribute', async ({ page }) => {
    await page.getByRole('button', { name: 'Settings' }).click();

    await page.getByLabel('Theme').selectOption('light');

    const dataTheme = await page.evaluate(() =>
      document.documentElement.getAttribute('data-theme'),
    );
    expect(dataTheme).toBe('light');
  });
});
