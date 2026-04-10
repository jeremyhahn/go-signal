import { test, expect } from '@playwright/test';
import { setupMockAPI } from './fixtures/mock-api';

/**
 * navigation.spec.ts
 *
 * Covers top-level routing logic in App.tsx:
 *   - Unregistered  -> renders InstallScreen
 *   - Registered    -> renders Inbox
 *   - Registration  -> transitions InstallScreen -> Inbox
 *
 * Each test navigates independently to guarantee isolation.
 */

test.describe('App routing — unregistered', () => {
  test.beforeEach(async ({ page }) => {
    await setupMockAPI(page);
    await page.goto('/');
  });

  test('unregistered user sees the InstallScreen', async ({ page }) => {
    await expect(page.getByRole('heading', { name: 'Register Your Phone' })).toBeVisible();
    await expect(page.getByLabel('Phone Number')).toBeVisible();
  });

  test('unregistered user does not see the Inbox', async ({ page }) => {
    await expect(page.getByPlaceholder('Search conversations')).not.toBeVisible();
  });

  test('unregistered user does not see a conversation list', async ({ page }) => {
    await expect(page.locator('.conversation-list')).not.toBeVisible();
  });
});

test.describe('App routing — registered', () => {
  test.beforeEach(async ({ page }) => {
    await setupMockAPI(page);

    // Override registered to return true before navigation.
    await page.route('**/api/v1/account/registered', async (route) => {
      await route.fulfill({ json: true });
    });

    await page.goto('/');
  });

  test('registered user sees the Inbox', async ({ page }) => {
    await expect(page.getByPlaceholder('Search conversations')).toBeVisible();
  });

  test('registered user does not see the InstallScreen', async ({ page }) => {
    await expect(page.getByLabel('Phone Number')).not.toBeVisible();
  });

  test('registered user sees the conversation list', async ({ page }) => {
    await expect(page.locator('.conversation-list')).toBeVisible();
  });

  test('registered user sees conversations from the API', async ({ page }) => {
    await expect(page.getByText('Alice')).toBeVisible();
    await expect(page.getByText('Bob')).toBeVisible();
  });
});

test.describe('App routing — registration transition', () => {
  test('completing registration navigates from InstallScreen to Inbox', async ({ page }) => {
    await setupMockAPI(page);
    await page.goto('/');

    // Confirm we start on InstallScreen.
    await expect(page.getByLabel('Phone Number')).toBeVisible();

    // Complete the registration flow.
    await page.getByLabel('Phone Number').fill('+15555550100');
    await page.getByRole('button', { name: 'Request Code' }).click();
    await page.getByPlaceholder('123456').fill('654321');
    await page.getByRole('button', { name: 'Verify' }).click();

    // InstallScreen should disappear and Inbox should appear.
    await expect(page.getByLabel('Phone Number')).not.toBeVisible({ timeout: 10_000 });
    await expect(page.getByPlaceholder('Search conversations')).toBeVisible({ timeout: 10_000 });
  });

  test('Inbox displays conversations immediately after registration', async ({ page }) => {
    await setupMockAPI(page);
    await page.goto('/');

    await page.getByLabel('Phone Number').fill('+15555550100');
    await page.getByRole('button', { name: 'Request Code' }).click();
    await page.getByPlaceholder('123456').fill('654321');
    await page.getByRole('button', { name: 'Verify' }).click();

    await expect(page.getByText('Alice')).toBeVisible({ timeout: 10_000 });
    await expect(page.getByText('Bob')).toBeVisible({ timeout: 10_000 });
  });
});
