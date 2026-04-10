import { test, expect } from '@playwright/test';
import { setupMockAPI } from './fixtures/mock-api';

/**
 * install-screen.spec.ts
 *
 * Covers the full registration flow rendered by InstallScreen:
 *   enterNumber -> awaitCode -> (verifying) -> registered (Inbox)
 * and the error recovery path.
 *
 * Each test sets up a fresh unregistered mock API and navigates to '/'
 * independently so tests cannot share state.
 */

test.describe('InstallScreen — phone number step', () => {
  test.beforeEach(async ({ page }) => {
    await setupMockAPI(page);
    await page.goto('/');
  });

  test('shows the registration heading', async ({ page }) => {
    await expect(page.getByRole('heading', { name: 'Register Your Phone' })).toBeVisible();
  });

  test('shows phone number input when not registered', async ({ page }) => {
    await expect(page.getByLabel('Phone Number')).toBeVisible();
  });

  test('Request Code button is disabled while phone field is empty', async ({ page }) => {
    const button = page.getByRole('button', { name: 'Request Code' });
    await expect(button).toBeDisabled();
  });

  test('Request Code button is enabled after entering a phone number', async ({ page }) => {
    await page.getByLabel('Phone Number').fill('+15555550100');
    const button = page.getByRole('button', { name: 'Request Code' });
    await expect(button).toBeEnabled();
  });

  test('shows verification code step after requesting a code', async ({ page }) => {
    await page.getByLabel('Phone Number').fill('+15555550100');
    await page.getByRole('button', { name: 'Request Code' }).click();

    await expect(
      page.getByText(/Enter the verification code sent to/),
    ).toBeVisible();
    await expect(page.getByPlaceholder('123456')).toBeVisible();
  });

  test('Verify button is disabled while code field is empty', async ({ page }) => {
    await page.getByLabel('Phone Number').fill('+15555550100');
    await page.getByRole('button', { name: 'Request Code' }).click();

    const verifyButton = page.getByRole('button', { name: 'Verify' });
    await expect(verifyButton).toBeDisabled();
  });

  test('Verify button is enabled after entering a code', async ({ page }) => {
    await page.getByLabel('Phone Number').fill('+15555550100');
    await page.getByRole('button', { name: 'Request Code' }).click();

    await page.getByPlaceholder('123456').fill('654321');
    await expect(page.getByRole('button', { name: 'Verify' })).toBeEnabled();
  });
});

test.describe('InstallScreen — registration completion', () => {
  test('transitions to Inbox after successful registration', async ({ page }) => {
    await setupMockAPI(page);
    await page.goto('/');

    await page.getByLabel('Phone Number').fill('+15555550100');
    await page.getByRole('button', { name: 'Request Code' }).click();

    await page.getByPlaceholder('123456').fill('654321');
    await page.getByRole('button', { name: 'Verify' }).click();

    // After registration the Inbox left pane should become visible.
    await expect(
      page.getByPlaceholder('Search conversations'),
    ).toBeVisible({ timeout: 10_000 });
  });

  test('shows conversations in the Inbox after registration', async ({ page }) => {
    await setupMockAPI(page);
    await page.goto('/');

    await page.getByLabel('Phone Number').fill('+15555550100');
    await page.getByRole('button', { name: 'Request Code' }).click();
    await page.getByPlaceholder('123456').fill('654321');
    await page.getByRole('button', { name: 'Verify' }).click();

    await expect(page.getByText('Alice')).toBeVisible({ timeout: 10_000 });
  });
});

test.describe('InstallScreen — verifying state', () => {
  test('shows "Verifying..." while code submission is in flight', async ({ page }) => {
    await setupMockAPI(page);

    // Make the submit endpoint hang so we can observe the spinner.
    await page.route('**/api/v1/account/verify/submit', async (route) => {
      // Never fulfill — keeps the request in flight.
      await new Promise(() => {});
    });

    await page.goto('/');
    await page.getByLabel('Phone Number').fill('+15555550100');
    await page.getByRole('button', { name: 'Request Code' }).click();
    await page.getByPlaceholder('123456').fill('654321');
    await page.getByRole('button', { name: 'Verify' }).click();

    await expect(page.getByText('Verifying...')).toBeVisible();
  });
});

test.describe('InstallScreen — verification code failure', () => {
  test('shows error when code submission fails', async ({ page }) => {
    await setupMockAPI(page);

    // Override submit endpoint to return a server error.
    await page.route('**/api/v1/account/verify/submit', async (route) => {
      await route.fulfill({ status: 500, body: 'Invalid code' });
    });

    await page.goto('/');
    await page.getByLabel('Phone Number').fill('+15555550100');
    await page.getByRole('button', { name: 'Request Code' }).click();
    await page.getByPlaceholder('123456').fill('000000');
    await page.getByRole('button', { name: 'Verify' }).click();

    await expect(page.getByText(/HTTP 500/)).toBeVisible();
    await expect(page.getByRole('button', { name: 'Try Again' })).toBeVisible();
  });

  test('Try Again after code failure returns to phone number step', async ({ page }) => {
    await setupMockAPI(page);

    await page.route('**/api/v1/account/verify/submit', async (route) => {
      await route.fulfill({ status: 500, body: 'Invalid code' });
    });

    await page.goto('/');
    await page.getByLabel('Phone Number').fill('+15555550100');
    await page.getByRole('button', { name: 'Request Code' }).click();
    await page.getByPlaceholder('123456').fill('000000');
    await page.getByRole('button', { name: 'Verify' }).click();

    await page.getByRole('button', { name: 'Try Again' }).click();
    await expect(page.getByLabel('Phone Number')).toBeVisible();
  });
});

test.describe('InstallScreen — error state', () => {
  test('shows error message when verification session creation fails', async ({ page }) => {
    await setupMockAPI(page);

    // Override session endpoint to return a server error.
    await page.route('**/api/v1/account/verify/session', async (route) => {
      await route.fulfill({ status: 500, body: 'Internal Server Error' });
    });

    await page.goto('/');
    await page.getByLabel('Phone Number').fill('+15555550100');
    await page.getByRole('button', { name: 'Request Code' }).click();

    await expect(page.getByText(/HTTP 500/)).toBeVisible();
  });

  test('Try Again button returns to phone number step after an error', async ({ page }) => {
    await setupMockAPI(page);

    await page.route('**/api/v1/account/verify/session', async (route) => {
      await route.fulfill({ status: 500, body: 'Internal Server Error' });
    });

    await page.goto('/');
    await page.getByLabel('Phone Number').fill('+15555550100');
    await page.getByRole('button', { name: 'Request Code' }).click();

    await page.getByRole('button', { name: 'Try Again' }).click();
    await expect(page.getByLabel('Phone Number')).toBeVisible();
  });
});
