import { test as base, expect } from '@playwright/test';
import { setupMockAPI } from './fixtures/mock-api';
import { setupMockWebRTC } from './fixtures/mock-webrtc';

/**
 * dark-theme.spec.ts
 *
 * Verifies that the dark theme is applied correctly across all major views.
 * Each test activates dark mode via the Settings theme selector before
 * exercising a particular screen or component.
 */

const test = base.extend({
  page: async ({ page }, use) => {
    await setupMockWebRTC(page);
    await setupMockAPI(page);
    await page.route('**/api/v1/account/registered', async (route) => {
      await route.fulfill({ json: true });
    });
    await page.goto('/');
    await use(page);
  },
});

/** Switches the theme selector to "dark" from Settings and returns to Chats. */
async function enableDarkTheme(page: ReturnType<typeof test['extend']>['prototype']['page']) {
  await page.getByRole('button', { name: 'Settings' }).click();
  await page.getByLabel('Theme').selectOption('dark');
  // Return to the Chats view after activating dark mode.
  await page.getByRole('button', { name: 'Chats' }).click();
}

// ---------------------------------------------------------------------------
// General dark mode application
// ---------------------------------------------------------------------------

test.describe('Dark theme — general', () => {
  test('dark theme sets data-theme="dark" on the document root', async ({ page }) => {
    await page.getByRole('button', { name: 'Settings' }).click();
    await page.getByLabel('Theme').selectOption('dark');

    const dataTheme = await page.evaluate(() =>
      document.documentElement.getAttribute('data-theme'),
    );
    expect(dataTheme).toBe('dark');
  });

  test('dark theme body background is not white', async ({ page }) => {
    await enableDarkTheme(page);

    const bgColor = await page.evaluate(() =>
      getComputedStyle(document.body).backgroundColor,
    );
    expect(bgColor).not.toBe('rgb(255, 255, 255)');
  });
});

// ---------------------------------------------------------------------------
// InstallScreen in dark mode
// ---------------------------------------------------------------------------

test.describe('Dark theme — InstallScreen', () => {
  test('InstallScreen in dark mode does not use a white background', async ({ page }) => {
    // Start unregistered so InstallScreen is rendered.
    await setupMockAPI(page);

    // Seed dark theme via localStorage before navigation.
    await page.addInitScript(() => {
      localStorage.setItem('go-signal-theme', 'dark');
    });

    await page.goto('/');

    const bgColor = await page.evaluate(() =>
      getComputedStyle(document.body).backgroundColor,
    );
    expect(bgColor).not.toBe('rgb(255, 255, 255)');
  });
});

// ---------------------------------------------------------------------------
// Inbox in dark mode
// ---------------------------------------------------------------------------

test.describe('Dark theme — Inbox', () => {
  test('Inbox panel background changes in dark mode', async ({ page }) => {
    await enableDarkTheme(page);

    await expect(page.getByPlaceholder('Search conversations')).toBeVisible();

    const bgColor = await page.evaluate(() =>
      getComputedStyle(document.body).backgroundColor,
    );
    expect(bgColor).not.toBe('rgb(255, 255, 255)');
  });

  test('Inbox conversation list is still visible in dark mode', async ({ page }) => {
    await enableDarkTheme(page);

    await expect(page.getByText('Alice')).toBeVisible();
    await expect(page.getByText('Bob')).toBeVisible();
  });
});

// ---------------------------------------------------------------------------
// Conversation view in dark mode
// ---------------------------------------------------------------------------

test.describe('Dark theme — Conversation view', () => {
  test('conversation header is visible in dark mode', async ({ page }) => {
    await enableDarkTheme(page);
    await page.getByText('Alice').click();

    await expect(page.locator('.conversation-header')).toBeVisible();
  });

  test('message bubbles are visible in dark mode', async ({ page }) => {
    await enableDarkTheme(page);
    await page.getByText('Alice').click();

    await expect(page.locator('.message-bubble').first()).toBeVisible();
  });

  test('outgoing message bubble has a non-white background in dark mode', async ({ page }) => {
    await enableDarkTheme(page);
    await page.getByText('Alice').click();

    const outgoing = page.locator('.message-bubble.outgoing').first();
    await expect(outgoing).toBeVisible();

    const bgColor = await outgoing.evaluate((el) =>
      getComputedStyle(el).backgroundColor,
    );
    expect(bgColor).not.toBe('rgb(255, 255, 255)');
  });

  test('message input is visible in dark mode', async ({ page }) => {
    await enableDarkTheme(page);
    await page.getByText('Alice').click();

    await expect(page.getByLabel('Message input')).toBeVisible();
  });
});

// ---------------------------------------------------------------------------
// Settings page in dark mode
// ---------------------------------------------------------------------------

test.describe('Dark theme — Settings page', () => {
  test('Settings heading is visible in dark mode', async ({ page }) => {
    await page.getByRole('button', { name: 'Settings' }).click();
    await page.getByLabel('Theme').selectOption('dark');

    await expect(page.getByRole('heading', { name: 'Settings' })).toBeVisible();
  });

  test('Theme selector still shows "dark" after switching', async ({ page }) => {
    await page.getByRole('button', { name: 'Settings' }).click();
    await page.getByLabel('Theme').selectOption('dark');

    await expect(page.getByLabel('Theme')).toHaveValue('dark');
  });
});

// ---------------------------------------------------------------------------
// CallingLobby in dark mode
// ---------------------------------------------------------------------------

test.describe('Dark theme — CallingLobby', () => {
  test('CallingLobby is rendered correctly in dark mode', async ({ page }) => {
    await enableDarkTheme(page);
    await page.getByText('Alice').click();
    await page.getByTestId('call-audio-button').click();

    await expect(page.getByTestId('calling-lobby')).toBeVisible();

    const bgColor = await page.evaluate(() =>
      getComputedStyle(document.body).backgroundColor,
    );
    expect(bgColor).not.toBe('rgb(255, 255, 255)');
  });
});

// ---------------------------------------------------------------------------
// Search input in dark mode
// ---------------------------------------------------------------------------

test.describe('Dark theme — Search input', () => {
  test('search input is visible in dark mode', async ({ page }) => {
    await enableDarkTheme(page);

    const search = page.getByPlaceholder('Search conversations');
    await expect(search).toBeVisible();
  });

  test('search input is functional in dark mode', async ({ page }) => {
    await enableDarkTheme(page);

    const search = page.getByPlaceholder('Search conversations');
    await search.fill('Alice');
    await expect(search).toHaveValue('Alice');
  });
});

// ---------------------------------------------------------------------------
// Connection banner in dark mode
// ---------------------------------------------------------------------------

test.describe('Dark theme — Connection banner', () => {
  test('connection banner is visible in dark mode', async ({ page }) => {
    await enableDarkTheme(page);

    // Banner is always visible in tests since the WS connection is aborted.
    await expect(page.getByRole('alert')).toBeVisible();
  });

  test('connection banner text is readable in dark mode', async ({ page }) => {
    await enableDarkTheme(page);

    await expect(page.getByText('Connecting...')).toBeVisible();
  });
});

export { expect };
