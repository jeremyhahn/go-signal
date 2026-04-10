import { test as base, expect } from '@playwright/test';
import { setupMockAPI } from './fixtures/mock-api';
import { setupMockWebRTC } from './fixtures/mock-webrtc';

/**
 * race-conditions.spec.ts
 *
 * Exercises timing-sensitive interaction paths where rapid user actions could
 * produce corrupt state, duplicate requests, or broken UI.
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

// ---------------------------------------------------------------------------
// Rapid conversation switching
// ---------------------------------------------------------------------------

test.describe('Race conditions — rapid conversation switching', () => {
  test('rapid Alice → Bob → Alice → Bob switching shows correct final header', async ({ page }) => {
    const alice = page.locator('.conversation-item').first();
    const bob = page.locator('.conversation-item').nth(1);

    // Simulate rapid switching without waiting between clicks.
    await alice.click();
    await bob.click();
    await alice.click();
    await bob.click();

    // Only one item should be active at the end.
    const activeCount = await page.locator('.conversation-item.active').count();
    expect(activeCount).toBe(1);

    // Header must show Bob (the last selected).
    const headerText = await page.locator('.conversation-header').textContent();
    expect(headerText).toContain('Bob');
  });

  test('rapid switching does not leave multiple conversation headers visible', async ({ page }) => {
    const alice = page.locator('.conversation-item').first();
    const bob = page.locator('.conversation-item').nth(1);

    await alice.click();
    await bob.click();
    await alice.click();

    const headers = page.locator('.conversation-header');
    await expect(headers).toHaveCount(1);
  });
});

// ---------------------------------------------------------------------------
// Double-click send
// ---------------------------------------------------------------------------

test.describe('Race conditions — double-click send', () => {
  test('double-clicking send only clears the input once', async ({ page }) => {
    await page.getByText('Alice').click();

    const input = page.getByLabel('Message input');
    const sendBtn = page.getByRole('button', { name: 'Send message' });

    await input.fill('Double click test');
    await expect(sendBtn).toBeEnabled();

    // Rapid double-click.
    await sendBtn.dblclick();

    // Input should be cleared (not stuck in a broken state).
    await expect(input).toHaveValue('');
  });

  test('double-clicking send leaves the input enabled for follow-up messages', async ({ page }) => {
    await page.getByText('Alice').click();

    const input = page.getByLabel('Message input');
    const sendBtn = page.getByRole('button', { name: 'Send message' });

    await input.fill('Another message');
    await sendBtn.dblclick();

    // Input must remain accessible.
    await expect(input).toBeEnabled();
  });
});

// ---------------------------------------------------------------------------
// Double-click call button
// ---------------------------------------------------------------------------

test.describe('Race conditions — double-click call button', () => {
  test('double-clicking audio call button does not open two lobbies', async ({ page }) => {
    await page.getByText('Alice').click();
    await expect(page.getByTestId('call-audio-button')).toBeVisible();

    // Rapid double-click on the call button.
    await page.getByTestId('call-audio-button').dblclick();

    // Only one lobby should be present in the DOM.
    const lobbyCount = await page.getByTestId('calling-lobby').count();
    expect(lobbyCount).toBeLessThanOrEqual(1);
  });

  test('call lobby can be cancelled after a double-click open attempt', async ({ page }) => {
    await page.getByText('Alice').click();
    await page.getByTestId('call-audio-button').dblclick();

    // If a lobby did open, cancel should still work.
    const lobby = page.getByTestId('calling-lobby');
    const isVisible = await lobby.isVisible();
    if (isVisible) {
      await page.getByTestId('lobby-cancel').click();
      await expect(lobby).not.toBeVisible();
    }
  });
});

// ---------------------------------------------------------------------------
// Rapid theme switching
// ---------------------------------------------------------------------------

test.describe('Race conditions — rapid theme switching', () => {
  test('rapid theme cycling does not break the UI', async ({ page }) => {
    await page.getByRole('button', { name: 'Settings' }).click();

    const themeSelect = page.getByLabel('Theme');

    // Cycle quickly through themes.
    await themeSelect.selectOption('dark');
    await themeSelect.selectOption('light');
    await themeSelect.selectOption('dark');
    await themeSelect.selectOption('light');

    // Settings heading must still be visible after rapid switching.
    await expect(page.getByRole('heading', { name: 'Settings' })).toBeVisible();
  });

  test('rapid theme cycling leaves data-theme in a valid state', async ({ page }) => {
    await page.getByRole('button', { name: 'Settings' }).click();

    const themeSelect = page.getByLabel('Theme');
    await themeSelect.selectOption('dark');
    await themeSelect.selectOption('light');
    await themeSelect.selectOption('dark');

    const dataTheme = await page.evaluate(() =>
      document.documentElement.getAttribute('data-theme'),
    );
    expect(['dark', 'light', 'system', null]).toContain(dataTheme);
  });

  test('navigation still works after rapid theme switching', async ({ page }) => {
    await page.getByRole('button', { name: 'Settings' }).click();

    const themeSelect = page.getByLabel('Theme');
    await themeSelect.selectOption('dark');
    await themeSelect.selectOption('light');
    await themeSelect.selectOption('dark');

    // Navigate back to chats — must work correctly.
    await page.getByRole('button', { name: 'Chats' }).click();
    await expect(page.getByText('Alice')).toBeVisible();
  });
});

export { expect };
