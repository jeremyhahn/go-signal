import { test, expect } from '@playwright/test';
import { setupMockAPI } from './fixtures/mock-api';
import { setupMockWebRTC } from './fixtures/mock-webrtc';

/**
 * full-flow.spec.ts
 *
 * End-to-end journeys that span multiple app states in a single test run.
 * These tests intentionally cover the widest possible slice of the app to
 * catch regressions that unit-scope tests would miss.
 */

// ---------------------------------------------------------------------------
// Registration → first message flow
// ---------------------------------------------------------------------------

test.describe('Full flow — registration to first message', () => {
  test('complete registration to first message flow', async ({ page }) => {
    await setupMockAPI(page);
    await page.goto('/');

    // Step 1: registration — phone number entry.
    await expect(page.getByRole('heading', { name: 'Register Your Phone' })).toBeVisible();
    await page.getByLabel('Phone Number').fill('+15555550100');
    await page.getByRole('button', { name: 'Request Code' }).click();

    // Step 2: verification code entry.
    await expect(page.getByPlaceholder('123456')).toBeVisible();
    await page.getByPlaceholder('123456').fill('654321');
    await page.getByRole('button', { name: 'Verify' }).click();

    // Step 3: inbox loads with conversations.
    await expect(page.getByPlaceholder('Search conversations')).toBeVisible({ timeout: 10_000 });
    await expect(page.getByText('Alice')).toBeVisible({ timeout: 10_000 });

    // Step 4: select Alice's conversation.
    await page.getByText('Alice').click();
    await expect(page.locator('.conversation-header')).toBeVisible();

    // Step 5: send a message and verify the input clears.
    const input = page.getByLabel('Message input');
    await input.fill('Hello from E2E');
    await expect(page.getByRole('button', { name: 'Send message' })).toBeEnabled();
    await page.getByRole('button', { name: 'Send message' }).click();

    // After a successful send the input should be empty.
    await expect(input).toHaveValue('');
  });
});

// ---------------------------------------------------------------------------
// Registration → audio call flow
// ---------------------------------------------------------------------------

test.describe('Full flow — registration to audio call', () => {
  test('complete registration to audio call flow', async ({ page }) => {
    await setupMockWebRTC(page);
    await setupMockAPI(page);
    await page.goto('/');

    // Step 1: register.
    await page.getByLabel('Phone Number').fill('+15555550100');
    await page.getByRole('button', { name: 'Request Code' }).click();
    await page.getByPlaceholder('123456').fill('654321');
    await page.getByRole('button', { name: 'Verify' }).click();

    // Step 2: inbox loads.
    await expect(page.getByText('Alice')).toBeVisible({ timeout: 10_000 });

    // Step 3: select Alice and open audio call lobby.
    await page.getByText('Alice').click();
    await expect(page.locator('.conversation-header')).toBeVisible();
    await page.getByTestId('call-audio-button').click();

    // Step 4: lobby is shown.
    await expect(page.getByTestId('calling-lobby')).toBeVisible();
    await expect(page.getByText('Audio call with Alice')).toBeVisible();

    // Step 5: start the call.
    await expect(page.getByTestId('lobby-start-call')).toBeEnabled({ timeout: 5_000 });
    await page.getByTestId('lobby-start-call').click();

    // Step 6: call screen appears.
    await expect(page.getByTestId('call-screen')).toBeVisible({ timeout: 5_000 });

    // Step 7: hang up.
    await expect(page.getByTestId('call-hangup')).toBeVisible({ timeout: 5_000 });
    await page.getByTestId('call-hangup').click();

    // Step 8: call screen is gone.
    await expect(page.getByTestId('call-screen')).not.toBeVisible({ timeout: 5_000 });
  });
});

// ---------------------------------------------------------------------------
// Settings round trip (theme change persists)
// ---------------------------------------------------------------------------

test.describe('Full flow — settings round trip', () => {
  test('settings round trip: change theme, return to chats, verify persistence', async ({ page }) => {
    await setupMockAPI(page);
    await page.route('**/api/v1/account/registered', async (route) => {
      await route.fulfill({ json: true });
    });
    await page.goto('/');

    // Step 1: open Settings and switch to dark.
    await page.getByRole('button', { name: 'Settings' }).click();
    await page.getByLabel('Theme').selectOption('dark');

    const dataThemeAfterChange = await page.evaluate(() =>
      document.documentElement.getAttribute('data-theme'),
    );
    expect(dataThemeAfterChange).toBe('dark');

    // Step 2: navigate back to chats — conversations must still be visible.
    await page.getByRole('button', { name: 'Chats' }).click();
    await expect(page.getByText('Alice')).toBeVisible();
    await expect(page.getByText('Bob')).toBeVisible();

    // Step 3: return to Settings — theme selector must still show dark.
    await page.getByRole('button', { name: 'Settings' }).click();
    await expect(page.getByLabel('Theme')).toHaveValue('dark');
  });
});

// ---------------------------------------------------------------------------
// Conversation switching preserves header identity
// ---------------------------------------------------------------------------

test.describe('Full flow — conversation switching', () => {
  test('conversation switching shows correct header after multiple switches', async ({ page }) => {
    await setupMockAPI(page);
    await page.route('**/api/v1/account/registered', async (route) => {
      await route.fulfill({ json: true });
    });
    await page.goto('/');

    // Select Alice.
    await page.getByText('Alice').click();
    await expect(page.locator('.conversation-header')).toBeVisible();

    // Type something in the input.
    await page.getByLabel('Message input').fill('Drafted message');

    // Switch to Bob.
    await page.getByText('Bob').click();
    await expect(page.locator('.conversation-header')).toBeVisible();

    // Switch back to Alice — header must show Alice's name.
    await page.locator('.conversation-item').first().click();
    const headerText = await page.locator('.conversation-header').textContent();
    expect(headerText).toContain('Alice');
  });
});

export { expect };
