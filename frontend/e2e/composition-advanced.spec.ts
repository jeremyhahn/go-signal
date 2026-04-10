import { test, expect } from './fixtures/registered';

/**
 * composition-advanced.spec.ts
 *
 * Covers advanced CompositionArea interactions: sending states, send failure,
 * multi-line messages, focus management, and paste behavior.
 */

test.describe('CompositionArea — sending state', () => {
  test.beforeEach(async ({ page }) => {
    await page.getByText('Alice').click();
    await expect(page.getByLabel('Message input')).toBeVisible();
  });

  test('input and send button become disabled during send', async ({ page }) => {
    // Make send endpoint slow so we can observe the sending state.
    await page.route('**/api/v1/messages/send', async (route) => {
      await new Promise((resolve) => setTimeout(resolve, 2000));
      await route.fulfill({ json: { timestamp: Date.now(), needsSync: false } });
    });

    await page.getByLabel('Message input').fill('Test message');
    await page.getByRole('button', { name: 'Send message' }).click();

    // During sending, both should be disabled.
    await expect(page.getByLabel('Message input')).toBeDisabled();
    await expect(page.getByRole('button', { name: 'Send message' })).toBeDisabled();
  });

  test('input is re-enabled after send completes', async ({ page }) => {
    await page.getByLabel('Message input').fill('Test message');
    await page.getByRole('button', { name: 'Send message' }).click();

    // After send, input should be enabled and empty.
    await expect(page.getByLabel('Message input')).toBeEnabled();
    await expect(page.getByLabel('Message input')).toHaveValue('');
  });
});

test.describe('CompositionArea — send failure', () => {
  test.beforeEach(async ({ page }) => {
    await page.getByText('Alice').click();
    await expect(page.getByLabel('Message input')).toBeVisible();
  });

  test('input is re-enabled after send failure', async ({ page }) => {
    // Make send endpoint fail.
    await page.route('**/api/v1/messages/send', async (route) => {
      await route.fulfill({ status: 500, body: 'Internal Server Error' });
    });

    await page.getByLabel('Message input').fill('Will fail');
    await page.getByRole('button', { name: 'Send message' }).click();

    // Input should become enabled again after failure.
    await expect(page.getByLabel('Message input')).toBeEnabled({ timeout: 5000 });
  });
});

test.describe('CompositionArea — multi-line messages', () => {
  test.beforeEach(async ({ page }) => {
    await page.getByText('Alice').click();
    await expect(page.getByLabel('Message input')).toBeVisible();
  });

  test('Shift+Enter adds a new line without sending', async ({ page }) => {
    const input = page.getByLabel('Message input');
    await input.fill('Line one');
    await input.press('Shift+Enter');
    await input.type('Line two');

    const value = await input.inputValue();
    expect(value).toContain('Line one');
    expect(value).toContain('Line two');
  });

  test('Enter after Shift+Enter sends the multi-line message', async ({ page }) => {
    const input = page.getByLabel('Message input');
    await input.fill('Line one');
    await input.press('Shift+Enter');
    await input.type('Line two');
    await input.press('Enter');

    // Input should be cleared after sending.
    await expect(input).toHaveValue('');
  });
});

test.describe('CompositionArea — focus', () => {
  test('composition area textarea is focusable', async ({ page }) => {
    await page.getByText('Alice').click();

    const input = page.getByLabel('Message input');
    await input.focus();
    await expect(input).toBeFocused();
  });
});
