import { test, expect } from './fixtures/registered';

/**
 * composition.spec.ts
 *
 * Covers the CompositionArea component: typing, enabling / disabling the
 * send button, sending a message, and keyboard submission via Enter.
 *
 * All tests use the `registered` fixture and open Alice's conversation first
 * so the composition area is rendered.
 */

test.describe('CompositionArea', () => {
  test.beforeEach(async ({ page }) => {
    // Open a conversation so the composition area is visible.
    await page.getByText('Alice').click();
    await expect(page.getByLabel('Message input')).toBeVisible();
  });

  test('send button is disabled when the message input is empty', async ({ page }) => {
    await expect(page.getByRole('button', { name: 'Send message' })).toBeDisabled();
  });

  test('send button is disabled when the input contains only whitespace', async ({ page }) => {
    await page.getByLabel('Message input').fill('   ');
    await expect(page.getByRole('button', { name: 'Send message' })).toBeDisabled();
  });

  test('send button is enabled after typing a message', async ({ page }) => {
    await page.getByLabel('Message input').fill('Hello!');
    await expect(page.getByRole('button', { name: 'Send message' })).toBeEnabled();
  });

  test('can type a message in the composition area', async ({ page }) => {
    const input = page.getByLabel('Message input');
    await input.fill('Test message');
    await expect(input).toHaveValue('Test message');
  });

  test('clicking send clears the input', async ({ page }) => {
    const input = page.getByLabel('Message input');
    await input.fill('Hello!');
    await page.getByRole('button', { name: 'Send message' }).click();

    await expect(input).toHaveValue('');
  });

  test('send button becomes disabled again after sending', async ({ page }) => {
    await page.getByLabel('Message input').fill('Hello!');
    await page.getByRole('button', { name: 'Send message' }).click();

    await expect(page.getByRole('button', { name: 'Send message' })).toBeDisabled();
  });

  test('pressing Enter submits the message', async ({ page }) => {
    const input = page.getByLabel('Message input');
    await input.fill('Keyboard send');
    await input.press('Enter');

    // Input should be cleared after submission.
    await expect(input).toHaveValue('');
  });

  test('pressing Shift+Enter does not submit the message', async ({ page }) => {
    const input = page.getByLabel('Message input');
    await input.fill('Line one');
    await input.press('Shift+Enter');

    // Input must still contain text — message was NOT sent.
    const value = await input.inputValue();
    expect(value).toContain('Line one');
  });
});
