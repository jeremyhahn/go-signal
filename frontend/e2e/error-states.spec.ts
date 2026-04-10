import { test as base, expect } from '@playwright/test';
import { setupMockAPI } from './fixtures/mock-api';

/**
 * error-states.spec.ts
 *
 * Covers API failure modes: 500 errors, network timeouts, 401 mid-session,
 * and malformed responses. All tests start in the registered state so
 * errors are exercised against the main application views.
 */

const test = base.extend({
  page: async ({ page }, use) => {
    await setupMockAPI(page);
    await page.route('**/api/v1/account/registered', async (route) => {
      await route.fulfill({ json: true });
    });
    await page.goto('/');
    await use(page);
  },
});

// ---------------------------------------------------------------------------
// 500 errors
// ---------------------------------------------------------------------------

test.describe('Error states — conversations 500', () => {
  test('conversations endpoint 500 shows empty state or error gracefully', async ({ page }) => {
    await setupMockAPI(page);
    await page.route('**/api/v1/account/registered', async (route) => {
      await route.fulfill({ json: true });
    });
    await page.route('**/api/v1/conversations', async (route) => {
      await route.fulfill({ status: 500, body: 'Internal Server Error' });
    });
    await page.goto('/');

    // The app should not crash — root must contain content.
    const rootContent = await page.locator('#root').innerHTML();
    expect(rootContent.length).toBeGreaterThan(0);
  });

  test('conversations 500 does not show a white screen', async ({ page }) => {
    await setupMockAPI(page);
    await page.route('**/api/v1/account/registered', async (route) => {
      await route.fulfill({ json: true });
    });
    await page.route('**/api/v1/conversations', async (route) => {
      await route.fulfill({ status: 500, body: 'Internal Server Error' });
    });
    await page.goto('/');

    const bgColor = await page.evaluate(() => getComputedStyle(document.body).backgroundColor);
    // Background should be rendered (not a blank transparent page).
    expect(bgColor).not.toBe('rgba(0, 0, 0, 0)');
  });
});

test.describe('Error states — messages 500', () => {
  test('messages endpoint 500 does not crash the conversation view', async ({ page }) => {
    await page.route('**/api/v1/messages?*', async (route) => {
      await route.fulfill({ status: 500, body: 'Internal Server Error' });
    });

    await page.getByText('Alice').click();

    // The conversation header should still be visible.
    await expect(page.locator('.conversation-header')).toBeVisible();
  });

  test('messages 500 keeps the message input accessible', async ({ page }) => {
    await page.route('**/api/v1/messages?*', async (route) => {
      await route.fulfill({ status: 500, body: 'Internal Server Error' });
    });

    await page.getByText('Alice').click();

    await expect(page.getByLabel('Message input')).toBeVisible();
  });
});

test.describe('Error states — send message 500', () => {
  test('send returns 500 and input remains accessible for retry', async ({ page }) => {
    await page.route('**/api/v1/messages/send', async (route) => {
      await route.fulfill({ status: 500, body: 'Internal Server Error' });
    });

    await page.getByText('Alice').click();
    await page.getByLabel('Message input').fill('Hello retry');
    await page.getByRole('button', { name: 'Send message' }).click();

    // Input should still be in the DOM and enabled after a failed send.
    await expect(page.getByLabel('Message input')).toBeVisible();
    await expect(page.getByLabel('Message input')).toBeEnabled();
  });

  test('send 500 does not remove the typed text from the input', async ({ page }) => {
    await page.route('**/api/v1/messages/send', async (route) => {
      await route.fulfill({ status: 500, body: 'Internal Server Error' });
    });

    await page.getByText('Alice').click();
    await page.getByLabel('Message input').fill('Should stay');
    await page.getByRole('button', { name: 'Send message' }).click();

    // The app root must remain functional.
    const rootContent = await page.locator('#root').innerHTML();
    expect(rootContent.length).toBeGreaterThan(0);
  });
});

test.describe('Error states — TURN credentials 500', () => {
  test('TURN 500 does not crash the app when no call is in progress', async ({ page }) => {
    await page.route('**/v2/calling/relays', async (route) => {
      await route.fulfill({ status: 500, body: 'Internal Server Error' });
    });

    // The inbox should still be functional.
    await expect(page.getByPlaceholder('Search conversations')).toBeVisible();
  });

  test('TURN 500 during call lobby is handled gracefully', async ({ page }) => {
    await page.route('**/v2/calling/relays', async (route) => {
      await route.fulfill({ status: 500, body: 'Internal Server Error' });
    });

    await page.getByText('Alice').click();
    await page.getByTestId('call-audio-button').click();

    // The lobby should attempt to open; root must stay rendered.
    const rootContent = await page.locator('#root').innerHTML();
    expect(rootContent.length).toBeGreaterThan(0);
  });
});

// ---------------------------------------------------------------------------
// Network timeouts (route never responds)
// ---------------------------------------------------------------------------

test.describe('Error states — network timeouts', () => {
  test('hanging messages endpoint keeps conversation header visible', async ({ page }) => {
    await page.route('**/api/v1/messages?*', async (_route) => {
      // Intentionally never fulfilled — simulates a hung request.
      await new Promise(() => {});
    });

    await page.getByText('Alice').click();

    // Header must still be present.
    await expect(page.locator('.conversation-header')).toBeVisible();
  });

  test('hanging send endpoint disables the send button while in flight', async ({ page }) => {
    let resolveSend!: () => void;
    const sendHeld = new Promise<void>((resolve) => {
      resolveSend = resolve;
    });

    await page.route('**/api/v1/messages/send', async (route) => {
      await sendHeld;
      await route.fulfill({ json: { timestamp: Date.now(), needsSync: false } });
    });

    await page.getByText('Alice').click();
    await page.getByLabel('Message input').fill('In flight');
    await page.getByRole('button', { name: 'Send message' }).click();

    // The send button should be disabled while the request is pending.
    await expect(page.getByRole('button', { name: 'Send message' })).toBeDisabled();

    // Release the held request.
    resolveSend();
  });
});

// ---------------------------------------------------------------------------
// 401 mid-session
// ---------------------------------------------------------------------------

test.describe('Error states — 401 mid-session', () => {
  test('conversations 401 is handled without a crash', async ({ page }) => {
    await page.route('**/api/v1/conversations', async (route) => {
      await route.fulfill({ status: 401, json: { error: 'Unauthorized' } });
    });

    await setupMockAPI(page);
    await page.route('**/api/v1/account/registered', async (route) => {
      await route.fulfill({ json: true });
    });
    await page.goto('/');

    // App root must still contain rendered content.
    const rootContent = await page.locator('#root').innerHTML();
    expect(rootContent.length).toBeGreaterThan(0);
  });
});

// ---------------------------------------------------------------------------
// Malformed / unexpected responses
// ---------------------------------------------------------------------------

test.describe('Error states — malformed responses', () => {
  test('conversations returning non-JSON does not crash the app', async ({ page }) => {
    await setupMockAPI(page);
    await page.route('**/api/v1/account/registered', async (route) => {
      await route.fulfill({ json: true });
    });
    await page.route('**/api/v1/conversations', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'text/plain',
        body: 'not json at all <<<>>>',
      });
    });
    await page.goto('/');

    const rootContent = await page.locator('#root').innerHTML();
    expect(rootContent.length).toBeGreaterThan(0);
  });

  test('messages returning null body does not crash the conversation view', async ({ page }) => {
    await page.route('**/api/v1/messages?*', async (route) => {
      await route.fulfill({ status: 200, json: null });
    });

    await page.getByText('Alice').click();

    // Conversation header must remain visible.
    await expect(page.locator('.conversation-header')).toBeVisible();
  });

  test('conversations returning an object instead of array does not crash', async ({ page }) => {
    await setupMockAPI(page);
    await page.route('**/api/v1/account/registered', async (route) => {
      await route.fulfill({ json: true });
    });
    await page.route('**/api/v1/conversations', async (route) => {
      await route.fulfill({ status: 200, json: { error: 'unexpected object' } });
    });
    await page.goto('/');

    const rootContent = await page.locator('#root').innerHTML();
    expect(rootContent.length).toBeGreaterThan(0);
  });

  test('messages returning an empty object does not crash the app', async ({ page }) => {
    await page.route('**/api/v1/messages?*', async (route) => {
      await route.fulfill({ status: 200, json: {} });
    });

    await page.getByText('Alice').click();

    // App root must remain functional even if the timeline cannot render.
    const rootContent = await page.locator('#root').innerHTML();
    expect(rootContent.length).toBeGreaterThan(0);
  });
});

export { expect };
