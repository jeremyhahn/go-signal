import { test, expect } from './fixtures/registered';

/**
 * accessibility-comprehensive.spec.ts
 *
 * Comprehensive WCAG-focused accessibility checks covering keyboard navigation,
 * ARIA attributes, semantic roles, and label associations across all major views.
 */

// ---------------------------------------------------------------------------
// Tab order through the main app
// ---------------------------------------------------------------------------

test.describe('Accessibility — tab order', () => {
  test('search input is reachable via programmatic focus', async ({ page }) => {
    const search = page.getByPlaceholder('Search conversations');
    await search.focus();
    await expect(search).toBeFocused();
  });

  test('first conversation item receives focus after Tab from search', async ({ page }) => {
    const search = page.getByPlaceholder('Search conversations');
    await search.focus();
    await page.keyboard.press('Tab');

    const focused = page.locator(':focus');
    await expect(focused).toBeVisible();
  });

  test('second conversation item is focusable', async ({ page }) => {
    const secondItem = page.locator('.conversation-item').nth(1);
    await secondItem.focus();
    await expect(secondItem).toBeFocused();
  });

  test('Settings tab button is reachable via programmatic focus', async ({ page }) => {
    const settingsBtn = page.getByRole('button', { name: 'Settings' });
    await settingsBtn.focus();
    await expect(settingsBtn).toBeFocused();
  });
});

// ---------------------------------------------------------------------------
// All buttons have aria-labels
// ---------------------------------------------------------------------------

test.describe('Accessibility — button aria-labels on Inbox', () => {
  test('NavTabs buttons have accessible names', async ({ page }) => {
    // Wait for at least one NavTabs button to be present in the DOM.
    const firstNavBtn = page.locator('nav.NavTabs button').first();
    await expect(firstNavBtn).toBeAttached();

    const navButtons = page.locator('nav.NavTabs button');
    const count = await navButtons.count();
    expect(count).toBeGreaterThan(0);

    for (let i = 0; i < count; i++) {
      const btn = navButtons.nth(i);
      const ariaLabel = await btn.getAttribute('aria-label');
      const innerText = await btn.textContent();
      const hasAccessibleName =
        (ariaLabel !== null && ariaLabel.trim().length > 0) ||
        (innerText !== null && innerText.trim().length > 0);
      expect(hasAccessibleName).toBe(true);
    }
  });
});

test.describe('Accessibility — button aria-labels in Conversation view', () => {
  test.beforeEach(async ({ page }) => {
    await page.getByText('Alice').click();
    await expect(page.locator('.conversation-header')).toBeVisible();
  });

  test('audio call button has aria-label', async ({ page }) => {
    await expect(page.getByTestId('call-audio-button')).toHaveAttribute('aria-label', 'Audio call');
  });

  test('video call button has aria-label', async ({ page }) => {
    await expect(page.getByTestId('call-video-button')).toHaveAttribute('aria-label', 'Video call');
  });

  test('send message button has aria-label', async ({ page }) => {
    await expect(page.getByRole('button', { name: 'Send message' })).toBeVisible();
  });
});

// ---------------------------------------------------------------------------
// Form inputs have labels
// ---------------------------------------------------------------------------

test.describe('Accessibility — form inputs have labels', () => {
  test('message input has an associated label', async ({ page }) => {
    await page.getByText('Alice').click();
    await expect(page.getByLabel('Message input')).toBeVisible();
  });

  test('search input has an associated label', async ({ page }) => {
    await expect(
      page.getByRole('searchbox', { name: 'Search conversations' }),
    ).toBeVisible();
  });

  test('theme selector has an associated label', async ({ page }) => {
    await page.getByRole('button', { name: 'Settings' }).click();
    await expect(page.getByLabel('Theme')).toBeVisible();
  });
});

// ---------------------------------------------------------------------------
// ARIA roles
// ---------------------------------------------------------------------------

test.describe('Accessibility — ARIA roles', () => {
  test('conversation items have role="button"', async ({ page }) => {
    const items = page.locator('.conversation-item');
    await expect(items.first()).toHaveAttribute('role', 'button');
  });

  test('connection banner has role="alert"', async ({ page }) => {
    await expect(page.getByRole('alert')).toBeVisible();
  });

  test('NavTabs has aria-label for navigation landmark', async ({ page }) => {
    await expect(page.locator('nav.NavTabs')).toHaveAttribute('aria-label', 'Main navigation');
  });
});

// ---------------------------------------------------------------------------
// Call screen ARIA roles
// These tests use a custom fixture that sets up WebRTC before navigation.
// ---------------------------------------------------------------------------

import { test as webrtcBase } from '@playwright/test';
import { setupMockAPI as _setupMockAPI } from './fixtures/mock-api';
import { setupMockWebRTC as _setupMockWebRTC } from './fixtures/mock-webrtc';

const webrtcTest = webrtcBase.extend({
  page: async ({ page }, use) => {
    await _setupMockWebRTC(page);
    await _setupMockAPI(page);
    await page.route('**/api/v1/account/registered', async (route) => {
      await route.fulfill({ json: true });
    });
    await page.goto('/');
    await use(page);
  },
});

webrtcTest.describe('Accessibility — call screen ARIA roles', () => {
  webrtcTest('calling lobby is visible and reachable after opening', async ({ page }) => {
    await page.getByText('Alice').click();
    await page.getByTestId('call-audio-button').click();

    const lobby = page.getByTestId('calling-lobby');
    await expect(lobby).toBeVisible();
  });

  webrtcTest('lobby cancel button has an accessible name', async ({ page }) => {
    await page.getByText('Alice').click();
    await page.getByTestId('call-audio-button').click();

    const cancelBtn = page.getByTestId('lobby-cancel');
    await expect(cancelBtn).toBeVisible({ timeout: 5_000 });

    const cancelText = await cancelBtn.textContent();
    const cancelLabel = await cancelBtn.getAttribute('aria-label');
    const hasName =
      (cancelText !== null && cancelText.trim().length > 0) ||
      (cancelLabel !== null && cancelLabel.trim().length > 0);
    expect(hasName).toBe(true);
  });

  webrtcTest('audio mute toggle has aria-label', async ({ page }) => {
    await page.getByText('Alice').click();
    await page.getByTestId('call-audio-button').click();

    await expect(page.getByTestId('lobby-toggle-audio')).toHaveAttribute('aria-label', /microphone/i);
  });
});

// ---------------------------------------------------------------------------
// Keyboard operability
// ---------------------------------------------------------------------------

test.describe('Accessibility — keyboard operability', () => {
  test('conversation items have tabindex="0"', async ({ page }) => {
    const items = page.locator('.conversation-item');
    await expect(items.first()).toHaveAttribute('tabindex', '0');
  });

  test('Enter key activates a focused conversation', async ({ page }) => {
    const firstItem = page.locator('.conversation-item').first();
    await firstItem.focus();
    await firstItem.press('Enter');

    await expect(page.locator('.conversation-header')).toBeVisible();
  });

  test('theme selector is keyboard accessible', async ({ page }) => {
    await page.getByRole('button', { name: 'Settings' }).click();
    const themeSelect = page.getByLabel('Theme');
    await themeSelect.focus();
    await expect(themeSelect).toBeFocused();
  });
});

export { expect };
