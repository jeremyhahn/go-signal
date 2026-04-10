import { test as base, expect } from '@playwright/test';
import { setupMockAPI } from './fixtures/mock-api';
import { setupMockWebRTC } from './fixtures/mock-webrtc';

/**
 * calling.spec.ts
 *
 * Covers the 1:1 audio/video calling feature: call buttons, CallingLobby,
 * CallScreen, IncomingCallBar, CallControls, and the full call lifecycle.
 *
 * Uses mocked WebRTC (RTCPeerConnection, getUserMedia) to run in headless.
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

test.describe('Calling — header buttons', () => {
  test.beforeEach(async ({ page }) => {
    await page.getByText('Alice').click();
    await expect(page.locator('.conversation-header')).toBeVisible();
  });

  test('shows audio call button in conversation header', async ({ page }) => {
    await expect(page.getByTestId('call-audio-button')).toBeVisible();
  });

  test('shows video call button in conversation header', async ({ page }) => {
    await expect(page.getByTestId('call-video-button')).toBeVisible();
  });

  test('audio call button has correct aria-label', async ({ page }) => {
    await expect(page.getByTestId('call-audio-button')).toHaveAttribute('aria-label', 'Audio call');
  });

  test('video call button has correct aria-label', async ({ page }) => {
    await expect(page.getByTestId('call-video-button')).toHaveAttribute('aria-label', 'Video call');
  });
});

test.describe('Calling — lobby (audio)', () => {
  test.beforeEach(async ({ page }) => {
    await page.getByText('Alice').click();
    await page.getByTestId('call-audio-button').click();
  });

  test('clicking audio call opens CallingLobby', async ({ page }) => {
    await expect(page.getByTestId('calling-lobby')).toBeVisible();
  });

  test('CallingLobby shows peer name', async ({ page }) => {
    await expect(page.getByText('Audio call with Alice')).toBeVisible();
  });

  test('CallingLobby shows Start Call button', async ({ page }) => {
    await expect(page.getByTestId('lobby-start-call')).toBeVisible();
  });

  test('CallingLobby shows Cancel button', async ({ page }) => {
    await expect(page.getByTestId('lobby-cancel')).toBeVisible();
  });

  test('CallingLobby shows audio mute toggle', async ({ page }) => {
    await expect(page.getByTestId('lobby-toggle-audio')).toBeVisible();
  });

  test('clicking Cancel closes the lobby', async ({ page }) => {
    await page.getByTestId('lobby-cancel').click();
    await expect(page.getByTestId('calling-lobby')).not.toBeVisible();
  });
});

test.describe('Calling — lobby (video)', () => {
  test.beforeEach(async ({ page }) => {
    await page.getByText('Alice').click();
    await page.getByTestId('call-video-button').click();
  });

  test('video lobby shows video preview', async ({ page }) => {
    await expect(page.getByTestId('lobby-video-preview')).toBeVisible();
  });

  test('video lobby shows video toggle', async ({ page }) => {
    await expect(page.getByTestId('lobby-toggle-video')).toBeVisible();
  });
});

test.describe('Calling — start call', () => {
  test('clicking Start Call transitions to ringing state', async ({ page }) => {
    await page.getByText('Alice').click();
    await page.getByTestId('call-audio-button').click();
    await expect(page.getByTestId('calling-lobby')).toBeVisible();

    // Wait for mock getUserMedia to resolve (Start Call should become enabled).
    await expect(page.getByTestId('lobby-start-call')).toBeEnabled({ timeout: 5000 });
    await page.getByTestId('lobby-start-call').click();

    // Should transition from lobby to call screen.
    await expect(page.getByTestId('call-screen')).toBeVisible({ timeout: 5000 });
    await expect(page.getByTestId('call-status')).toContainText('Ringing');
  });

  test('call screen shows hangup button', async ({ page }) => {
    await page.getByText('Alice').click();
    await page.getByTestId('call-audio-button').click();
    await expect(page.getByTestId('lobby-start-call')).toBeEnabled({ timeout: 5000 });
    await page.getByTestId('lobby-start-call').click();

    await expect(page.getByTestId('call-hangup')).toBeVisible({ timeout: 5000 });
  });

  test('clicking hangup ends the call', async ({ page }) => {
    await page.getByText('Alice').click();
    await page.getByTestId('call-audio-button').click();
    await expect(page.getByTestId('lobby-start-call')).toBeEnabled({ timeout: 5000 });
    await page.getByTestId('lobby-start-call').click();
    await expect(page.getByTestId('call-hangup')).toBeVisible({ timeout: 5000 });

    await page.getByTestId('call-hangup').click();

    // Call screen should disappear.
    await expect(page.getByTestId('call-screen')).not.toBeVisible({ timeout: 5000 });
  });
});

test.describe('Calling — audio/video toggles', () => {
  test('audio mute toggle in lobby changes button state', async ({ page }) => {
    await page.getByText('Alice').click();
    await page.getByTestId('call-audio-button').click();
    await expect(page.getByTestId('lobby-toggle-audio')).toBeVisible();

    const toggleBtn = page.getByTestId('lobby-toggle-audio');

    // Initially unmuted.
    await expect(toggleBtn).toHaveAttribute('aria-label', 'Mute microphone');

    // Click to mute.
    await toggleBtn.click();
    await expect(toggleBtn).toHaveAttribute('aria-label', 'Unmute microphone');

    // Click to unmute.
    await toggleBtn.click();
    await expect(toggleBtn).toHaveAttribute('aria-label', 'Mute microphone');
  });
});

test.describe('Calling — call buttons hidden during active call', () => {
  test('call buttons are hidden when a call is active', async ({ page }) => {
    await page.getByText('Alice').click();
    await expect(page.getByTestId('call-audio-button')).toBeVisible();

    // Start a call.
    await page.getByTestId('call-audio-button').click();
    await expect(page.getByTestId('lobby-start-call')).toBeEnabled({ timeout: 5000 });
    await page.getByTestId('lobby-start-call').click();

    // Call buttons should be hidden during active call.
    await expect(page.getByTestId('call-audio-button')).not.toBeVisible();
    await expect(page.getByTestId('call-video-button')).not.toBeVisible();
  });
});

export { expect };
