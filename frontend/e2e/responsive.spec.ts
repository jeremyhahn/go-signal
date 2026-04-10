import { test as base, expect } from '@playwright/test';
import { setupMockAPI } from './fixtures/mock-api';

/**
 * responsive.spec.ts
 *
 * Verifies that the application renders without layout breakage at standard
 * viewport widths covering mobile, tablet, and desktop breakpoints.
 *
 * Each test sets viewport size before navigating so the layout is computed
 * at the target dimensions from the first paint.
 */

const test = base.extend({
  page: async ({ page }, use) => {
    await setupMockAPI(page);
    await page.route('**/api/v1/account/registered', async (route) => {
      await route.fulfill({ json: true });
    });
    await use(page);
  },
});

// ---------------------------------------------------------------------------
// Desktop viewport (1920 × 1080)
// ---------------------------------------------------------------------------

test.describe('Responsive — desktop (1920px)', () => {
  test.beforeEach(async ({ page }) => {
    await page.setViewportSize({ width: 1920, height: 1080 });
    await page.goto('/');
  });

  test('app renders at 1920px width without a white screen', async ({ page }) => {
    const rootContent = await page.locator('#root').innerHTML();
    expect(rootContent.length).toBeGreaterThan(0);
  });

  test('conversation list is visible at 1920px', async ({ page }) => {
    await expect(page.locator('.conversation-list')).toBeVisible();
  });

  test('search input is visible at 1920px', async ({ page }) => {
    await expect(page.getByPlaceholder('Search conversations')).toBeVisible();
  });

  test('NavTabs is visible at 1920px', async ({ page }) => {
    await expect(page.locator('nav.NavTabs')).toBeVisible();
  });
});

// ---------------------------------------------------------------------------
// Tablet viewport (768 × 1024)
// ---------------------------------------------------------------------------

test.describe('Responsive — tablet (768px)', () => {
  test.beforeEach(async ({ page }) => {
    await page.setViewportSize({ width: 768, height: 1024 });
    await page.goto('/');
  });

  test('app renders at 768px width without a white screen', async ({ page }) => {
    const rootContent = await page.locator('#root').innerHTML();
    expect(rootContent.length).toBeGreaterThan(0);
  });

  test('conversation list is visible at 768px', async ({ page }) => {
    await expect(page.locator('.conversation-list')).toBeVisible();
  });

  test('NavTabs is visible at 768px', async ({ page }) => {
    await expect(page.locator('nav.NavTabs')).toBeVisible();
  });

  test('NavTabs does not overflow the viewport at 768px', async ({ page }) => {
    const nav = page.locator('nav.NavTabs');
    await expect(nav).toBeVisible();

    const navBox = await nav.boundingBox();
    expect(navBox).not.toBeNull();
    if (navBox) {
      // NavTabs must fit within the 768px viewport width.
      expect(navBox.x + navBox.width).toBeLessThanOrEqual(768);
    }
  });
});

// ---------------------------------------------------------------------------
// Mobile viewport (480 × 812)
// ---------------------------------------------------------------------------

test.describe('Responsive — mobile (480px)', () => {
  test.beforeEach(async ({ page }) => {
    await page.setViewportSize({ width: 480, height: 812 });
    await page.goto('/');
  });

  test('app renders at 480px width without a white screen', async ({ page }) => {
    const rootContent = await page.locator('#root').innerHTML();
    expect(rootContent.length).toBeGreaterThan(0);
  });

  test('NavTabs does not overflow the 480px viewport when visible', async ({ page }) => {
    const nav = page.locator('nav.NavTabs');

    // On mobile the nav may be hidden by CSS (collapsed menu pattern).
    // If it is present and visible, it must not overflow the viewport.
    const isVisible = await nav.isVisible();
    if (isVisible) {
      const navBox = await nav.boundingBox();
      expect(navBox).not.toBeNull();
      if (navBox) {
        expect(navBox.x + navBox.width).toBeLessThanOrEqual(480);
      }
    } else {
      // Nav is intentionally hidden at this breakpoint — that is valid.
      expect(isVisible).toBe(false);
    }
  });

  test('app body does not have a horizontal scrollbar at 480px', async ({ page }) => {
    const scrollWidth = await page.evaluate(() => document.body.scrollWidth);
    const clientWidth = await page.evaluate(() => document.body.clientWidth);
    // Allow at most 1px tolerance for sub-pixel rounding.
    expect(scrollWidth).toBeLessThanOrEqual(clientWidth + 1);
  });
});

// ---------------------------------------------------------------------------
// Default viewport — conversation list presence
// ---------------------------------------------------------------------------

test.describe('Responsive — default viewport', () => {
  test('conversation list is visible at default width', async ({ page }) => {
    await page.goto('/');
    await expect(page.locator('.conversation-list')).toBeVisible();
  });

  test('NavTabs is visible at default width', async ({ page }) => {
    await page.goto('/');
    await expect(page.locator('nav.NavTabs')).toBeVisible();
  });
});

export { expect };
