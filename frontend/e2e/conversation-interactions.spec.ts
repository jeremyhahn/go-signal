import { test, expect } from './fixtures/registered';

/**
 * conversation-interactions.spec.ts
 *
 * Covers advanced conversation list interactions: hover states, avatar
 * consistency, focus management, and conversation item structure.
 */

test.describe('Conversation list — item structure', () => {
  test('each conversation item has a circular avatar', async ({ page }) => {
    const avatars = page.locator('.conv-avatar');
    await expect(avatars.first()).toBeVisible();

    // Avatar should show the first letter of the name.
    const text = await avatars.first().textContent();
    expect(text).toBe('A');
  });

  test('avatar colors are consistent for the same contact', async ({ page }) => {
    // Get Alice's avatar color class.
    const avatar = page.locator('.conversation-item').first().locator('.conv-avatar');
    const classes = await avatar.getAttribute('class');

    // Reload and check the same class is applied.
    await page.reload();
    const avatarAfter = page.locator('.conversation-item').first().locator('.conv-avatar');
    const classesAfter = await avatarAfter.getAttribute('class');

    expect(classes).toBe(classesAfter);
  });

  test('conversation items have role="button"', async ({ page }) => {
    const items = page.locator('.conversation-item');
    await expect(items.first()).toHaveAttribute('role', 'button');
  });

  test('conversation items have tabindex for keyboard access', async ({ page }) => {
    const items = page.locator('.conversation-item');
    await expect(items.first()).toHaveAttribute('tabindex', '0');
  });
});

test.describe('Conversation list — selection behavior', () => {
  test('selecting a conversation adds the active class', async ({ page }) => {
    const firstItem = page.locator('.conversation-item').first();
    await firstItem.click();

    await expect(firstItem).toHaveClass(/active/);
  });

  test('only one conversation can be active at a time', async ({ page }) => {
    // Click first conversation.
    await page.locator('.conversation-item').first().click();
    let activeCount = await page.locator('.conversation-item.active').count();
    expect(activeCount).toBe(1);

    // Click second conversation.
    await page.locator('.conversation-item').nth(1).click();
    activeCount = await page.locator('.conversation-item.active').count();
    expect(activeCount).toBe(1);

    // The second one should be active, not the first.
    const secondItem = page.locator('.conversation-item').nth(1);
    await expect(secondItem).toHaveClass(/active/);
  });

  test('conversation timestamp updates format based on day', async ({ page }) => {
    // Alice has a recent timestamp, Bob has an older one.
    const aliceTime = page.locator('.conversation-item').first().locator('.conv-time');
    const aliceText = await aliceTime.textContent();
    // Should be a time format like "12:30 PM".
    expect(aliceText).toMatch(/\d{1,2}:\d{2}/);
  });
});

test.describe('Conversation list — conversation count', () => {
  test('renders the correct number of conversations', async ({ page }) => {
    const items = page.locator('.conversation-item');
    await expect(items).toHaveCount(2);
  });

  test('conversations without unread counts have no badge', async ({ page }) => {
    // Bob has unreadCount: 0 — should have no badge.
    const bobItem = page.locator('.conversation-item').nth(1);
    await expect(bobItem.locator('.badge')).not.toBeVisible();
  });
});
