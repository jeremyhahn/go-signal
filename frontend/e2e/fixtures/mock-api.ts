import { Page } from '@playwright/test';

/**
 * setupMockAPI intercepts all /api/v1/* calls made by WebAdapter so tests
 * run against the Vite dev server with no Go backend required.
 *
 * Registration state is tracked within a single page session; each test
 * should call this from a fresh page to guarantee isolation.
 */
export async function setupMockAPI(page: Page): Promise<void> {
  let registered = false;
  const sessionId = 'test-session-id';

  // --- Account ---

  await page.route('**/api/v1/account/registered', async (route) => {
    await route.fulfill({ json: registered });
  });

  await page.route('**/api/v1/account/verify/session', async (route) => {
    await route.fulfill({ json: { id: sessionId } });
  });

  await page.route('**/api/v1/account/verify/code', async (route) => {
    await route.fulfill({ status: 200, json: {} });
  });

  await page.route('**/api/v1/account/verify/submit', async (route) => {
    await route.fulfill({ json: { id: sessionId, verified: true } });
  });

  await page.route('**/api/v1/account/register', async (route) => {
    registered = true;
    await route.fulfill({
      json: {
        number: '+15555550100',
        uuid: 'test-uuid-1234',
        deviceId: 1,
      },
    });
  });

  await page.route('**/api/v1/account/whoami', async (route) => {
    if (!registered) {
      await route.fulfill({ status: 401, json: { error: 'not registered' } });
      return;
    }
    await route.fulfill({
      json: {
        number: '+15555550100',
        uuid: 'test-uuid-1234',
        deviceId: 1,
      },
    });
  });

  // --- Conversations ---

  await page.route('**/api/v1/conversations', async (route) => {
    await route.fulfill({
      json: [
        {
          id: 1,
          conversationId: 'conv-1',
          type: 1,
          name: 'Alice',
          unreadCount: 2,
          lastMessageTimestamp: Date.now(),
          lastMessageBody: 'Hey there!',
          isPinned: false,
          isArchived: false,
        },
        {
          id: 2,
          conversationId: 'conv-2',
          type: 1,
          name: 'Bob',
          unreadCount: 0,
          lastMessageTimestamp: Date.now() - 3_600_000,
          lastMessageBody: 'See you later',
          isPinned: false,
          isArchived: false,
        },
      ],
    });
  });

  // --- Messages ---

  await page.route('**/api/v1/messages?*', async (route) => {
    await route.fulfill({
      json: [
        {
          id: 1,
          guid: 'msg-1',
          conversationId: 'conv-1',
          sourceUuid: 'alice-uuid',
          timestamp: Date.now() - 60_000,
          type: 1,
          body: 'Hey there!',
          isRead: true,
          sendState: 2,
        },
        {
          id: 2,
          guid: 'msg-2',
          conversationId: 'conv-1',
          sourceUuid: 'test-uuid-1234',
          timestamp: Date.now(),
          type: 2,
          body: 'Hi Alice!',
          isRead: true,
          sendState: 2,
        },
      ],
    });
  });

  await page.route('**/api/v1/messages/send', async (route) => {
    await route.fulfill({ json: { timestamp: Date.now(), needsSync: false } });
  });

  // --- Contacts ---

  await page.route('**/api/v1/contacts', async (route) => {
    await route.fulfill({
      json: [
        {
          uuid: 'alice-uuid',
          e164: '+15555550101',
          givenName: 'Alice',
          familyName: 'Smith',
          isBlocked: false,
        },
        {
          uuid: 'bob-uuid',
          e164: '+15555550102',
          givenName: 'Bob',
          familyName: 'Jones',
          isBlocked: false,
        },
      ],
    });
  });

  // --- Calling ---

  await page.route('**/v2/calling/relays', async (route) => {
    await route.fulfill({
      json: {
        relays: [
          {
            username: 'test-user',
            password: 'test-pass',
            ttl: 3600,
            urls: ['stun:stun.test:3478'],
          },
        ],
      },
    });
  });

  await page.route('**/api/v1/call/offer', async (route) => {
    await route.fulfill({ status: 204 });
  });

  await page.route('**/api/v1/call/answer', async (route) => {
    await route.fulfill({ status: 204 });
  });

  await page.route('**/api/v1/call/ice', async (route) => {
    await route.fulfill({ status: 204 });
  });

  await page.route('**/api/v1/call/hangup', async (route) => {
    await route.fulfill({ status: 204 });
  });

  // --- WebSocket events ---
  // Playwright does not natively intercept WebSocket upgrades via page.route,
  // but aborting the HTTP upgrade request causes the browser to fail the WS
  // connection immediately rather than hanging, which is sufficient for tests
  // that do not exercise real-time events.
  await page.route('**/api/v1/events', async (route) => {
    await route.abort();
  });
}
