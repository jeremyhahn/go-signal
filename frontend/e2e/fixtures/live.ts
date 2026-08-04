import { test as base, type WebSocketRoute } from '@playwright/test';
import { setupMockAPI } from './mock-api';
import { setupMockWebRTC } from './mock-webrtc';

/**
 * live.ts provides a fully-registered page whose WebSocket event channel
 * (/api/v1/events) is intercepted by a mock server. Unlike setupMockAPI —
 * which aborts the WebSocket upgrade and leaves the app permanently
 * "Connecting..." — this fixture establishes a live mock socket so that the
 * connected state, real-time message delivery, incoming calls, call-signal
 * answers, and remote hangups can all be exercised deterministically.
 *
 * The `ws` fixture exposes:
 *   - connected:  resolves once the app has opened the WebSocket
 *   - send(type, payload):  pushes a server event to the page, matching the
 *     WebAdapter wire protocol of { type, payload }
 *
 * Recognised event types (see WebAdapter.wsEventDispatch):
 *   signal:message:received | signal:typing | signal:call:incoming |
 *   signal:call:signal | signal:call:ended
 */
export interface WSController {
  connected: Promise<void>;
  send(type: string, payload: unknown): void;
}

interface LiveFixtures {
  ws: WSController;
}

export const test = base.extend<LiveFixtures>({
  ws: async ({ page }, use) => {
    // Mocks must be installed before navigation so routes are in place.
    await setupMockWebRTC(page);
    await setupMockAPI(page);
    await page.route('**/api/v1/account/registered', async (route) => {
      await route.fulfill({ json: true });
    });

    let routeHandle: WebSocketRoute | null = null;
    let resolveConnected!: () => void;
    const connected = new Promise<void>((resolve) => {
      resolveConnected = resolve;
    });

    // Intercept the WebSocket in mock mode (no connectToServer) so the page's
    // socket opens against us and we control every server-pushed frame.
    await page.routeWebSocket('**/api/v1/events', (ws) => {
      routeHandle = ws;
      // Ignore client -> server frames; the app only sends keepalives, if any.
      ws.onMessage(() => {});
      resolveConnected();
    });

    await page.goto('/');

    const controller: WSController = {
      connected,
      send(type: string, payload: unknown) {
        if (!routeHandle) {
          throw new Error('WebSocket not yet established; await ws.connected first');
        }
        routeHandle.send(JSON.stringify({ type, payload }));
      },
    };

    await use(controller);
  },
});

export { expect } from '@playwright/test';
