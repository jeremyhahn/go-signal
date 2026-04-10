import type {
  ISignalClient,
  Account,
  Message,
  Conversation,
  Contact,
  SendResult,
  VerificationSession,
  UnsubscribeFn,
  TurnCredentials,
  IncomingCallData,
  CallSignalData,
} from './ISignalClient';

// WebAdapter implements ISignalClient by calling REST endpoints + WebSocket.
// Used when the React app is served by signald as a web UI.
export class WebAdapter implements ISignalClient {
  private baseURL: string;
  private ws: WebSocket | null = null;
  private messageHandlers: Set<(msg: Message) => void> = new Set();
  private typingHandlers: Set<(data: any) => void> = new Set();
  private connectionHandlers: Set<(connected: boolean) => void> = new Set();
  private incomingCallHandlers: Set<(data: IncomingCallData) => void> = new Set();
  private callSignalHandlers: Set<(signal: CallSignalData) => void> = new Set();
  private callEndedHandlers: Set<(data: { callId: string; reason: string }) => void> = new Set();

  constructor(baseURL: string) {
    this.baseURL = baseURL.replace(/\/$/, '');
  }

  private async fetch<T>(path: string, init?: RequestInit): Promise<T> {
    const res = await fetch(`${this.baseURL}${path}`, {
      ...init,
      headers: { 'Content-Type': 'application/json', ...init?.headers },
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}: ${await res.text()}`);
    const contentType = res.headers.get('content-type') || '';
    if (!contentType.includes('application/json')) {
      throw new Error(`Expected JSON response but got ${contentType}`);
    }
    return res.json();
  }

  private async fetchNoContent(path: string, init?: RequestInit): Promise<void> {
    const res = await fetch(`${this.baseURL}${path}`, {
      ...init,
      headers: { 'Content-Type': 'application/json', ...init?.headers },
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}: ${await res.text()}`);
  }

  // --- Account ---

  async isRegistered(): Promise<boolean> {
    try {
      return await this.fetch('/api/v1/account/registered');
    } catch {
      return false;
    }
  }

  async createVerificationSession(number: string): Promise<VerificationSession> {
    return this.fetch('/api/v1/account/verify/session', {
      method: 'POST',
      body: JSON.stringify({ number }),
    });
  }

  async requestVerificationCode(sessionId: string): Promise<void> {
    await this.fetch('/api/v1/account/verify/code', {
      method: 'POST',
      body: JSON.stringify({ sessionId }),
    });
  }

  async submitVerificationCode(sessionId: string, code: string): Promise<VerificationSession> {
    return this.fetch('/api/v1/account/verify/submit', {
      method: 'POST',
      body: JSON.stringify({ sessionId, code }),
    });
  }

  async register(number: string, sessionId: string): Promise<Account> {
    return this.fetch('/api/v1/account/register', {
      method: 'POST',
      body: JSON.stringify({ number, sessionId }),
    });
  }

  async whoAmI(): Promise<Account> {
    return this.fetch('/api/v1/account/whoami');
  }

  // --- Messaging ---

  async sendMessage(recipient: string, text: string): Promise<SendResult> {
    return this.fetch('/api/v1/messages/send', {
      method: 'POST',
      body: JSON.stringify({ recipient, text }),
    });
  }

  async getMessages(conversationId: string, limit: number, before?: number): Promise<Message[]> {
    const params = new URLSearchParams({ conversationId, limit: String(limit) });
    if (before) params.set('before', String(before));
    return this.fetch(`/api/v1/messages?${params}`);
  }

  async getConversations(): Promise<Conversation[]> {
    return this.fetch('/api/v1/conversations');
  }

  // --- Contacts ---

  async listContacts(): Promise<Contact[]> {
    return this.fetch('/api/v1/contacts');
  }

  // --- Calling ---

  async sendCallSignal(signal: { type: string; callId: string; callerUuid?: string; calleeUuid: string; callType: string; payload: unknown }): Promise<void> {
    const endpointMap: Record<string, string> = {
      offer: '/api/v1/call/offer',
      answer: '/api/v1/call/answer',
      ice: '/api/v1/call/ice',
      hangup: '/api/v1/call/hangup',
    };
    const endpoint = endpointMap[signal.type];
    if (!endpoint) throw new Error(`Unknown call signal type: ${signal.type}`);
    await this.fetchNoContent(endpoint, {
      method: 'POST',
      body: JSON.stringify(signal),
    });
  }

  async getTurnCredentials(): Promise<TurnCredentials> {
    return this.fetch('/v2/calling/relays');
  }

  // --- Events ---

  onMessage(handler: (msg: Message) => void): UnsubscribeFn {
    this.messageHandlers.add(handler);
    this.ensureWebSocket();
    return () => this.messageHandlers.delete(handler);
  }

  onTyping(handler: (data: any) => void): UnsubscribeFn {
    this.typingHandlers.add(handler);
    this.ensureWebSocket();
    return () => this.typingHandlers.delete(handler);
  }

  onConnectionStatus(handler: (connected: boolean) => void): UnsubscribeFn {
    this.connectionHandlers.add(handler);
    this.ensureWebSocket();
    return () => this.connectionHandlers.delete(handler);
  }

  onIncomingCall(handler: (data: IncomingCallData) => void): UnsubscribeFn {
    this.incomingCallHandlers.add(handler);
    this.ensureWebSocket();
    return () => this.incomingCallHandlers.delete(handler);
  }

  onCallSignal(handler: (signal: CallSignalData) => void): UnsubscribeFn {
    this.callSignalHandlers.add(handler);
    this.ensureWebSocket();
    return () => this.callSignalHandlers.delete(handler);
  }

  onCallEnded(handler: (data: { callId: string; reason: string }) => void): UnsubscribeFn {
    this.callEndedHandlers.add(handler);
    this.ensureWebSocket();
    return () => this.callEndedHandlers.delete(handler);
  }

  // --- Cleanup ---

  destroy(): void {
    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }
    this.messageHandlers.clear();
    this.typingHandlers.clear();
    this.connectionHandlers.clear();
    this.incomingCallHandlers.clear();
    this.callSignalHandlers.clear();
    this.callEndedHandlers.clear();
  }

  // --- WebSocket ---

  private wsEventDispatch: Record<string, (payload: any) => void> = {
    'signal:message:received': (payload) => this.messageHandlers.forEach((h) => h(payload)),
    'signal:typing': (payload) => this.typingHandlers.forEach((h) => h(payload)),
    'signal:call:incoming': (payload) => this.incomingCallHandlers.forEach((h) => h(payload)),
    'signal:call:signal': (payload) => this.callSignalHandlers.forEach((h) => h(payload)),
    'signal:call:ended': (payload) => this.callEndedHandlers.forEach((h) => h(payload)),
  };

  private ensureWebSocket(): void {
    if (this.ws) return;
    const wsURL = this.baseURL.replace(/^http/, 'ws') + '/api/v1/events';
    try {
      this.ws = new WebSocket(wsURL);
    } catch {
      this.connectionHandlers.forEach((h) => h(false));
      setTimeout(() => this.ensureWebSocket(), 5000);
      return;
    }

    this.ws.onopen = () => {
      this.connectionHandlers.forEach((h) => h(true));
    };

    this.ws.onerror = () => {
      // Suppress console errors from failed WebSocket connections.
    };

    this.ws.onclose = () => {
      this.connectionHandlers.forEach((h) => h(false));
      this.ws = null;
      setTimeout(() => this.ensureWebSocket(), 5000);
    };

    this.ws.onmessage = (event) => {
      const data = JSON.parse(event.data);
      const handler = this.wsEventDispatch[data.type];
      if (handler) handler(data.payload);
    };
  }
}
