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

// WailsAdapter implements ISignalClient by calling Wails Go bindings.
// The Go methods are auto-generated into wailsjs/ by the Wails build system.
export class WailsAdapter implements ISignalClient {
  async isRegistered(): Promise<boolean> {
    // @ts-expect-error -- Wails bindings generated at build time
    const { IsRegistered } = await import('../../wailsjs/go/desktop/App');
    return IsRegistered();
  }

  async createVerificationSession(number: string): Promise<VerificationSession> {
    const { CreateVerificationSession } = await import('../../wailsjs/go/desktop/App');
    return CreateVerificationSession(number);
  }

  async requestVerificationCode(sessionId: string): Promise<void> {
    const { RequestVerificationCode } = await import('../../wailsjs/go/desktop/App');
    return RequestVerificationCode(sessionId);
  }

  async submitVerificationCode(sessionId: string, code: string): Promise<VerificationSession> {
    const { SubmitVerificationCode } = await import('../../wailsjs/go/desktop/App');
    return SubmitVerificationCode(sessionId, code);
  }

  async register(number: string, sessionId: string): Promise<Account> {
    const { Register } = await import('../../wailsjs/go/desktop/App');
    return Register(number, sessionId);
  }

  async whoAmI(): Promise<Account> {
    const { WhoAmI } = await import('../../wailsjs/go/desktop/App');
    return WhoAmI();
  }

  async sendMessage(recipient: string, text: string): Promise<SendResult> {
    const { SendMessage } = await import('../../wailsjs/go/desktop/App');
    return SendMessage(recipient, text);
  }

  async getMessages(conversationId: string, limit: number, before?: number): Promise<Message[]> {
    // TODO: wire to Wails binding
    return [];
  }

  async getConversations(): Promise<Conversation[]> {
    const { GetConversations } = await import('../../wailsjs/go/desktop/App');
    return GetConversations();
  }

  onMessage(handler: (msg: Message) => void): UnsubscribeFn {
    // Subscribe to Wails runtime events
    if (typeof window !== 'undefined' && (window as any).runtime) {
      return (window as any).runtime.EventsOn('signal:message:received', handler);
    }
    return () => {};
  }

  onTyping(handler: (data: { conversationId: string; sender: string; started: boolean }) => void): UnsubscribeFn {
    if (typeof window !== 'undefined' && (window as any).runtime) {
      return (window as any).runtime.EventsOn('signal:typing', handler);
    }
    return () => {};
  }

  onConnectionStatus(handler: (connected: boolean) => void): UnsubscribeFn {
    if (typeof window !== 'undefined' && (window as any).runtime) {
      return (window as any).runtime.EventsOn('signal:connection:status', handler);
    }
    return () => {};
  }

  async listContacts(): Promise<Contact[]> {
    // TODO: wire to Wails binding
    return [];
  }

  // --- Calling ---

  async sendCallSignal(signal: { type: string; callId: string; callerUuid?: string; calleeUuid: string; callType: string; payload: unknown }): Promise<void> {
    const { SendCallSignal } = await import('../../wailsjs/go/desktop/App');
    return SendCallSignal(JSON.stringify(signal));
  }

  async getTurnCredentials(): Promise<TurnCredentials> {
    const { GetTurnCredentials } = await import('../../wailsjs/go/desktop/App');
    return GetTurnCredentials();
  }

  onIncomingCall(handler: (data: IncomingCallData) => void): UnsubscribeFn {
    if (typeof window !== 'undefined' && (window as any).runtime) {
      return (window as any).runtime.EventsOn('signal:call:incoming', handler);
    }
    return () => {};
  }

  onCallSignal(handler: (signal: CallSignalData) => void): UnsubscribeFn {
    if (typeof window !== 'undefined' && (window as any).runtime) {
      return (window as any).runtime.EventsOn('signal:call:signal', handler);
    }
    return () => {};
  }

  onCallEnded(handler: (data: { callId: string; reason: string }) => void): UnsubscribeFn {
    if (typeof window !== 'undefined' && (window as any).runtime) {
      return (window as any).runtime.EventsOn('signal:call:ended', handler);
    }
    return () => {};
  }

  destroy(): void {
    // Nothing to clean up for Wails adapter
  }
}
