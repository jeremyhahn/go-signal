// ISignalClient is the unified TypeScript interface for the Signal client.
// React components use this interface exclusively -- never Wails bindings
// or HTTP calls directly. Two implementations exist:
//   - WailsAdapter: for the desktop app (calls Go bindings via Wails runtime)
//   - WebAdapter: for the web UI (calls REST + WebSocket)

export interface Account {
  number: string;
  uuid: string;
  pni?: string;
  deviceId: number;
}

export interface Message {
  id: number;
  guid: string;
  conversationId: string;
  sourceUuid: string;
  timestamp: number;
  type: number;
  body: string;
  isRead: boolean;
  sendState: number;
}

export interface Conversation {
  id: number;
  conversationId: string;
  type: number;
  name: string;
  unreadCount: number;
  lastMessageTimestamp: number;
  lastMessageBody: string;
  isPinned: boolean;
  isArchived: boolean;
}

export interface Contact {
  uuid: string;
  e164?: string;
  givenName?: string;
  familyName?: string;
  profileName?: string;
  isBlocked: boolean;
}

export interface SendResult {
  timestamp: number;
  needsSync: boolean;
}

export interface VerificationSession {
  id: string;
  [key: string]: unknown;
}

// Calling types

export type CallType = 'audio' | 'video';
export type CallState = 'idle' | 'lobby' | 'ringing' | 'connecting' | 'connected' | 'ended';

export interface CallInfo {
  callId: string;
  peerUuid: string;
  peerName?: string;
  callType: CallType;
  state: CallState;
  isOutgoing: boolean;
  startedAt: number;
}

export interface IncomingCallData {
  callId: string;
  callerUuid: string;
  callerName?: string;
  callType: CallType;
  offer: RTCSessionDescriptionInit;
}

export interface CallSignalData {
  type: 'answer' | 'ice' | 'hangup';
  callId: string;
  payload: unknown;
}

export interface TurnRelay {
  username: string;
  password: string;
  ttl: number;
  urls: string[];
}

export interface TurnCredentials {
  relays: TurnRelay[];
}

export type UnsubscribeFn = () => void;

export interface ISignalClient {
  // Account
  isRegistered(): Promise<boolean>;
  createVerificationSession(number: string): Promise<VerificationSession>;
  requestVerificationCode(sessionId: string): Promise<void>;
  submitVerificationCode(sessionId: string, code: string): Promise<VerificationSession>;
  register(number: string, sessionId: string): Promise<Account>;
  whoAmI(): Promise<Account>;

  // Messaging
  sendMessage(recipient: string, text: string): Promise<SendResult>;
  getMessages(conversationId: string, limit: number, before?: number): Promise<Message[]>;
  getConversations(): Promise<Conversation[]>;

  // Events (real-time)
  onMessage(handler: (msg: Message) => void): UnsubscribeFn;
  onTyping(handler: (data: { conversationId: string; sender: string; started: boolean }) => void): UnsubscribeFn;
  onConnectionStatus(handler: (connected: boolean) => void): UnsubscribeFn;

  // Contacts
  listContacts(): Promise<Contact[]>;

  // Calling
  sendCallSignal(signal: { type: string; callId: string; callerUuid?: string; calleeUuid: string; callType: string; payload: unknown }): Promise<void>;
  getTurnCredentials(): Promise<TurnCredentials>;

  // Call events
  onIncomingCall(handler: (data: IncomingCallData) => void): UnsubscribeFn;
  onCallSignal(handler: (signal: CallSignalData) => void): UnsubscribeFn;
  onCallEnded(handler: (data: { callId: string; reason: string }) => void): UnsubscribeFn;

  // Cleanup
  destroy(): void;
}
