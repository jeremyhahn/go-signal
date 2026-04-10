import { create } from 'zustand';
import type { Conversation, Message, Contact } from '../sdk/ISignalClient';
import { type CallingSlice, createCallingSlice } from './slices/callingSlice';

export type NavTab = 'chats' | 'settings';
export type Theme = 'light' | 'dark' | 'system';

export interface AppState extends CallingSlice {
  // Auth
  isRegistered: boolean;
  setRegistered: (v: boolean) => void;

  // Navigation
  activeTab: NavTab;
  setActiveTab: (tab: NavTab) => void;

  // Theme
  theme: Theme;
  setTheme: (theme: Theme) => void;

  // Conversations
  conversations: Conversation[];
  activeConversationId: string | null;
  conversationsLoading: boolean;
  setConversations: (convs: Conversation[]) => void;
  selectConversation: (id: string) => void;
  setConversationsLoading: (v: boolean) => void;

  // Messages for active conversation
  messages: Message[];
  messagesLoading: boolean;
  setMessages: (msgs: Message[]) => void;
  appendMessage: (msg: Message) => void;
  setMessagesLoading: (v: boolean) => void;

  // Contacts
  contacts: Contact[];
  setContacts: (contacts: Contact[]) => void;

  // Connection
  connected: boolean;
  setConnected: (v: boolean) => void;
}

function loadTheme(): Theme {
  try {
    const stored = localStorage.getItem('go-signal-theme');
    if (stored === 'light' || stored === 'dark' || stored === 'system') return stored;
  } catch { /* ignore */ }
  return 'system';
}

export const useStore = create<AppState>((...a) => ({
  isRegistered: false,
  setRegistered: (v) => a[0]({ isRegistered: v }),

  activeTab: 'chats',
  setActiveTab: (tab) => a[0]({ activeTab: tab }),

  theme: loadTheme(),
  setTheme: (theme) => {
    try { localStorage.setItem('go-signal-theme', theme); } catch { /* ignore */ }
    a[0]({ theme });
  },

  conversations: [],
  activeConversationId: null,
  conversationsLoading: false,
  setConversations: (convs) => a[0]({ conversations: convs, conversationsLoading: false }),
  selectConversation: (id) => a[0]({ activeConversationId: id }),
  setConversationsLoading: (v) => a[0]({ conversationsLoading: v }),

  messages: [],
  messagesLoading: false,
  setMessages: (msgs) => a[0]({ messages: msgs, messagesLoading: false }),
  appendMessage: (msg) =>
    a[0]((state) => ({ messages: [...state.messages, msg] })),
  setMessagesLoading: (v) => a[0]({ messagesLoading: v }),

  contacts: [],
  setContacts: (contacts) => a[0]({ contacts }),

  connected: false,
  setConnected: (v) => a[0]({ connected: v }),

  // Calling slice
  ...createCallingSlice(...a),
}));
