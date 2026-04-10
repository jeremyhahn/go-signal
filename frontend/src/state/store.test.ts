import { describe, it, expect, beforeEach, vi } from 'vitest';
import { useStore } from './store';
import type { Conversation, Message } from '../sdk/ISignalClient';

// Reset Zustand store state between tests by reinitialising to defaults.
beforeEach(() => {
  useStore.setState({
    isRegistered: false,
    activeTab: 'chats',
    theme: 'system',
    conversations: [],
    activeConversationId: null,
    conversationsLoading: false,
    messages: [],
    messagesLoading: false,
    contacts: [],
    connected: false,
    activeCall: null,
    incomingCall: null,
    localStream: null,
    remoteStream: null,
    isAudioMuted: false,
    isVideoOff: false,
    callDuration: 0,
  });
  localStorage.clear();
});

const sampleConversation: Conversation = {
  id: 1,
  conversationId: 'conv-1',
  type: 0,
  name: 'Alice',
  unreadCount: 0,
  lastMessageTimestamp: 1000,
  lastMessageBody: 'Hi',
  isPinned: false,
  isArchived: false,
};

const sampleMessage: Message = {
  id: 1,
  guid: 'msg-guid-1',
  conversationId: 'conv-1',
  sourceUuid: 'uuid-sender',
  timestamp: 2000,
  type: 0,
  body: 'Hello',
  isRead: false,
  sendState: 0,
};

describe('store – initial state', () => {
  it('has correct default values', () => {
    const state = useStore.getState();
    expect(state.isRegistered).toBe(false);
    expect(state.activeTab).toBe('chats');
    expect(state.theme).toBe('system');
    expect(state.conversations).toEqual([]);
    expect(state.activeConversationId).toBeNull();
    expect(state.conversationsLoading).toBe(false);
    expect(state.messages).toEqual([]);
    expect(state.messagesLoading).toBe(false);
    expect(state.connected).toBe(false);
  });
});

describe('store – setRegistered', () => {
  it('sets isRegistered to true', () => {
    useStore.getState().setRegistered(true);
    expect(useStore.getState().isRegistered).toBe(true);
  });

  it('sets isRegistered back to false', () => {
    useStore.getState().setRegistered(true);
    useStore.getState().setRegistered(false);
    expect(useStore.getState().isRegistered).toBe(false);
  });
});

describe('store – setActiveTab', () => {
  it('switches to settings tab', () => {
    useStore.getState().setActiveTab('settings');
    expect(useStore.getState().activeTab).toBe('settings');
  });

  it('switches back to chats tab', () => {
    useStore.getState().setActiveTab('settings');
    useStore.getState().setActiveTab('chats');
    expect(useStore.getState().activeTab).toBe('chats');
  });
});

describe('store – setTheme', () => {
  it('updates theme to dark', () => {
    useStore.getState().setTheme('dark');
    expect(useStore.getState().theme).toBe('dark');
  });

  it('writes theme to localStorage', () => {
    useStore.getState().setTheme('light');
    expect(localStorage.getItem('go-signal-theme')).toBe('light');
  });

  it('updates theme to system', () => {
    useStore.getState().setTheme('system');
    expect(useStore.getState().theme).toBe('system');
    expect(localStorage.getItem('go-signal-theme')).toBe('system');
  });
});

describe('store – setConversations', () => {
  it('replaces conversations array', () => {
    useStore.getState().setConversations([sampleConversation]);
    expect(useStore.getState().conversations).toEqual([sampleConversation]);
  });

  it('clears conversationsLoading flag', () => {
    useStore.getState().setConversationsLoading(true);
    useStore.getState().setConversations([sampleConversation]);
    expect(useStore.getState().conversationsLoading).toBe(false);
  });

  it('replaces with empty array', () => {
    useStore.getState().setConversations([sampleConversation]);
    useStore.getState().setConversations([]);
    expect(useStore.getState().conversations).toEqual([]);
  });
});

describe('store – selectConversation', () => {
  it('sets activeConversationId', () => {
    useStore.getState().selectConversation('conv-42');
    expect(useStore.getState().activeConversationId).toBe('conv-42');
  });

  it('replaces a previous selection', () => {
    useStore.getState().selectConversation('conv-1');
    useStore.getState().selectConversation('conv-2');
    expect(useStore.getState().activeConversationId).toBe('conv-2');
  });
});

describe('store – setMessages', () => {
  it('replaces messages array', () => {
    useStore.getState().setMessages([sampleMessage]);
    expect(useStore.getState().messages).toEqual([sampleMessage]);
  });

  it('clears messagesLoading flag', () => {
    useStore.getState().setMessagesLoading(true);
    useStore.getState().setMessages([sampleMessage]);
    expect(useStore.getState().messagesLoading).toBe(false);
  });
});

describe('store – appendMessage', () => {
  it('adds a message to an empty list', () => {
    useStore.getState().appendMessage(sampleMessage);
    expect(useStore.getState().messages).toEqual([sampleMessage]);
  });

  it('appends to an existing list', () => {
    const second: Message = { ...sampleMessage, id: 2, guid: 'msg-guid-2' };
    useStore.getState().setMessages([sampleMessage]);
    useStore.getState().appendMessage(second);
    expect(useStore.getState().messages).toEqual([sampleMessage, second]);
  });
});

describe('store – setConnected', () => {
  it('sets connected to true', () => {
    useStore.getState().setConnected(true);
    expect(useStore.getState().connected).toBe(true);
  });

  it('sets connected back to false', () => {
    useStore.getState().setConnected(true);
    useStore.getState().setConnected(false);
    expect(useStore.getState().connected).toBe(false);
  });
});

describe('store – setConversationsLoading / setMessagesLoading', () => {
  it('toggles conversationsLoading on', () => {
    useStore.getState().setConversationsLoading(true);
    expect(useStore.getState().conversationsLoading).toBe(true);
  });

  it('toggles conversationsLoading off', () => {
    useStore.getState().setConversationsLoading(true);
    useStore.getState().setConversationsLoading(false);
    expect(useStore.getState().conversationsLoading).toBe(false);
  });

  it('toggles messagesLoading on', () => {
    useStore.getState().setMessagesLoading(true);
    expect(useStore.getState().messagesLoading).toBe(true);
  });

  it('toggles messagesLoading off', () => {
    useStore.getState().setMessagesLoading(true);
    useStore.getState().setMessagesLoading(false);
    expect(useStore.getState().messagesLoading).toBe(false);
  });
});
