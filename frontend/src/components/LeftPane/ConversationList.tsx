import { useEffect } from 'react';
import { useSignalClient } from '../../App';
import { useStore } from '../../state/store';
import type { Conversation } from '../../sdk/ISignalClient';

const AVATAR_COLORS = [
  'ultramarine', 'blue', 'crimson', 'forest', 'indigo', 'plum',
  'steel', 'teal', 'vermilion', 'violet', 'wintergreen', 'taupe', 'burlap',
];

function avatarColor(name: string): string {
  let hash = 0;
  for (let i = 0; i < name.length; i++) {
    hash = name.charCodeAt(i) + ((hash << 5) - hash);
  }
  return AVATAR_COLORS[Math.abs(hash) % AVATAR_COLORS.length];
}

export function ConversationList() {
  const client = useSignalClient();
  const conversations = useStore((s) => s.conversations);
  const setConversations = useStore((s) => s.setConversations);
  const activeId = useStore((s) => s.activeConversationId);
  const selectConversation = useStore((s) => s.selectConversation);

  useEffect(() => {
    client.getConversations().then(setConversations);
  }, [client, setConversations]);

  return (
    <div className="conversation-list">
      {conversations.map((conv) => (
        <ConversationListItem
          key={conv.conversationId}
          conversation={conv}
          isActive={conv.conversationId === activeId}
          onClick={() => selectConversation(conv.conversationId)}
        />
      ))}
      {conversations.length === 0 && (
        <p className="empty-state">No conversations yet</p>
      )}
    </div>
  );
}

function ConversationListItem({
  conversation,
  isActive,
  onClick,
}: {
  conversation: Conversation;
  isActive: boolean;
  onClick: () => void;
}) {
  const displayName = conversation.name || conversation.conversationId;
  const initial = (displayName || '?')[0].toUpperCase();
  const color = avatarColor(displayName);

  return (
    <div
      className={`conversation-item ${isActive ? 'active' : ''}`}
      onClick={onClick}
      role="button"
      tabIndex={0}
      onKeyDown={(e) => e.key === 'Enter' && onClick()}
    >
      <div className={`conv-avatar conv-avatar--${color}`}>
        {initial}
      </div>
      <div className="conv-content">
        <div className="conv-header">
          <span className="conv-name">{displayName}</span>
          {conversation.lastMessageTimestamp > 0 && (
            <span className="conv-time">
              {formatTime(conversation.lastMessageTimestamp)}
            </span>
          )}
        </div>
        <div className="conv-footer">
          {conversation.lastMessageBody && (
            <p className="conv-preview">{conversation.lastMessageBody}</p>
          )}
          {conversation.unreadCount > 0 && (
            <span className="badge">{conversation.unreadCount}</span>
          )}
        </div>
      </div>
    </div>
  );
}

function formatTime(timestamp: number): string {
  const date = new Date(timestamp);
  const now = new Date();
  if (date.toDateString() === now.toDateString()) {
    return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  }
  return date.toLocaleDateString([], { month: 'short', day: 'numeric' });
}
