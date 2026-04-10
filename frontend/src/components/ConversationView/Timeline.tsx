import { useEffect, useRef, useState, useCallback } from 'react';
import { useSignalClient } from '../../App';
import { useStore } from '../../state/store';
import type { Message } from '../../sdk/ISignalClient';

export function Timeline() {
  const client = useSignalClient();
  const activeId = useStore((s) => s.activeConversationId);
  const messages = useStore((s) => s.messages);
  const setMessages = useStore((s) => s.setMessages);
  const messagesLoading = useStore((s) => s.messagesLoading);
  const setMessagesLoading = useStore((s) => s.setMessagesLoading);
  const containerRef = useRef<HTMLDivElement>(null);
  const endRef = useRef<HTMLDivElement>(null);
  const [showScrollDown, setShowScrollDown] = useState(false);

  useEffect(() => {
    if (!activeId) return;
    setMessagesLoading(true);
    client.getMessages(activeId, 50).then(setMessages);
  }, [client, activeId, setMessages, setMessagesLoading]);

  // Scroll to bottom on new messages.
  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  const handleScroll = useCallback(() => {
    const el = containerRef.current;
    if (!el) return;
    const distanceFromBottom = el.scrollHeight - el.scrollTop - el.clientHeight;
    setShowScrollDown(distanceFromBottom > 100);
  }, []);

  const scrollToBottom = useCallback(() => {
    endRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, []);

  if (!activeId) {
    return <div className="timeline-empty">Select a conversation</div>;
  }

  if (messagesLoading && messages.length === 0) {
    return (
      <div className="timeline-loading">
        <div className="spinner" />
      </div>
    );
  }

  // Group messages by date for separators.
  const groupedMessages = groupByDate(messages);

  return (
    <div className="timeline" ref={containerRef} onScroll={handleScroll}>
      {groupedMessages.map((group) => (
        <div key={group.dateKey}>
          <div className="timeline__date-separator">
            <span className="timeline__date-label">{group.label}</span>
          </div>
          {group.messages.map((msg) => (
            <MessageBubble key={msg.guid || msg.id} message={msg} />
          ))}
        </div>
      ))}
      <div ref={endRef} />

      {showScrollDown && (
        <button
          type="button"
          className="timeline__scroll-down"
          onClick={scrollToBottom}
          aria-label="Scroll to bottom"
        >
          <svg viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg">
            <path d="M8 3v10m0 0 4-4m-4 4-4-4" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
          </svg>
        </button>
      )}
    </div>
  );
}

function MessageBubble({ message }: { message: Message }) {
  const isOutgoing = message.type === 2;

  return (
    <div className={`message-bubble ${isOutgoing ? 'outgoing' : 'incoming'}`}>
      <p className="message-body">{message.body}</p>
      <div className="message-meta">
        <span className="message-time">
          {new Date(message.timestamp).toLocaleTimeString([], {
            hour: '2-digit',
            minute: '2-digit',
          })}
        </span>
        {isOutgoing && <MessageStatus sendState={message.sendState} />}
      </div>
    </div>
  );
}

function MessageStatus({ sendState }: { sendState: number }) {
  // sendState: 0 = pending, 1 = sent, 2 = delivered, 3 = read
  let title: string;
  let icon: JSX.Element;

  switch (sendState) {
    case 0:
      title = 'Sending';
      icon = (
        <svg className="message-status__icon message-status__icon--pending" viewBox="0 0 12 12" fill="none" xmlns="http://www.w3.org/2000/svg">
          <circle cx="6" cy="6" r="5" stroke="currentColor" strokeWidth="1.5" strokeDasharray="3 2" />
        </svg>
      );
      break;
    case 1:
      title = 'Sent';
      icon = (
        <svg className="message-status__icon" viewBox="0 0 12 12" fill="none" xmlns="http://www.w3.org/2000/svg">
          <path d="M2.5 6.5 5 9l4.5-6" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
      );
      break;
    case 2:
      title = 'Delivered';
      icon = (
        <svg className="message-status__icon" viewBox="0 0 16 12" fill="none" xmlns="http://www.w3.org/2000/svg">
          <path d="M1.5 6.5 4 9l4.5-6" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
          <path d="M5.5 6.5 8 9l4.5-6" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
      );
      break;
    case 3:
    default:
      title = 'Read';
      icon = (
        <svg className="message-status__icon message-status__icon--read" viewBox="0 0 16 12" fill="none" xmlns="http://www.w3.org/2000/svg">
          <path d="M1.5 6.5 4 9l4.5-6" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
          <path d="M5.5 6.5 8 9l4.5-6" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
      );
      break;
  }

  return (
    <span className="message-status" title={title} aria-label={title}>
      {icon}
    </span>
  );
}

interface DateGroup {
  dateKey: string;
  label: string;
  messages: Message[];
}

function groupByDate(messages: Message[]): DateGroup[] {
  const groups: DateGroup[] = [];
  let currentKey = '';

  for (const msg of messages) {
    const date = new Date(msg.timestamp);
    const key = date.toDateString();

    if (key !== currentKey) {
      currentKey = key;
      groups.push({
        dateKey: key,
        label: formatDateLabel(date),
        messages: [],
      });
    }
    groups[groups.length - 1].messages.push(msg);
  }

  return groups;
}

function formatDateLabel(date: Date): string {
  const now = new Date();
  const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
  const target = new Date(date.getFullYear(), date.getMonth(), date.getDate());
  const diff = today.getTime() - target.getTime();
  const dayMs = 86_400_000;

  if (diff === 0) return 'Today';
  if (diff === dayMs) return 'Yesterday';
  if (diff < 7 * dayMs) {
    return date.toLocaleDateString(undefined, { weekday: 'long' });
  }
  return date.toLocaleDateString(undefined, {
    month: 'long',
    day: 'numeric',
    year: date.getFullYear() !== now.getFullYear() ? 'numeric' : undefined,
  });
}
