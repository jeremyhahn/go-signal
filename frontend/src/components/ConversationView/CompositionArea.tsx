import { useState, useCallback } from 'react';
import { useSignalClient } from '../../App';
import { useStore } from '../../state/store';

export function CompositionArea() {
  const client = useSignalClient();
  const activeId = useStore((s) => s.activeConversationId);
  const [text, setText] = useState('');
  const [sending, setSending] = useState(false);

  const handleSend = useCallback(async () => {
    if (!activeId || !text.trim() || sending) return;
    setSending(true);
    try {
      await client.sendMessage(activeId, text.trim());
      setText('');
    } finally {
      setSending(false);
    }
  }, [client, activeId, text, sending]);

  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        handleSend();
      }
    },
    [handleSend],
  );

  if (!activeId) return null;

  return (
    <div className="composition-area">
      <textarea
        value={text}
        onChange={(e) => setText(e.target.value)}
        onKeyDown={handleKeyDown}
        placeholder="Message"
        rows={1}
        disabled={sending}
        aria-label="Message input"
      />
      <button
        onClick={handleSend}
        disabled={!text.trim() || sending}
        aria-label="Send message"
      >
        <svg className="composition-area__send-icon" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg">
          <path d="M3.105 17.316a.75.75 0 0 1-1.044-.883L4.073 10 2.06 3.567a.75.75 0 0 1 1.044-.883l14.5 6.5a.75.75 0 0 1 0 1.373l-14.5 6.5ZM5.073 10.75l10.7 0-11.6 5.2L5.073 10.75ZM4.173 4.05l11.6 5.2-10.7 0L4.173 4.05Z" />
        </svg>
      </button>
    </div>
  );
}
