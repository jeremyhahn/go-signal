import { useStore } from '../state/store';
import { NavTabs } from './NavTabs';
import { ConversationList } from './LeftPane/ConversationList';
import { SearchInput } from './LeftPane/SearchInput';
import { Timeline } from './ConversationView/Timeline';
import { CompositionArea } from './ConversationView/CompositionArea';
import { NoConversationSplash } from './common/NoConversationSplash';
import { SettingsPage } from './Settings/SettingsPage';
import { useCallManagerContext } from '../hooks/useCallManager';

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

export function Inbox() {
  const { startCall } = useCallManagerContext();
  const activeTab = useStore((s) => s.activeTab);
  const activeConversationId = useStore((s) => s.activeConversationId);
  const conversations = useStore((s) => s.conversations);
  const connected = useStore((s) => s.connected);
  const activeCallState = useStore((s) => s.activeCall);

  const activeConv = conversations.find(
    (c) => c.conversationId === activeConversationId,
  );

  const activeName = activeConv?.name || activeConversationId || '';
  const activeInitial = (activeName || '?')[0].toUpperCase();
  const activeColor = avatarColor(activeName);

  return (
    <div className="inbox">
      <NavTabs />

      {activeTab === 'settings' ? (
        <SettingsPage />
      ) : (
        <>
          <div className="left-pane">
            {!connected && (
              <div className="connection-banner" role="alert">
                <svg className="connection-banner__icon" viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg">
                  <circle cx="8" cy="8" r="6.5" stroke="currentColor" strokeWidth="1.5" />
                  <path d="M8 5v3" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
                  <circle cx="8" cy="11" r="0.75" fill="currentColor" />
                </svg>
                <span>Connecting...</span>
              </div>
            )}
            <div className="left-pane__header">
              <h1 className="left-pane__header-title">Chats</h1>
              <div className="left-pane__header-actions">
                <button type="button" className="left-pane__header-button" aria-label="Compose">
                  <svg viewBox="0 0 20 20" fill="none" xmlns="http://www.w3.org/2000/svg">
                    <path d="M13.586 3.586a2 2 0 1 1 2.828 2.828l-8.793 8.793-3.535.707.707-3.536 8.793-8.792Z" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
                  </svg>
                </button>
              </div>
            </div>
            <SearchInput onSearch={() => {}} placeholder="Search conversations" />
            <ConversationList />
          </div>
          <div className="conversation-view">
            {activeConversationId ? (
              <div className="conversation-panel">
                <div className="conversation-header">
                  <div
                    className={`conversation-header__avatar conv-avatar--${activeColor}`}
                  >
                    {activeInitial}
                  </div>
                  <div className="conversation-header__info">
                    <h3>{activeName}</h3>
                  </div>
                  <div className="conversation-header__actions">
                    {!activeCallState && (
                      <>
                        <button
                          type="button"
                          className="conversation-header__button"
                          aria-label="Audio call"
                          data-testid="call-audio-button"
                          onClick={() => startCall(activeConversationId!, activeName, 'audio')}
                        >
                          <svg viewBox="0 0 20 20" fill="none" xmlns="http://www.w3.org/2000/svg">
                            <path d="M2 3.5C2 2.67 2.67 2 3.5 2h3.09a1 1 0 0 1 .98.79l.72 3.6a1 1 0 0 1-.27.88l-1.52 1.53a11.04 11.04 0 0 0 4.7 4.7l1.53-1.52a1 1 0 0 1 .88-.27l3.6.72a1 1 0 0 1 .79.98v3.09c0 .83-.67 1.5-1.5 1.5C8.84 18 2 11.16 2 3.5Z" stroke="currentColor" strokeWidth="1.5"/>
                          </svg>
                        </button>
                        <button
                          type="button"
                          className="conversation-header__button"
                          aria-label="Video call"
                          data-testid="call-video-button"
                          onClick={() => startCall(activeConversationId!, activeName, 'video')}
                        >
                          <svg viewBox="0 0 20 20" fill="none" xmlns="http://www.w3.org/2000/svg">
                            <rect x="1" y="4" width="12" height="12" rx="2" stroke="currentColor" strokeWidth="1.5"/>
                            <path d="m19 6-5 3.5L19 13V6Z" stroke="currentColor" strokeWidth="1.5" strokeLinejoin="round"/>
                          </svg>
                        </button>
                      </>
                    )}
                    <button type="button" className="conversation-header__button" aria-label="Search in conversation">
                      <svg viewBox="0 0 20 20" fill="none" xmlns="http://www.w3.org/2000/svg">
                        <circle cx="9" cy="9" r="5.5" stroke="currentColor" strokeWidth="1.5"/>
                        <path d="m13 13 4 4" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"/>
                      </svg>
                    </button>
                    <button type="button" className="conversation-header__button" aria-label="More options">
                      <svg viewBox="0 0 20 20" fill="currentColor" xmlns="http://www.w3.org/2000/svg">
                        <circle cx="10" cy="4" r="1.5"/><circle cx="10" cy="10" r="1.5"/><circle cx="10" cy="16" r="1.5"/>
                      </svg>
                    </button>
                  </div>
                </div>
                <Timeline />
                <CompositionArea />
              </div>
            ) : (
              <NoConversationSplash />
            )}
          </div>
        </>
      )}
    </div>
  );
}
