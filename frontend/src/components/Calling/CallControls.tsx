import type { CallType } from '../../sdk/ISignalClient';

interface CallControlsProps {
  isAudioMuted: boolean;
  isVideoOff: boolean;
  callType: CallType;
  onToggleAudio: () => void;
  onToggleVideo: () => void;
  onHangup: () => void;
}

export function CallControls({
  isAudioMuted,
  isVideoOff,
  callType,
  onToggleAudio,
  onToggleVideo,
  onHangup,
}: CallControlsProps) {
  return (
    <div className="calling-controls">
      <button
        type="button"
        className={`calling-controls__button ${isAudioMuted ? 'calling-controls__button--muted' : ''}`}
        onClick={onToggleAudio}
        aria-label={isAudioMuted ? 'Unmute microphone' : 'Mute microphone'}
        data-testid="call-toggle-audio"
      >
        <svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
          {isAudioMuted ? (
            <>
              <path d="M12 1a3 3 0 0 0-3 3v8a3 3 0 0 0 6 0V4a3 3 0 0 0-3-3Z" stroke="currentColor" strokeWidth="2" />
              <path d="M19 10v2a7 7 0 0 1-14 0v-2" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
              <path d="M12 19v4" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
              <line x1="3" y1="3" x2="21" y2="21" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
            </>
          ) : (
            <>
              <path d="M12 1a3 3 0 0 0-3 3v8a3 3 0 0 0 6 0V4a3 3 0 0 0-3-3Z" stroke="currentColor" strokeWidth="2" />
              <path d="M19 10v2a7 7 0 0 1-14 0v-2" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
              <path d="M12 19v4" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
            </>
          )}
        </svg>
      </button>

      {callType === 'video' && (
        <button
          type="button"
          className={`calling-controls__button ${isVideoOff ? 'calling-controls__button--muted' : ''}`}
          onClick={onToggleVideo}
          aria-label={isVideoOff ? 'Turn on camera' : 'Turn off camera'}
          data-testid="call-toggle-video"
        >
          <svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
            {isVideoOff ? (
              <>
                <rect x="2" y="5" width="14" height="14" rx="2" stroke="currentColor" strokeWidth="2" />
                <path d="m22 7-6 4 6 4V7Z" stroke="currentColor" strokeWidth="2" strokeLinejoin="round" />
                <line x1="3" y1="3" x2="21" y2="21" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
              </>
            ) : (
              <>
                <rect x="2" y="5" width="14" height="14" rx="2" stroke="currentColor" strokeWidth="2" />
                <path d="m22 7-6 4 6 4V7Z" stroke="currentColor" strokeWidth="2" strokeLinejoin="round" />
              </>
            )}
          </svg>
        </button>
      )}

      <button
        type="button"
        className="calling-controls__button calling-controls__button--hangup"
        onClick={onHangup}
        aria-label="End call"
        data-testid="call-hangup"
      >
        <svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
          <path d="M23 16.01c-2.8-2.8-6.5-4.01-10.5-4.01S5.3 13.21 2.5 16.01L1 14.5C4.3 11.2 8.6 9.5 12.5 9.5s8.2 1.7 11.5 5l-1 1.51Z" fill="currentColor" />
          <path d="M3.5 20.5 1 16l5-1 1.5 3-4 2.5Zm17 0L23 16l-5-1-1.5 3 4 2.5Z" fill="currentColor" />
        </svg>
      </button>
    </div>
  );
}
