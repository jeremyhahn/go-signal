import { useEffect, useRef } from 'react';
import type { CallType } from '../../sdk/ISignalClient';

interface CallingLobbyProps {
  peerName: string;
  callType: CallType;
  localStream: MediaStream | null;
  isAudioMuted: boolean;
  isVideoOff: boolean;
  onToggleAudio: () => void;
  onToggleVideo: () => void;
  onStartCall: () => void;
  onCancel: () => void;
}

export function CallingLobby({
  peerName,
  callType,
  localStream,
  isAudioMuted,
  isVideoOff,
  onToggleAudio,
  onToggleVideo,
  onStartCall,
  onCancel,
}: CallingLobbyProps) {
  const videoRef = useRef<HTMLVideoElement>(null);
  const mediaReady = !!localStream;

  useEffect(() => {
    if (videoRef.current && localStream) {
      videoRef.current.srcObject = localStream;
    }
  }, [localStream]);

  return (
    <div className="calling-overlay" data-testid="calling-lobby">
      <div className="calling-lobby">
        <h2 className="calling-lobby__title">
          {callType === 'video' ? 'Video' : 'Audio'} call with {peerName}
        </h2>

        <div className="calling-lobby__preview">
          {callType === 'video' ? (
            <video
              ref={videoRef}
              className="calling-lobby__video"
              autoPlay
              playsInline
              muted
              data-testid="lobby-video-preview"
            />
          ) : (
            <div className="calling-lobby__avatar">
              <span>{(peerName || '?')[0].toUpperCase()}</span>
            </div>
          )}
        </div>

        <div className="calling-lobby__controls">
          <button
            type="button"
            className={`calling-controls__button ${isAudioMuted ? 'calling-controls__button--muted' : ''}`}
            onClick={onToggleAudio}
            aria-label={isAudioMuted ? 'Unmute microphone' : 'Mute microphone'}
            data-testid="lobby-toggle-audio"
          >
            <svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
              <path d="M12 1a3 3 0 0 0-3 3v8a3 3 0 0 0 6 0V4a3 3 0 0 0-3-3Z" stroke="currentColor" strokeWidth="2" />
              <path d="M19 10v2a7 7 0 0 1-14 0v-2" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
              <path d="M12 19v4" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
              {isAudioMuted && <line x1="3" y1="3" x2="21" y2="21" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />}
            </svg>
          </button>

          {callType === 'video' && (
            <button
              type="button"
              className={`calling-controls__button ${isVideoOff ? 'calling-controls__button--muted' : ''}`}
              onClick={onToggleVideo}
              aria-label={isVideoOff ? 'Turn on camera' : 'Turn off camera'}
              data-testid="lobby-toggle-video"
            >
              <svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                <rect x="2" y="5" width="14" height="14" rx="2" stroke="currentColor" strokeWidth="2" />
                <path d="m22 7-6 4 6 4V7Z" stroke="currentColor" strokeWidth="2" strokeLinejoin="round" />
                {isVideoOff && <line x1="3" y1="3" x2="21" y2="21" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />}
              </svg>
            </button>
          )}
        </div>

        <div className="calling-lobby__actions">
          <button
            type="button"
            className="calling-lobby__cancel"
            onClick={onCancel}
            data-testid="lobby-cancel"
          >
            Cancel
          </button>
          <button
            type="button"
            className="calling-lobby__start"
            onClick={onStartCall}
            disabled={!mediaReady}
            data-testid="lobby-start-call"
          >
            Start Call
          </button>
        </div>
      </div>
    </div>
  );
}
