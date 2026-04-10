import { useEffect, useRef } from 'react';
import type { CallInfo } from '../../sdk/ISignalClient';
import { CallControls } from './CallControls';

interface CallScreenProps {
  call: CallInfo;
  localStream: MediaStream | null;
  remoteStream: MediaStream | null;
  isAudioMuted: boolean;
  isVideoOff: boolean;
  callDuration: number;
  onToggleAudio: () => void;
  onToggleVideo: () => void;
  onHangup: () => void;
}

function formatDuration(seconds: number): string {
  const m = Math.floor(seconds / 60);
  const s = seconds % 60;
  return `${m.toString().padStart(2, '0')}:${s.toString().padStart(2, '0')}`;
}

export function CallScreen({
  call,
  localStream,
  remoteStream,
  isAudioMuted,
  isVideoOff,
  callDuration,
  onToggleAudio,
  onToggleVideo,
  onHangup,
}: CallScreenProps) {
  const localVideoRef = useRef<HTMLVideoElement>(null);
  const remoteVideoRef = useRef<HTMLVideoElement>(null);

  useEffect(() => {
    if (localVideoRef.current && localStream) {
      localVideoRef.current.srcObject = localStream;
    }
  }, [localStream]);

  useEffect(() => {
    if (remoteVideoRef.current && remoteStream) {
      remoteVideoRef.current.srcObject = remoteStream;
    }
  }, [remoteStream]);

  const isVideo = call.callType === 'video';
  const peerName = call.peerName || call.peerUuid;
  const peerInitial = (peerName || '?')[0].toUpperCase();

  return (
    <div className="calling-overlay" data-testid="call-screen">
      <div className="calling-screen">
        {/* Remote area */}
        <div className="calling-screen__remote">
          {isVideo && remoteStream ? (
            <video
              ref={remoteVideoRef}
              className="remote-video"
              autoPlay
              playsInline
              data-testid="call-remote-video"
            />
          ) : (
            <div className="calling-screen__avatar">
              <div className="calling-screen__avatar-circle">
                {peerInitial}
              </div>
              <span className="calling-screen__peer-name">{peerName}</span>
            </div>
          )}
        </div>

        {/* Header with name and timer */}
        <div className="calling-screen__header">
          <span className="calling-screen__name">{peerName}</span>
          <span className="calling-screen__status" data-testid="call-status">
            {call.state === 'ringing' && 'Ringing...'}
            {call.state === 'connecting' && 'Connecting...'}
            {call.state === 'connected' && formatDuration(callDuration)}
          </span>
        </div>

        {/* Local video PiP */}
        {isVideo && localStream && (
          <div className="local-video-container">
            <video
              ref={localVideoRef}
              className="local-video"
              autoPlay
              playsInline
              muted
              data-testid="call-local-video"
            />
          </div>
        )}

        {/* Controls */}
        <CallControls
          isAudioMuted={isAudioMuted}
          isVideoOff={isVideoOff}
          callType={call.callType}
          onToggleAudio={onToggleAudio}
          onToggleVideo={onToggleVideo}
          onHangup={onHangup}
        />
      </div>
    </div>
  );
}
