import { createContext, useContext, useEffect, useState } from 'react';
import { createSignalClient } from './sdk/factory';
import type { ISignalClient } from './sdk/ISignalClient';
import { useStore } from './state/store';
import { InstallScreen } from './components/Auth/InstallScreen';
import { Inbox } from './components/Inbox';
import { ErrorBoundary } from './components/common/ErrorBoundary';
import { CallingLobby } from './components/Calling/CallingLobby';
import { CallScreen } from './components/Calling/CallScreen';
import { IncomingCallBar } from './components/Calling/IncomingCallBar';
import { useCallManager, CallManagerContext } from './hooks/useCallManager';

// SignalClientContext provides the client to all components.
export const SignalClientContext = createContext<ISignalClient | null>(null);
export const useSignalClient = () => {
  const client = useContext(SignalClientContext);
  if (!client) throw new Error('SignalClientContext not initialized');
  return client;
};

function useThemeEffect() {
  const theme = useStore((s) => s.theme);

  useEffect(() => {
    const root = document.documentElement;
    if (theme === 'system') {
      const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
      root.setAttribute('data-theme', prefersDark ? 'dark' : 'light');

      const handler = (e: MediaQueryListEvent) => {
        root.setAttribute('data-theme', e.matches ? 'dark' : 'light');
      };
      const mq = window.matchMedia('(prefers-color-scheme: dark)');
      mq.addEventListener('change', handler);
      return () => mq.removeEventListener('change', handler);
    }
    root.setAttribute('data-theme', theme);
  }, [theme]);
}

function CallingOverlay() {
  const {
    confirmCall, acceptCall, declineCall, endCall,
    toggleAudio, toggleVideo, cancelLobby,
  } = useContext(CallManagerContext)!;

  const activeCall = useStore((s) => s.activeCall);
  const incomingCall = useStore((s) => s.incomingCall);
  const localStream = useStore((s) => s.localStream);
  const remoteStream = useStore((s) => s.remoteStream);
  const isAudioMuted = useStore((s) => s.isAudioMuted);
  const isVideoOff = useStore((s) => s.isVideoOff);
  const callDuration = useStore((s) => s.callDuration);
  const conversations = useStore((s) => s.conversations);

  // Resolve caller name for incoming calls.
  const incomingCallerName = incomingCall
    ? (incomingCall.callerName
      || conversations.find((c) => c.conversationId === incomingCall.callerUuid)?.name
      || incomingCall.callerUuid)
    : '';

  return (
    <>
      {/* Incoming call notification */}
      {incomingCall && !activeCall && (
        <IncomingCallBar
          callerName={incomingCallerName}
          callType={incomingCall.callType}
          onAccept={acceptCall}
          onDecline={declineCall}
        />
      )}

      {/* Pre-call lobby */}
      {activeCall?.state === 'lobby' && (
        <CallingLobby
          peerName={activeCall.peerName || activeCall.peerUuid}
          callType={activeCall.callType}
          localStream={localStream}
          isAudioMuted={isAudioMuted}
          isVideoOff={isVideoOff}
          onToggleAudio={toggleAudio}
          onToggleVideo={toggleVideo}
          onStartCall={confirmCall}
          onCancel={cancelLobby}
        />
      )}

      {/* Active call screen */}
      {activeCall && (activeCall.state === 'ringing' || activeCall.state === 'connecting' || activeCall.state === 'connected') && (
        <CallScreen
          call={activeCall}
          localStream={localStream}
          remoteStream={remoteStream}
          isAudioMuted={isAudioMuted}
          isVideoOff={isVideoOff}
          callDuration={callDuration}
          onToggleAudio={toggleAudio}
          onToggleVideo={toggleVideo}
          onHangup={endCall}
        />
      )}
    </>
  );
}

function AppInner() {
  const isRegistered = useStore((s) => s.isRegistered);
  const setRegistered = useStore((s) => s.setRegistered);
  const setConnected = useStore((s) => s.setConnected);
  const appendMessage = useStore((s) => s.appendMessage);
  const client = useSignalClient();

  // Single useCallManager instance — shared via CallManagerContext.
  const callManager = useCallManager();

  useThemeEffect();

  // Check registration status on mount.
  useEffect(() => {
    client.isRegistered().then(setRegistered);
  }, [client, setRegistered]);

  // Subscribe to real-time events.
  useEffect(() => {
    const unsubs = [
      client.onMessage((msg) => appendMessage(msg)),
      client.onConnectionStatus((connected) => setConnected(connected)),
    ];
    return () => unsubs.forEach((fn) => fn());
  }, [client, appendMessage, setConnected]);

  return (
    <CallManagerContext.Provider value={callManager}>
      <div className="app">
        {isRegistered ? (
          <>
            <Inbox />
            <CallingOverlay />
          </>
        ) : (
          <InstallScreen />
        )}
      </div>
    </CallManagerContext.Provider>
  );
}

export default function App() {
  const [client] = useState(() => createSignalClient());

  return (
    <ErrorBoundary>
      <SignalClientContext.Provider value={client}>
        <AppInner />
      </SignalClientContext.Provider>
    </ErrorBoundary>
  );
}
