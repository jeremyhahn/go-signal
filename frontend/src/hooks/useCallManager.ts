import { createContext, useCallback, useContext, useEffect, useRef } from 'react';
import { useStore } from '../state/store';
import { useSignalClient } from '../App';
import { WebRTCManager } from '../lib/WebRTCManager';
import type { CallType, CallInfo, IncomingCallData, CallSignalData } from '../sdk/ISignalClient';

export interface CallManagerAPI {
  startCall: (peerUuid: string, peerName: string, callType: CallType) => Promise<void>;
  confirmCall: () => Promise<void>;
  acceptCall: () => Promise<void>;
  declineCall: () => void;
  endCall: () => void;
  toggleAudio: () => void;
  toggleVideo: () => void;
  cancelLobby: () => void;
}

export const CallManagerContext = createContext<CallManagerAPI | null>(null);

export function useCallManagerContext(): CallManagerAPI {
  const ctx = useContext(CallManagerContext);
  if (!ctx) throw new Error('CallManagerContext not initialized');
  return ctx;
}

export function useCallManager() {
  const client = useSignalClient();
  const rtcRef = useRef<WebRTCManager | null>(null);
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const activeCall = useStore((s) => s.activeCall);
  const setActiveCall = useStore((s) => s.setActiveCall);
  const setIncomingCall = useStore((s) => s.setIncomingCall);
  const updateCallState = useStore((s) => s.updateCallState);
  const setLocalStream = useStore((s) => s.setLocalStream);
  const setRemoteStream = useStore((s) => s.setRemoteStream);
  const setCallDuration = useStore((s) => s.setCallDuration);
  const resetCalling = useStore((s) => s.resetCalling);
  const toggleAudioStore = useStore((s) => s.toggleAudio);
  const toggleVideoStore = useStore((s) => s.toggleVideo);

  const cleanup = useCallback(() => {
    if (timerRef.current) {
      clearInterval(timerRef.current);
      timerRef.current = null;
    }
    if (rtcRef.current) {
      rtcRef.current.destroy();
      rtcRef.current = null;
    }
    resetCalling();
  }, [resetCalling]);

  const startTimer = useCallback(() => {
    let seconds = 0;
    timerRef.current = setInterval(() => {
      seconds += 1;
      setCallDuration(seconds);
    }, 1000);
  }, [setCallDuration]);

  const createRTCManager = useCallback(() => {
    const rtc = new WebRTCManager({
      onLocalStream: (stream) => setLocalStream(stream),
      onRemoteStream: (stream) => setRemoteStream(stream),
      onIceCandidate: (candidate) => {
        const call = useStore.getState().activeCall;
        if (!call) return;
        client.sendCallSignal({
          type: 'ice',
          callId: call.callId,
          calleeUuid: call.peerUuid,
          callType: call.callType,
          payload: candidate.toJSON(),
        });
      },
      onConnectionStateChange: (state) => {
        if (state === 'connected') {
          updateCallState('connected');
          startTimer();
        } else if (state === 'disconnected' || state === 'failed') {
          cleanup();
        }
      },
    });
    rtcRef.current = rtc;
    return rtc;
  }, [client, setLocalStream, setRemoteStream, updateCallState, startTimer, cleanup]);

  // --- Outgoing call ---

  const startCall = useCallback(async (peerUuid: string, peerName: string, callType: CallType) => {
    if (activeCall) return;

    const callId = crypto.randomUUID();
    const callInfo: CallInfo = {
      callId,
      peerUuid,
      peerName,
      callType,
      state: 'lobby',
      isOutgoing: true,
      startedAt: Date.now(),
    };
    setActiveCall(callInfo);

    try {
      const rtc = createRTCManager();
      const turnCreds = await client.getTurnCredentials();
      await rtc.initialize(turnCreds);
      await rtc.getUserMedia(callType);
    } catch (err) {
      console.error('Failed to initialize call media:', err);
      cleanup();
    }
  }, [activeCall, setActiveCall, createRTCManager, client, cleanup]);

  const confirmCall = useCallback(async () => {
    const call = useStore.getState().activeCall;
    if (!call || !rtcRef.current) return;

    updateCallState('ringing');
    const offer = await rtcRef.current.createOffer();
    await client.sendCallSignal({
      type: 'offer',
      callId: call.callId,
      calleeUuid: call.peerUuid,
      callType: call.callType,
      payload: offer,
    });
  }, [client, updateCallState]);

  // --- Incoming call ---

  const acceptCall = useCallback(async () => {
    const incoming = useStore.getState().incomingCall;
    if (!incoming) return;

    const callInfo: CallInfo = {
      callId: incoming.callId,
      peerUuid: incoming.callerUuid,
      peerName: incoming.callerName,
      callType: incoming.callType,
      state: 'connecting',
      isOutgoing: false,
      startedAt: Date.now(),
    };
    setActiveCall(callInfo);
    setIncomingCall(null);

    try {
      const rtc = createRTCManager();
      const turnCreds = await client.getTurnCredentials();
      await rtc.initialize(turnCreds);
      await rtc.getUserMedia(incoming.callType);
      const answer = await rtc.createAnswer(incoming.offer);
      await client.sendCallSignal({
        type: 'answer',
        callId: incoming.callId,
        calleeUuid: incoming.callerUuid,
        callType: incoming.callType,
        payload: answer,
      });
    } catch (err) {
      console.error('Failed to accept call:', err);
      cleanup();
    }
  }, [client, setActiveCall, setIncomingCall, createRTCManager, cleanup]);

  const declineCall = useCallback(() => {
    const incoming = useStore.getState().incomingCall;
    if (!incoming) return;

    client.sendCallSignal({
      type: 'hangup',
      callId: incoming.callId,
      calleeUuid: incoming.callerUuid,
      callType: incoming.callType,
      payload: { reason: 'declined' },
    });
    setIncomingCall(null);
  }, [client, setIncomingCall]);

  // --- End call ---

  const endCall = useCallback(() => {
    const call = useStore.getState().activeCall;
    if (call) {
      client.sendCallSignal({
        type: 'hangup',
        callId: call.callId,
        calleeUuid: call.peerUuid,
        callType: call.callType,
        payload: { reason: 'hangup' },
      });
    }
    cleanup();
  }, [client, cleanup]);

  // --- Media toggles ---

  const toggleAudio = useCallback(() => {
    if (rtcRef.current) {
      rtcRef.current.toggleAudio();
    }
    toggleAudioStore();
  }, [toggleAudioStore]);

  const toggleVideo = useCallback(() => {
    if (rtcRef.current) {
      rtcRef.current.toggleVideo();
    }
    toggleVideoStore();
  }, [toggleVideoStore]);

  // --- Cancel lobby ---

  const cancelLobby = useCallback(() => {
    cleanup();
  }, [cleanup]);

  // --- Event subscriptions ---

  useEffect(() => {
    const unsubs = [
      client.onIncomingCall((data: IncomingCallData) => {
        if (useStore.getState().activeCall) return; // busy
        setIncomingCall(data);
      }),
      client.onCallSignal((signal: CallSignalData) => {
        if (!rtcRef.current) return;
        if (signal.type === 'answer') {
          rtcRef.current.setRemoteAnswer(signal.payload as RTCSessionDescriptionInit);
          updateCallState('connecting');
        } else if (signal.type === 'ice') {
          rtcRef.current.addIceCandidate(signal.payload as RTCIceCandidateInit);
        }
      }),
      client.onCallEnded(() => {
        cleanup();
      }),
    ];
    return () => unsubs.forEach((fn) => fn());
  }, [client, setIncomingCall, updateCallState, cleanup]);

  return {
    startCall,
    confirmCall,
    acceptCall,
    declineCall,
    endCall,
    toggleAudio,
    toggleVideo,
    cancelLobby,
  };
}
