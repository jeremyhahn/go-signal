import type { StateCreator } from 'zustand';
import type { CallInfo, CallState, IncomingCallData } from '../../sdk/ISignalClient';

export interface CallingSlice {
  // Current call state
  activeCall: CallInfo | null;
  incomingCall: IncomingCallData | null;

  // Media state
  localStream: MediaStream | null;
  remoteStream: MediaStream | null;
  isAudioMuted: boolean;
  isVideoOff: boolean;
  callDuration: number;

  // Actions
  setActiveCall: (call: CallInfo | null) => void;
  setIncomingCall: (call: IncomingCallData | null) => void;
  updateCallState: (state: CallState) => void;
  setLocalStream: (stream: MediaStream | null) => void;
  setRemoteStream: (stream: MediaStream | null) => void;
  toggleAudio: () => void;
  toggleVideo: () => void;
  setCallDuration: (seconds: number) => void;
  resetCalling: () => void;
}

export const createCallingSlice: StateCreator<CallingSlice> = (set) => ({
  activeCall: null,
  incomingCall: null,
  localStream: null,
  remoteStream: null,
  isAudioMuted: false,
  isVideoOff: false,
  callDuration: 0,

  setActiveCall: (call) => set({ activeCall: call }),
  setIncomingCall: (call) => set({ incomingCall: call }),
  updateCallState: (state) =>
    set((s) =>
      s.activeCall ? { activeCall: { ...s.activeCall, state } } : {},
    ),
  setLocalStream: (stream) => set({ localStream: stream }),
  setRemoteStream: (stream) => set({ remoteStream: stream }),
  toggleAudio: () => set((s) => ({ isAudioMuted: !s.isAudioMuted })),
  toggleVideo: () => set((s) => ({ isVideoOff: !s.isVideoOff })),
  setCallDuration: (seconds) => set({ callDuration: seconds }),
  resetCalling: () =>
    set({
      activeCall: null,
      incomingCall: null,
      localStream: null,
      remoteStream: null,
      isAudioMuted: false,
      isVideoOff: false,
      callDuration: 0,
    }),
});
