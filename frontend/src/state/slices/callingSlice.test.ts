import { describe, it, expect, beforeEach } from 'vitest';
import { create } from 'zustand';
import { createCallingSlice, type CallingSlice } from './callingSlice';
import type { CallInfo, IncomingCallData } from '../../sdk/ISignalClient';

// Create an isolated store for each test group.
function makeStore() {
  return create<CallingSlice>()(createCallingSlice);
}

const sampleCallInfo: CallInfo = {
  callId: 'call-1',
  peerUuid: 'peer-uuid',
  peerName: 'Bob',
  callType: 'video',
  state: 'ringing',
  isOutgoing: true,
  startedAt: Date.now(),
};

const sampleIncoming: IncomingCallData = {
  callId: 'call-2',
  callerUuid: 'caller-uuid',
  callerName: 'Alice',
  callType: 'audio',
  offer: { type: 'offer', sdp: 'v=0\r\n' },
};

describe('callingSlice – initial state', () => {
  it('has all null / false / zero defaults', () => {
    const store = makeStore();
    const s = store.getState();
    expect(s.activeCall).toBeNull();
    expect(s.incomingCall).toBeNull();
    expect(s.localStream).toBeNull();
    expect(s.remoteStream).toBeNull();
    expect(s.isAudioMuted).toBe(false);
    expect(s.isVideoOff).toBe(false);
    expect(s.callDuration).toBe(0);
  });
});

describe('callingSlice – setActiveCall', () => {
  it('sets an active call', () => {
    const store = makeStore();
    store.getState().setActiveCall(sampleCallInfo);
    expect(store.getState().activeCall).toEqual(sampleCallInfo);
  });

  it('clears the active call with null', () => {
    const store = makeStore();
    store.getState().setActiveCall(sampleCallInfo);
    store.getState().setActiveCall(null);
    expect(store.getState().activeCall).toBeNull();
  });
});

describe('callingSlice – setIncomingCall', () => {
  it('sets an incoming call', () => {
    const store = makeStore();
    store.getState().setIncomingCall(sampleIncoming);
    expect(store.getState().incomingCall).toEqual(sampleIncoming);
  });

  it('clears the incoming call with null', () => {
    const store = makeStore();
    store.getState().setIncomingCall(sampleIncoming);
    store.getState().setIncomingCall(null);
    expect(store.getState().incomingCall).toBeNull();
  });
});

describe('callingSlice – updateCallState', () => {
  it('modifies activeCall.state when a call is active', () => {
    const store = makeStore();
    store.getState().setActiveCall(sampleCallInfo);
    store.getState().updateCallState('connected');
    expect(store.getState().activeCall?.state).toBe('connected');
  });

  it('preserves other activeCall fields when updating state', () => {
    const store = makeStore();
    store.getState().setActiveCall(sampleCallInfo);
    store.getState().updateCallState('ended');
    const call = store.getState().activeCall!;
    expect(call.callId).toBe(sampleCallInfo.callId);
    expect(call.peerUuid).toBe(sampleCallInfo.peerUuid);
  });

  it('does nothing when there is no activeCall', () => {
    const store = makeStore();
    store.getState().updateCallState('connected');
    expect(store.getState().activeCall).toBeNull();
  });
});

describe('callingSlice – setLocalStream / setRemoteStream', () => {
  it('sets the local stream', () => {
    const store = makeStore();
    const stream = {} as MediaStream;
    store.getState().setLocalStream(stream);
    expect(store.getState().localStream).toBe(stream);
  });

  it('sets the remote stream', () => {
    const store = makeStore();
    const stream = {} as MediaStream;
    store.getState().setRemoteStream(stream);
    expect(store.getState().remoteStream).toBe(stream);
  });

  it('clears local stream with null', () => {
    const store = makeStore();
    store.getState().setLocalStream({} as MediaStream);
    store.getState().setLocalStream(null);
    expect(store.getState().localStream).toBeNull();
  });
});

describe('callingSlice – toggleAudio', () => {
  it('flips isAudioMuted from false to true', () => {
    const store = makeStore();
    store.getState().toggleAudio();
    expect(store.getState().isAudioMuted).toBe(true);
  });

  it('flips isAudioMuted from true to false', () => {
    const store = makeStore();
    store.getState().toggleAudio();
    store.getState().toggleAudio();
    expect(store.getState().isAudioMuted).toBe(false);
  });
});

describe('callingSlice – toggleVideo', () => {
  it('flips isVideoOff from false to true', () => {
    const store = makeStore();
    store.getState().toggleVideo();
    expect(store.getState().isVideoOff).toBe(true);
  });

  it('flips isVideoOff from true to false', () => {
    const store = makeStore();
    store.getState().toggleVideo();
    store.getState().toggleVideo();
    expect(store.getState().isVideoOff).toBe(false);
  });
});

describe('callingSlice – setCallDuration', () => {
  it('sets duration in seconds', () => {
    const store = makeStore();
    store.getState().setCallDuration(120);
    expect(store.getState().callDuration).toBe(120);
  });

  it('replaces a previous duration', () => {
    const store = makeStore();
    store.getState().setCallDuration(60);
    store.getState().setCallDuration(90);
    expect(store.getState().callDuration).toBe(90);
  });
});

describe('callingSlice – resetCalling', () => {
  it('resets all fields to their initial values', () => {
    const store = makeStore();
    const stream = {} as MediaStream;
    store.getState().setActiveCall(sampleCallInfo);
    store.getState().setIncomingCall(sampleIncoming);
    store.getState().setLocalStream(stream);
    store.getState().setRemoteStream(stream);
    store.getState().toggleAudio();
    store.getState().toggleVideo();
    store.getState().setCallDuration(300);

    store.getState().resetCalling();

    const s = store.getState();
    expect(s.activeCall).toBeNull();
    expect(s.incomingCall).toBeNull();
    expect(s.localStream).toBeNull();
    expect(s.remoteStream).toBeNull();
    expect(s.isAudioMuted).toBe(false);
    expect(s.isVideoOff).toBe(false);
    expect(s.callDuration).toBe(0);
  });
});
