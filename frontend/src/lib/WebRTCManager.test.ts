import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { WebRTCManager, type WebRTCCallbacks } from './WebRTCManager';
import type { TurnCredentials } from '../sdk/ISignalClient';

// ---------------------------------------------------------------------------
// RTCPeerConnection mock
// ---------------------------------------------------------------------------

class MockPeerConnection {
  iceServers: RTCIceServer[];
  onicecandidate: ((e: RTCPeerConnectionIceEvent) => void) | null = null;
  ontrack: ((e: RTCTrackEvent) => void) | null = null;
  onconnectionstatechange: (() => void) | null = null;
  connectionState: RTCPeerConnectionState = 'new';

  addTrack = vi.fn();
  createOffer = vi.fn().mockResolvedValue({ type: 'offer', sdp: 'offer-sdp' });
  createAnswer = vi.fn().mockResolvedValue({ type: 'answer', sdp: 'answer-sdp' });
  setLocalDescription = vi.fn().mockResolvedValue(undefined);
  setRemoteDescription = vi.fn().mockResolvedValue(undefined);
  addIceCandidate = vi.fn().mockResolvedValue(undefined);
  close = vi.fn();

  constructor(config: RTCConfiguration) {
    this.iceServers = config.iceServers as RTCIceServer[];
  }
}

// Minimal MediaStreamTrack stub.
function makeMockTrack(kind: 'audio' | 'video'): MediaStreamTrack {
  return {
    kind,
    enabled: true,
    stop: vi.fn(),
  } as unknown as MediaStreamTrack;
}

// Minimal MediaStream stub.
function makeMockStream(kinds: ('audio' | 'video')[]): MediaStream {
  const tracks = kinds.map(makeMockTrack);
  return {
    getTracks: () => tracks,
    getAudioTracks: () => tracks.filter((t) => t.kind === 'audio'),
    getVideoTracks: () => tracks.filter((t) => t.kind === 'video'),
  } as unknown as MediaStream;
}

// ---------------------------------------------------------------------------
// Setup
// ---------------------------------------------------------------------------

let manager: WebRTCManager;
let callbacks: WebRTCCallbacks;
let mockPc: MockPeerConnection;

const turnCredentials: TurnCredentials = {
  relays: [
    { username: 'user1', password: 'pass1', ttl: 86400, urls: ['turn:turn.example.com:3478'] },
  ],
};

beforeEach(() => {
  callbacks = {
    onLocalStream: vi.fn(),
    onRemoteStream: vi.fn(),
    onIceCandidate: vi.fn(),
    onConnectionStateChange: vi.fn(),
  };

  vi.stubGlobal('RTCPeerConnection', vi.fn().mockImplementation((config: RTCConfiguration) => {
    mockPc = new MockPeerConnection(config);
    return mockPc;
  }));

  vi.stubGlobal('RTCSessionDescription', vi.fn().mockImplementation((init: RTCSessionDescriptionInit) => init));
  vi.stubGlobal('RTCIceCandidate', vi.fn().mockImplementation((init: RTCIceCandidateInit) => init));

  manager = new WebRTCManager(callbacks);
});

afterEach(() => {
  manager.destroy();
  vi.restoreAllMocks();
});

// ---------------------------------------------------------------------------
// initialize
// ---------------------------------------------------------------------------

describe('WebRTCManager – initialize', () => {
  it('creates RTCPeerConnection with ICE servers from TURN credentials', async () => {
    await manager.initialize(turnCredentials);

    expect(vi.mocked(RTCPeerConnection)).toHaveBeenCalledWith({
      iceServers: [
        { urls: ['turn:turn.example.com:3478'], username: 'user1', credential: 'pass1' },
      ],
    });
  });

  it('maps multiple relay entries to ICE servers', async () => {
    const multiRelay: TurnCredentials = {
      relays: [
        { username: 'u1', password: 'p1', ttl: 3600, urls: ['turn:a.example.com'] },
        { username: 'u2', password: 'p2', ttl: 3600, urls: ['turn:b.example.com'] },
      ],
    };
    await manager.initialize(multiRelay);

    const config = vi.mocked(RTCPeerConnection).mock.calls[0][0] as RTCConfiguration;
    expect((config.iceServers as RTCIceServer[]).length).toBe(2);
  });
});

// ---------------------------------------------------------------------------
// getUserMedia
// ---------------------------------------------------------------------------

describe('WebRTCManager – getUserMedia', () => {
  beforeEach(async () => {
    await manager.initialize(turnCredentials);
  });

  it('requests audio and video for video calls', async () => {
    const stream = makeMockStream(['audio', 'video']);
    vi.stubGlobal('navigator', {
      mediaDevices: { getUserMedia: vi.fn().mockResolvedValue(stream) },
    });

    await manager.getUserMedia('video');

    expect(navigator.mediaDevices.getUserMedia).toHaveBeenCalledWith(
      expect.objectContaining({ audio: true, video: expect.objectContaining({ width: 640 }) }),
    );
  });

  it('requests audio only for audio calls', async () => {
    const stream = makeMockStream(['audio']);
    vi.stubGlobal('navigator', {
      mediaDevices: { getUserMedia: vi.fn().mockResolvedValue(stream) },
    });

    await manager.getUserMedia('audio');

    expect(navigator.mediaDevices.getUserMedia).toHaveBeenCalledWith(
      expect.objectContaining({ audio: true, video: false }),
    );
  });

  it('adds tracks to the peer connection', async () => {
    const stream = makeMockStream(['audio', 'video']);
    vi.stubGlobal('navigator', {
      mediaDevices: { getUserMedia: vi.fn().mockResolvedValue(stream) },
    });

    await manager.getUserMedia('video');

    expect(mockPc.addTrack).toHaveBeenCalledTimes(2);
  });

  it('calls onLocalStream callback with the stream', async () => {
    const stream = makeMockStream(['audio']);
    vi.stubGlobal('navigator', {
      mediaDevices: { getUserMedia: vi.fn().mockResolvedValue(stream) },
    });

    await manager.getUserMedia('audio');

    expect(callbacks.onLocalStream).toHaveBeenCalledWith(stream);
  });
});

// ---------------------------------------------------------------------------
// createOffer
// ---------------------------------------------------------------------------

describe('WebRTCManager – createOffer', () => {
  it('returns an SDP offer and sets local description', async () => {
    await manager.initialize(turnCredentials);
    const offer = await manager.createOffer();

    expect(offer).toEqual({ type: 'offer', sdp: 'offer-sdp' });
    expect(mockPc.setLocalDescription).toHaveBeenCalledWith({ type: 'offer', sdp: 'offer-sdp' });
  });

  it('throws when PeerConnection is not initialized', async () => {
    await expect(manager.createOffer()).rejects.toThrow('PeerConnection not initialized');
  });
});

// ---------------------------------------------------------------------------
// createAnswer
// ---------------------------------------------------------------------------

describe('WebRTCManager – createAnswer', () => {
  it('sets remote description and returns an answer', async () => {
    await manager.initialize(turnCredentials);
    const offerInit: RTCSessionDescriptionInit = { type: 'offer', sdp: 'remote-sdp' };

    const answer = await manager.createAnswer(offerInit);

    expect(mockPc.setRemoteDescription).toHaveBeenCalled();
    expect(answer).toEqual({ type: 'answer', sdp: 'answer-sdp' });
  });

  it('throws when PeerConnection is not initialized', async () => {
    const offerInit: RTCSessionDescriptionInit = { type: 'offer', sdp: 'sdp' };
    await expect(manager.createAnswer(offerInit)).rejects.toThrow('PeerConnection not initialized');
  });
});

// ---------------------------------------------------------------------------
// setRemoteAnswer
// ---------------------------------------------------------------------------

describe('WebRTCManager – setRemoteAnswer', () => {
  it('calls setRemoteDescription on the peer connection', async () => {
    await manager.initialize(turnCredentials);
    await manager.setRemoteAnswer({ type: 'answer', sdp: 'answer-sdp' });

    expect(mockPc.setRemoteDescription).toHaveBeenCalled();
  });

  it('throws when PeerConnection is not initialized', async () => {
    await expect(manager.setRemoteAnswer({ type: 'answer', sdp: 'sdp' })).rejects.toThrow(
      'PeerConnection not initialized',
    );
  });
});

// ---------------------------------------------------------------------------
// addIceCandidate
// ---------------------------------------------------------------------------

describe('WebRTCManager – addIceCandidate', () => {
  it('calls pc.addIceCandidate', async () => {
    await manager.initialize(turnCredentials);
    await manager.addIceCandidate({ candidate: 'candidate-str', sdpMid: '0', sdpMLineIndex: 0 });

    expect(mockPc.addIceCandidate).toHaveBeenCalled();
  });

  it('throws when PeerConnection is not initialized', async () => {
    await expect(
      manager.addIceCandidate({ candidate: 'c', sdpMid: '0', sdpMLineIndex: 0 }),
    ).rejects.toThrow('PeerConnection not initialized');
  });
});

// ---------------------------------------------------------------------------
// toggleAudio
// ---------------------------------------------------------------------------

describe('WebRTCManager – toggleAudio', () => {
  it('disables audio track and returns true (muted)', async () => {
    const stream = makeMockStream(['audio']);
    vi.stubGlobal('navigator', {
      mediaDevices: { getUserMedia: vi.fn().mockResolvedValue(stream) },
    });
    await manager.initialize(turnCredentials);
    await manager.getUserMedia('audio');

    const muted = manager.toggleAudio();

    const audioTrack = stream.getAudioTracks()[0];
    expect(audioTrack.enabled).toBe(false);
    expect(muted).toBe(true);
  });

  it('re-enables audio track on second toggle', async () => {
    const stream = makeMockStream(['audio']);
    vi.stubGlobal('navigator', {
      mediaDevices: { getUserMedia: vi.fn().mockResolvedValue(stream) },
    });
    await manager.initialize(turnCredentials);
    await manager.getUserMedia('audio');

    manager.toggleAudio();
    const muted = manager.toggleAudio();

    expect(stream.getAudioTracks()[0].enabled).toBe(true);
    expect(muted).toBe(false);
  });

  it('returns false when there is no local stream', () => {
    expect(manager.toggleAudio()).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// toggleVideo
// ---------------------------------------------------------------------------

describe('WebRTCManager – toggleVideo', () => {
  it('disables video track and returns true (video off)', async () => {
    const stream = makeMockStream(['audio', 'video']);
    vi.stubGlobal('navigator', {
      mediaDevices: { getUserMedia: vi.fn().mockResolvedValue(stream) },
    });
    await manager.initialize(turnCredentials);
    await manager.getUserMedia('video');

    const off = manager.toggleVideo();

    expect(stream.getVideoTracks()[0].enabled).toBe(false);
    expect(off).toBe(true);
  });

  it('returns true when there is no local stream', () => {
    expect(manager.toggleVideo()).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// destroy
// ---------------------------------------------------------------------------

describe('WebRTCManager – destroy', () => {
  it('stops all tracks and closes the connection', async () => {
    const stream = makeMockStream(['audio', 'video']);
    vi.stubGlobal('navigator', {
      mediaDevices: { getUserMedia: vi.fn().mockResolvedValue(stream) },
    });
    await manager.initialize(turnCredentials);
    await manager.getUserMedia('video');

    manager.destroy();

    for (const track of stream.getTracks()) {
      expect(track.stop).toHaveBeenCalled();
    }
    expect(mockPc.close).toHaveBeenCalled();
  });
});

// ---------------------------------------------------------------------------
// Callbacks fired by PC events
// ---------------------------------------------------------------------------

describe('WebRTCManager – PC event callbacks', () => {
  it('onicecandidate fires onIceCandidate callback', async () => {
    await manager.initialize(turnCredentials);
    const candidate = { candidate: 'c', sdpMid: '0', sdpMLineIndex: 0 } as RTCIceCandidate;

    mockPc.onicecandidate?.({ candidate } as RTCPeerConnectionIceEvent);

    expect(callbacks.onIceCandidate).toHaveBeenCalledWith(candidate);
  });

  it('ontrack fires onRemoteStream callback', async () => {
    await manager.initialize(turnCredentials);
    const stream = makeMockStream(['audio']);
    mockPc.ontrack?.({ streams: [stream] } as unknown as RTCTrackEvent);

    expect(callbacks.onRemoteStream).toHaveBeenCalledWith(stream);
  });

  it('onconnectionstatechange fires onConnectionStateChange callback', async () => {
    await manager.initialize(turnCredentials);
    (mockPc as any).connectionState = 'connected';
    mockPc.onconnectionstatechange?.();

    expect(callbacks.onConnectionStateChange).toHaveBeenCalledWith('connected');
  });
});
