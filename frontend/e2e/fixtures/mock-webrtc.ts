import { Page } from '@playwright/test';

/**
 * setupMockWebRTC injects mock implementations for navigator.mediaDevices.getUserMedia
 * and RTCPeerConnection so that calling tests can run in headless Playwright without
 * real camera/microphone access or WebRTC connectivity.
 */
export async function setupMockWebRTC(page: Page): Promise<void> {
  await page.addInitScript(() => {
    // --- Mock getUserMedia ---
    // Creates a fake MediaStream from a canvas + silent audio oscillator.
    const origGetUserMedia = navigator.mediaDevices?.getUserMedia?.bind(navigator.mediaDevices);

    navigator.mediaDevices.getUserMedia = async (_constraints?: MediaStreamConstraints) => {
      const canvas = document.createElement('canvas');
      canvas.width = 640;
      canvas.height = 480;
      const ctx = canvas.getContext('2d');
      if (ctx) {
        ctx.fillStyle = '#333';
        ctx.fillRect(0, 0, 640, 480);
        ctx.fillStyle = '#fff';
        ctx.font = '24px sans-serif';
        ctx.fillText('Mock Camera', 200, 240);
      }
      const stream = canvas.captureStream(15);

      // Add a fake audio track via AudioContext.
      try {
        const audioCtx = new AudioContext();
        const oscillator = audioCtx.createOscillator();
        oscillator.frequency.setValueAtTime(0, audioCtx.currentTime); // silent
        const dest = audioCtx.createMediaStreamDestination();
        oscillator.connect(dest);
        oscillator.start();
        const audioTrack = dest.stream.getAudioTracks()[0];
        if (audioTrack) stream.addTrack(audioTrack);
      } catch {
        // AudioContext may not be available in all test environments.
      }

      return stream;
    };

    // --- Mock RTCPeerConnection ---
    const MockRTCPeerConnection = class {
      localDescription: RTCSessionDescriptionInit | null = null;
      remoteDescription: RTCSessionDescriptionInit | null = null;
      connectionState: RTCPeerConnectionState = 'new';
      iceConnectionState: RTCIceConnectionState = 'new';
      signalingState: RTCSignalingState = 'stable';

      onicecandidate: ((event: any) => void) | null = null;
      ontrack: ((event: any) => void) | null = null;
      onconnectionstatechange: (() => void) | null = null;

      private senders: any[] = [];

      addTrack(track: MediaStreamTrack, stream: MediaStream) {
        this.senders.push({ track, stream });
        return { track };
      }

      getSenders() {
        return this.senders;
      }

      async createOffer(): Promise<RTCSessionDescriptionInit> {
        return { type: 'offer', sdp: 'mock-sdp-offer' };
      }

      async createAnswer(): Promise<RTCSessionDescriptionInit> {
        return { type: 'answer', sdp: 'mock-sdp-answer' };
      }

      async setLocalDescription(desc: RTCSessionDescriptionInit) {
        this.localDescription = desc;
      }

      async setRemoteDescription(desc: RTCSessionDescriptionInit) {
        this.remoteDescription = desc;
        // Simulate connection established after remote description is set.
        setTimeout(() => {
          this.connectionState = 'connected';
          this.iceConnectionState = 'connected';
          if (this.onconnectionstatechange) this.onconnectionstatechange();
        }, 100);
      }

      async addIceCandidate(_candidate: RTCIceCandidateInit) {
        // No-op in mock.
      }

      close() {
        this.connectionState = 'closed';
        this.iceConnectionState = 'closed';
      }
    };

    // @ts-ignore
    window.RTCPeerConnection = MockRTCPeerConnection;
    // @ts-ignore
    window.RTCSessionDescription = class {
      type: string;
      sdp: string;
      constructor(init: RTCSessionDescriptionInit) {
        this.type = init.type || '';
        this.sdp = init.sdp || '';
      }
    };
    // @ts-ignore
    window.RTCIceCandidate = class {
      candidate: string;
      sdpMid: string | null;
      sdpMLineIndex: number | null;
      constructor(init: RTCIceCandidateInit) {
        this.candidate = init.candidate || '';
        this.sdpMid = init.sdpMid || null;
        this.sdpMLineIndex = init.sdpMLineIndex ?? null;
      }
      toJSON() {
        return { candidate: this.candidate, sdpMid: this.sdpMid, sdpMLineIndex: this.sdpMLineIndex };
      }
    };
  });
}
