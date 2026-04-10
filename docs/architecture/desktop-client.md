# Desktop Client Architecture

## Overview

The go-signal desktop client provides a native desktop GUI and a self-hosted
web UI for Signal messaging. Both modes share the same Go backend (SDK) and
React frontend, differing only in how they communicate.

## Storage (Unified)

Both CLI and desktop/web modes use the same storage stack:

```
Application Code
  |
  sdk/go.Client + sdk/go.DAOStore
  |
  pkg/daostore/Factory (14 GenericDAO instances)
  |
  QRDB KVEngine + PebbleDB
  |
  ~/.config/signal/db/pebble/
```

Entity types in `pkg/daostore/entities/`:
- MessageEntity (compound indexes: ConversationID+Timestamp, ConversationID+IsRead)
- ConversationEntity
- ContactEntity
- GroupEntity
- ReactionEntity (compound index: MessageID+AuthorUUID)
- AttachmentEntity
- StickerEntity (compound index: PackID+StickerID)
- JobEntity (compound index: QueueType+Status+NextRunAt)
- CryptoSessionEntity, PreKeyEntity, SignedPreKeyEntity, IdentityKeyEntity, SenderKeyEntity
- SettingEntity

## Frontend (Dual-Mode)

The React frontend uses the `ISignalClient` adapter pattern:

```
React Components
  |
  ISignalClient interface
  |
  +-- WailsAdapter (desktop: calls Go bindings via Wails runtime)
  +-- WebAdapter (web: calls REST /api/v1/* + WebSocket /api/v1/events)
```

The `factory.ts` auto-detects the runtime environment.

## Desktop Mode

- **Build tag**: `desktop` (gates Wails dependency)
- **Binary**: `signal` built with `-tags desktop,fido2`
- **GUI**: Wails v2 webview (WebKit on Linux/macOS, WebView2 on Windows)
- **Entry**: `cmd/signal/main.go` -> `pkg/desktop/desktop.go` -> `pkg/desktop/app.go`

## Web UI Mode

- **Served by**: signald server
- **Frontend**: embedded via `internal/frontend/frontend.go` (embed.FS)
- **Client API**: `pkg/api/rest/handlers_webui.go` (/api/v1/* REST endpoints)
- **Events**: `pkg/api/rest/handlers_webui_events.go` (/api/v1/events WebSocket)
- **SPA routing**: `pkg/api/rest/handlers_frontend.go` (catch-all with caching)

## Calling

Audio/video calls use the browser's native WebRTC stack:
- **Go backend**: Call state machine + signaling relay (`pkg/desktop/calling/`)
- **Frontend**: RTCPeerConnection lifecycle (`components/Calling/`)
- **Signaling**: Offer/answer/ICE relayed via WebSocket
- **No Pion/RingRTC**: Browser provides hardware-accelerated codecs

## Build Commands

```bash
make build-cli              # CLI only
make build-desktop          # Desktop GUI (Wails)
make build-all              # Server with embedded web UI
make dev-desktop            # Desktop dev mode with hot reload
make dev-web                # Web UI dev mode (Vite + signald)
make test-desktop           # Desktop package tests
```
