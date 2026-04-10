# WebSocket Protocol

The go-signal server exposes two WebSocket endpoints for real-time communication:

- `GET /v1/websocket/` - Authenticated messaging sessions
- `GET /v1/websocket/provisioning` - Device provisioning sessions

Both endpoints use the `coder/websocket` library (`github.com/coder/websocket`) for the WebSocket upgrade and connection management.

## Frame Format

The server supports two frame formats, detected automatically from the first message received on the connection:

- **JSON (text frames)** - Used by Go test clients and debugging tools
- **Protobuf (binary frames)** - Used by signal-cli and the official Signal apps

The format is locked for the session lifetime after the first message arrives. Binary WebSocket messages select protobuf; text messages select JSON.

## Message Structure

Every WebSocket frame carries a single `WebSocketMessage`, which wraps either a request or a response:

```json
{
  "type": "request",
  "request": {
    "id": 1,
    "verb": "PUT",
    "path": "/api/v1/message",
    "body": "base64-encoded-body",
    "headers": {
      "Content-Type": "application/json"
    }
  }
}
```

```json
{
  "type": "response",
  "response": {
    "id": 1,
    "status": 200,
    "message": "OK",
    "body": "base64-encoded-body",
    "headers": {}
  }
}
```

The `id` field correlates responses to their originating requests. Both the client and server can initiate requests. Body payloads are base64-encoded in both directions.

## Authenticated Sessions

When a client connects to `/v1/websocket/`, authentication happens during the upgrade. Credentials can be provided via:

1. **HTTP Basic Auth header** - Standard `Authorization: Basic base64(uuid.deviceId:password)` header
2. **Query parameters** - `?login=uuid.deviceId&password=auth-token`

After a successful upgrade, the server:

1. Starts the write pump goroutine for outbound messages
2. Registers the session with the `SessionManager`
3. Flushes all pending messages to the client as `PUT /api/v1/message` requests
4. Enters the read pump loop to process incoming frames

### Server-to-Client Message Delivery

When a new message arrives for a connected client, the server sends a request frame:

```json
{
  "type": "request",
  "request": {
    "id": 42,
    "verb": "PUT",
    "path": "/api/v1/message",
    "body": "base64-encoded-envelope-json"
  }
}
```

The client acknowledges receipt by sending a response with the matching `id`:

```json
{
  "type": "response",
  "response": {
    "id": 42,
    "status": 200,
    "message": "OK"
  }
}
```

### Client-to-Server Requests

Clients can issue any REST API call through the WebSocket by sending a request frame. The server routes these through the HTTP handler chain, meaning the same handler code processes both REST and WebSocket requests. This mirrors the Java Signal-Server's `WebSocketResourceProvider` pattern.

For example, to send a typing indicator:

```json
{
  "type": "request",
  "request": {
    "id": 5,
    "verb": "PUT",
    "path": "/v1/messages/recipient-uuid",
    "body": "base64-encoded-json-body",
    "headers": {
      "Content-Type": "application/json"
    }
  }
}
```

The server sets Basic Auth credentials on the internal HTTP request using the session's stored UUID and auth token, so auth middleware passes without the client needing to re-authenticate.

### Built-in Request Handlers

Two paths are handled directly without routing through the HTTP handler:

| Verb | Path | Purpose |
|------|------|---------|
| GET | `/api/v1/keepalive` | Client keepalive ping |
| PUT | `/api/v1/message` | Message acknowledgment |

Both return a `200 OK` response frame.

## Provisioning Sessions

The provisioning WebSocket at `/v1/websocket/provisioning` does not require authentication. It is used during the device-linking flow.

After the connection upgrades, the server:

1. Generates a unique provisioning address (UUID)
2. Registers a temporary session (device ID 0) with the `SessionManager`
3. Sends the provisioning address to the client as a request:

```json
{
  "type": "request",
  "request": {
    "id": 1,
    "verb": "PUT",
    "path": "/v1/address",
    "body": "base64-of-{\"uuid\":\"provisioning-address-uuid\"}"
  }
}
```

The primary device then calls `PUT /v1/provisioning/{destination}` (a REST endpoint) to send the provisioning message to the waiting secondary device. The `SessionManager` delivers this to the provisioning session over the WebSocket.

## Session Management

The `SessionManager` (in `pkg/websocket/`) tracks all active sessions by account UUID and device ID. It provides:

- **Register/Unregister** - Called on connect/disconnect to maintain the active session map
- **Message delivery** - Routes messages to the correct session's send channel
- **Session lookup** - Find sessions by UUID for provisioning message delivery

Sessions are automatically unregistered when the read pump exits (connection close, error, or server shutdown).

## Keepalive

The server sends periodic pings every 30 seconds to detect dead connections. If no pong response arrives within 10 seconds, the connection is considered dead and closed.

The write pump handles ping/pong at the WebSocket protocol level. Clients can also send application-level keepalive requests to `GET /api/v1/keepalive`, which the server responds to with a `200 OK` frame.

The write timeout for individual messages is 10 seconds. The send buffer holds up to 256 outbound messages per session.

## Connection Lifecycle

```
Client                                          Server
  |                                                |
  |--- GET /v1/websocket/ (upgrade) -------------->|
  |<-- 101 Switching Protocols --------------------|
  |                                                |
  |                              [register session]|
  |                              [start write pump]|
  |                                                |
  |<-- PUT /api/v1/message (pending msg 1) --------|
  |--- response {id:1, status:200} --------------->|
  |<-- PUT /api/v1/message (pending msg 2) --------|
  |--- response {id:2, status:200} --------------->|
  |                                                |
  |              ... real-time messaging ...        |
  |                                                |
  |<-- ping -------- [every 30s] ------------------|
  |--- pong ------->                                |
  |                                                |
  |--- GET /api/v1/keepalive --------------------->|
  |<-- response {status:200} ----------------------|
  |                                                |
  |--- PUT /v1/messages/{dest} (via WS) ---------->|
  |              [routed through HTTP handler]      |
  |<-- response {status:200, body:...} ------------|
  |                                                |
  |--- close ------>                                |
  |                            [unregister session]|
```
