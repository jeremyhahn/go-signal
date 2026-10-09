# WebSocket Protocol

> **Status: REFERENCE** · Last verified: 2026-10-09
> As-built description of the go-signal WebSocket endpoints (`pkg/api/websocket`, `pkg/websocket`).

The server exposes WebSocket endpoints on the REST listener (`pkg/api/rest/server.go`):

- `GET /v1/websocket/` - messaging sessions. With credentials the session is authenticated; without them it is an unauthenticated session that only serves WebSocket-wrapped HTTP requests (for example remote config).
- `GET /v1/websocket/provisioning` (and `/v1/websocket/provisioning/`) - device provisioning sessions.

`handleWebSocket` (`pkg/api/rest/handlers_websocket.go`) picks the authenticated handler when the request has a Basic header or a `login` query parameter, otherwise the unauthenticated one. If no WebSocket handler is configured it returns `503`.

The upgrade uses `github.com/coder/websocket`. When `server.allowedOrigins` is non-empty only those origins are accepted; otherwise the library's same-origin check applies.

## Frame Format

Two frame formats are supported, detected from the first inbound frame:

- **JSON (text frames)** - test clients and debugging tools.
- **Protobuf (binary frames)** - signal-cli and the official apps.

The format is set once, by the first frame (`Session.setFormat`), and stays for the session. The provisioning handler forces protobuf before it sends anything. The maximum inbound frame is 256 KB (`maxFrameSize`).

## Message Structure

Every frame carries one `WebSocketMessage`, wrapping a request or a response. JSON form:

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

`id` correlates a response with its request. Either side can send requests. Bodies are base64 in the JSON form.

## Authenticated Sessions

`HandleAuthenticated` takes credentials from either:

1. **HTTP Basic header** - `Authorization: Basic base64(uuid[.deviceId]:password)`
2. **Query parameters** - `?login=uuid[.deviceId]&password=auth-token`

A missing credential returns `401 missing credentials`. The `.deviceId` suffix is stripped and ignored: the password is always verified against the account's **primary** device (`AuthTokenHash.Verify`), and the session is registered as the primary device (`accounts.PrimaryDeviceID`). A linked device therefore cannot hold its own authenticated WebSocket with its own token. This differs from the REST and gRPC middleware, which verify the addressed device. An unknown account performs a dummy hash verification to equalise timing.

After the upgrade the server:

1. Starts the write pump.
2. Registers the session with the `SessionManager`.
3. Sends every pending message for the device as a `PUT /api/v1/message` request.
4. Runs the read pump until the connection closes.

### Server-to-Client Message Delivery

Each message is a request whose body is the base64 of the envelope's **protobuf** wire form (`messages.MarshalEnvelope`), not JSON. The pending-message flush numbers requests from 1.

```json
{
  "type": "request",
  "request": {
    "id": 42,
    "verb": "PUT",
    "path": "/api/v1/message",
    "body": "base64-of-protobuf-envelope"
  }
}
```

The client acknowledges with a response carrying the same `id`. The server logs the acknowledgement at debug level and takes no other action on it.

### Client-to-Server Requests

Any request other than the two built-ins below is forwarded to the REST handler chain, as in Java's `WebSocketResourceProvider`. The server builds an in-memory HTTP request from the frame:

- the body is base64-decoded (`400` on bad encoding);
- the frame's headers are copied; `Content-Type: application/json` is added when a body is present and none is set;
- Basic credentials are set from the session's UUID and sealed password (no device suffix), so the REST auth middleware authenticates it as the primary device;
- the response status, headers (first value of each) and base64 body come back in a response frame.

With no HTTP handler configured the reply is `404`.

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

### Built-in Request Handlers

| Verb | Path | Purpose |
|---|---|---|
| GET | `/api/v1/keepalive` | Client keepalive |
| PUT | `/api/v1/message` | Message acknowledgment |

Both reply `200 OK` directly.

## Unauthenticated Sessions

`HandleUnauthenticated` upgrades without credentials. The session gets a random UUID and device ID 0, no stored password, and handles the same built-ins and HTTP-wrapped requests. Because it has no credentials, routed requests carry no Basic header.

## Provisioning Sessions

`/v1/websocket/provisioning` needs no authentication. After the upgrade the server:

1. Generates a provisioning address: 16 random bytes, base64url without padding.
2. Registers a session under that address with device ID 0.
3. Forces protobuf framing and sends the address as a request:

```json
{
  "type": "request",
  "request": {
    "id": 1,
    "verb": "PUT",
    "path": "/v1/address",
    "body": "base64-of-protobuf-ProvisioningAddress",
    "headers": {"X-Signal-Timestamp": "1760000000000"}
  }
}
```

The body is a protobuf `ProvisioningAddress` (`pkg/websocket/wsproto`). `X-Signal-Timestamp` is the current time in milliseconds.

The primary device then calls `PUT /v1/provisioning/{destination}` (REST, authenticated) and the `SessionManager` delivers the message to the waiting socket. Responses the client sends on this socket are only logged.

## Session Management

`SessionManager` (`pkg/websocket/manager.go`) tracks sessions by account UUID and device ID:

- `Register` / `Unregister` - on connect and disconnect.
- `DeliverMessage`, `NotifyMessageAvailable` - route a message to the live session's send channel; `NotifyMessageAvailable` also publishes a wake-up through the cache (`NewSessionManagerWithCache`) for cross-instance delivery.
- `GetSession`, `HasActiveSession` - lookup.
- `CloseAll` - shutdown.

A session unregisters when its read pump exits (close, error, shutdown).

## Keepalive

The write pump pings every 30 seconds (`pingInterval`). A ping with no pong within 10 seconds (`pongTimeout`) ends the write pump, which closes the session. Clients may also send `GET /api/v1/keepalive`. Each outbound write has a 10 second timeout (`writeTimeout`), and the send buffer holds 256 messages per session (`sendBufferSize`).

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
