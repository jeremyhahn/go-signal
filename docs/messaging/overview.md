# Messaging

The messaging subsystem handles storing, retrieving, and delivering encrypted message envelopes between Signal clients. All message content is opaque to the server -- it stores and forwards encrypted bytes without inspecting them.

## Envelope Types

Every message has an `EnvelopeType` that identifies the cryptographic message format:

| Type | Value | Description |
|---|---|---|
| Ciphertext | 1 | Standard Signal protocol message within an established session |
| KeyExchange | 2 | Key exchange message during session negotiation |
| PreKeyBundle | 3 | Pre-key bundle for asynchronous session establishment |
| Receipt | 5 | Delivery or read receipt |
| UnidentifiedSender | 6 | Sealed-sender message with encrypted sender identity |
| PlaintextContent | 8 | Plaintext protocol messages (e.g., sender key distribution) |

## Data Types

### Envelope

The core storage unit. Each envelope represents one encrypted message waiting to be delivered to a specific device.

```go
type Envelope struct {
    ID                uint64       `json:"id"`
    Type              EnvelopeType `json:"type"`
    SourceUUID        string       `json:"sourceUuid,omitempty"`
    SourceDevice      uint32       `json:"sourceDevice,omitempty"`
    DestinationUUID   string       `json:"destinationUuid"`
    DestinationDevice uint64       `json:"destinationDevice"`
    Timestamp         uint64       `json:"timestamp"`
    ServerTimestamp   uint64       `json:"serverTimestamp"`
    Content           []byte       `json:"content"`
    ServerGUID        string       `json:"serverGuid"`
    Urgent            bool         `json:"urgent"`
    Story             bool         `json:"story"`
    ReportSpamToken   []byte       `json:"reportSpamToken,omitempty"`
}
```

The `ServerGUID` and `ServerTimestamp` fields are assigned by the server at insertion time, not by the client.

### IncomingMessage

A single message submitted by a sending client, targeting a specific device:

```go
type IncomingMessage struct {
    Type                EnvelopeType `json:"type"`
    DestinationUUID     string       `json:"destinationUuid"`
    DestinationDeviceID uint64       `json:"destinationDeviceId"`
    Content             string       `json:"content"`
    Timestamp           uint64       `json:"timestamp"`
    Urgent              bool         `json:"urgent"`
    Story               bool         `json:"story"`
}
```

### IncomingMessageList

A batch of messages from a sending client, typically one per destination device:

```go
type IncomingMessageList struct {
    Messages  []IncomingMessage `json:"messages"`
    Timestamp uint64            `json:"timestamp"`
}
```

### OutgoingMessage

A message being sent to a specific device (used internally):

```go
type OutgoingMessage struct {
    DestinationUUID   string       `json:"destinationUuid"`
    DestinationDevice uint64       `json:"destinationDevice"`
    Type              EnvelopeType `json:"type"`
    Content           []byte       `json:"content"`
    Timestamp         uint64       `json:"timestamp"`
    Urgent            bool         `json:"urgent"`
    Story             bool         `json:"story"`
}
```

### SendMessageResponse

Returned after processing an incoming message batch:

```go
type SendMessageResponse struct {
    NeedsSync bool `json:"needsSync"`
}
```

## MessagesManager

`MessagesManager` is the business logic layer for message operations. It wraps a `MessageStore` implementation and handles server-side metadata assignment.

### Operations

| Method | Description |
|---|---|
| `Insert` | Assigns a server GUID (v4 UUID) and server timestamp (Unix millis), then persists the envelope. Fires the delivery callback on success. |
| `GetMessagesForDevice` | Returns all pending envelopes for a destination device, ordered by server timestamp ascending. |
| `Delete` | Removes a single envelope by its server GUID. Idempotent. |
| `DeleteForDevice` | Removes all pending envelopes for a specific device. |
| `DeleteForAccount` | Removes all pending messages across all devices for an account. |

### Delivery Callback

The `MessagesManager` accepts an optional `DeliveryCallback`:

```go
type DeliveryCallback func(uuid string, deviceID uint64, envelope *Envelope)
```

After a message is successfully stored, the callback fires. The WebSocket `SessionManager` registers this callback to push messages to connected clients in real time. If the recipient has an active WebSocket session when a message arrives, it gets delivered immediately without the client needing to poll.

## MessageStore Interface

`MessageStore` defines the storage contract. Any backend that satisfies this interface can be plugged in.

```go
type MessageStore interface {
    Insert(ctx context.Context, destinationUUID string, destinationDevice uint64, envelope *Envelope) (uint64, error)
    GetMessagesForDevice(ctx context.Context, destinationUUID string, destinationDevice uint64) ([]*Envelope, error)
    Delete(ctx context.Context, destinationUUID string, serverGUID string) error
    DeleteForDevice(ctx context.Context, destinationUUID string, destinationDevice uint64) error
    DeleteForAccount(ctx context.Context, uuid string) error
}
```

The in-memory implementation lives in `pkg/storage/memory/`.

## REST Endpoints

The REST API exposes five message-related endpoints:

| Method | Path | Description |
|---|---|---|
| `PUT` | `/v1/messages/{destination}` | Send a message to a destination account |
| `PUT` | `/v1/messages/multi_recipient` | Send a single message to multiple recipients |
| `GET` | `/v1/messages` | Fetch pending messages for the authenticated user |
| `DELETE` | `/v1/messages/uuid/{guid}` | Delete a specific message by server GUID |
| `POST` | `/v1/messages/report/{source}/{messageGuid}` | Report a message as spam |

All endpoints require authentication. The send endpoints accept an `IncomingMessageList` body and return a `SendMessageResponse`.

## WebSocket Delivery

Messages are pushed to connected clients in real time through the WebSocket `SessionManager`. The flow works like this:

1. A sending client submits a message via `PUT /v1/messages/{destination}`.
2. The REST handler calls `MessagesManager.Insert`, which stores the envelope and assigns server metadata.
3. After successful storage, `Insert` invokes the registered `DeliveryCallback`.
4. The callback checks whether the recipient has an active WebSocket session.
5. If they do, the envelope is pushed immediately over the WebSocket connection.
6. If they don't, the message stays in the store until the recipient connects and calls `GET /v1/messages`.

This two-path delivery model means clients get messages instantly when online, and nothing is lost when they're offline.
