# Messaging

> **Status: REFERENCE** · Last verified: 2026-10-09
> Message types, the `MessagesManager`, the `MessageStore` contract, the REST endpoints and real-time delivery.

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
    DestinationIdentityType accounts.IdentityType `json:"destinationIdentityType,omitempty"`
    DestinationDevice uint64       `json:"destinationDevice"`
    Timestamp         uint64       `json:"timestamp"`
    ServerTimestamp   uint64       `json:"serverTimestamp"`
    Content           []byte       `json:"content"`
    ServerGUID        string       `json:"serverGuid"`
    Urgent            bool         `json:"urgent"`
    Story             bool         `json:"story"`
    ReportSpamToken   []byte       `json:"reportSpamToken,omitempty"`
    SharedMrmKey           []byte  `json:"sharedMrmKey,omitempty"`
    SharedMrmRecipientView []byte  `json:"sharedMrmRecipientView,omitempty"`
}
```

`ServerTimestamp` is always assigned by the server at insertion. `ServerGUID` is assigned at insertion unless the caller already set one. `DestinationIdentityType` selects whether `DestinationUUID` is an ACI or a PNI; the zero value is ACI. `SharedMrmKey` and `SharedMrmRecipientView` reference a shared multi-recipient payload in the MRM cache; `Content` is empty for such an envelope until it is rehydrated on read.

### IncomingMessage

A single message submitted by a sending client, targeting a specific device:

```go
type IncomingMessage struct {
    Type                EnvelopeType `json:"type"`
    DestinationUUID     string       `json:"destinationUuid"`
    DestinationIdentityType accounts.IdentityType `json:"destinationIdentityType,omitempty"`
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

A message being sent to a specific device:

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
| `Insert` | Rejects a nil envelope. Assigns a server GUID (v4 UUID) unless one is already set, and a server timestamp (Unix millis), then persists the envelope. Fires the delivery callback on success. |
| `GetMessagesForDevice` | Returns all pending envelopes for a destination device, in insertion order (the stores order by insertion sequence). When an MRM cache is set (`SetMRMCache`), rehydrates envelopes that carry a `SharedMrmKey`; envelopes whose shared data is gone are dropped and deleted from the store. |
| `HasMessagesForDevice` | Reports whether the device has at least one pending envelope without loading them. |
| `Delete` | Removes a single envelope by its server GUID; an empty GUID is rejected. |
| `DeleteForDevice` | Removes all pending envelopes for a specific device. |
| `DeleteForAccount` | Removes all pending messages across all devices for an account. |
| `RemoveExpired` | Removes envelopes whose `expires_at` is before a cutoff; returns the count. Used by the remove-expired-messages worker. |

### Delivery Callback

The `MessagesManager` accepts an optional `DeliveryCallback`:

```go
type DeliveryCallback func(uuid string, deviceID uint64, envelope *Envelope)
```

After a message is successfully stored, the callback fires. `cmd/signald/start.go` registers a callback that:

1. delivers the envelope to a live WebSocket session on this instance (`wsSessions.DeliverMessage`) and stops if that succeeds;
2. otherwise sends a cross-instance wake-up (`NotifyMessageAvailable`);
3. then, in a goroutine, schedules a push notification for devices that have an APNs or FCM registration and do not fetch messages themselves.

## MessageStore Interface

`MessageStore` defines the storage contract. Any backend that satisfies this interface can be plugged in.

```go
type MessageStore interface {
    Insert(ctx context.Context, destinationUUID string, destinationDevice uint64, envelope *Envelope) (uint64, error)
    GetMessagesForDevice(ctx context.Context, destinationUUID string, destinationDevice uint64) ([]*Envelope, error)
    Delete(ctx context.Context, destinationUUID string, serverGUID string) error
    DeleteForDevice(ctx context.Context, destinationUUID string, destinationDevice uint64) error
    DeleteForAccount(ctx context.Context, uuid string) error
    RemoveExpired(ctx context.Context, before time.Time) (int64, error)
    HasMessagesForDevice(ctx context.Context, destinationUUID string, destinationDevice uint64) (bool, error)
}
```

Implementations are in `pkg/storage/memory/`, `pkg/storage/postgres/` and `pkg/storage/qrdb/`. Memory and qrdb record no expiry, so `RemoveExpired` returns `0, nil` there.

## REST Endpoints

The REST API exposes five message-related endpoints:

| Method | Path | Description |
|---|---|---|
| `PUT` | `/v1/messages/{destination}` | Send a message to a destination account |
| `PUT` | `/v1/messages/multi_recipient` | Send a single message to multiple recipients |
| `GET` | `/v1/messages` | Fetch pending messages for the authenticated user |
| `DELETE` | `/v1/messages/uuid/{guid}` | Delete a specific message by server GUID |
| `POST` | `/v1/messages/report/{source}/{messageGuid}` | Report a message as spam |

The two send endpoints accept either Basic auth or an `Unidentified-Access-Key` header (sealed sender), and are rate limited. The other three require Basic auth. The send endpoints accept an `IncomingMessageList` body and return a `SendMessageResponse`.

## WebSocket Delivery

Messages are pushed to connected clients in real time through the WebSocket `SessionManager`. The flow is:

1. A sending client submits a message via `PUT /v1/messages/{destination}`.
2. The REST handler calls `MessagesManager.Insert`, which stores the envelope and assigns server metadata.
3. After successful storage, `Insert` invokes the registered `DeliveryCallback`.
4. The callback delivers to a local WebSocket session if one exists.
5. If not, it sends a cross-instance wake-up and schedules a push notification.
6. The envelope stays in the store until the recipient connects and fetches it (WebSocket queue or `GET /v1/messages`) and the envelope is deleted.
