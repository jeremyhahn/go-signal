# Redis key conventions

The Redis cache is used for cross-request state that the KV storage
layer either can't serve (pub/sub) or shouldn't (hot paths like
rate-limit counters). All keys live under category prefixes so an
operator can scope `KEYS` / `SCAN` operations cleanly.

The cache interface is defined in `pkg/cache/cache.go`. Both the
in-memory and Redis implementations obey the same key layout.

## Leader election (workers)

| Key pattern             | Type       | TTL            | Purpose                                       |
|-------------------------|------------|----------------|-----------------------------------------------|
| `workers:lease:{name}`  | string     | configurable   | Leader-election lease for a worker `name`.    |

The token stored is a random 16-byte hex string, matched on release so
an expired+re-acquired lease isn't accidentally released by the
previous holder. Default lease TTL is 30 seconds.

## Rate-limit counters (Phase 2.1+)

| Key pattern                  | Type     | TTL        | Purpose                              |
|------------------------------|----------|------------|--------------------------------------|
| `rl:{bucket}:{identifier}`   | counter  | per-bucket | Token-bucket / leaky-bucket counter. |

Bucket names and TTLs come from `config.LimitsConfig`.

## Message availability (Phase 2.4)

| Key pattern                       | Type     | TTL        | Purpose                                         |
|-----------------------------------|----------|------------|-------------------------------------------------|
| `hasMessages:{aci}:{device}`      | boolean  | 24h        | Flag set when the queue for a device is non-empty. |
| `q:{aci}:{device}`                | zset     | 24h        | Sorted set of message GUIDs awaiting delivery.  |

## Multi-recipient message (MRM) payloads (Phase 2.4)

| Key pattern           | Type     | TTL        | Purpose                                                  |
|-----------------------|----------|------------|----------------------------------------------------------|
| `mrm:{sharedHash}`    | hash     | 24h        | Shared ciphertext + per-recipient view fields.           |

Direct port of Java Signal-Server's MRM optimisation. One hash per
multi-recipient envelope; each recipient's view field carries their
per-device RE-encrypted copy.

## Pub/sub channels

| Channel pattern                 | Purpose                                             |
|---------------------------------|-----------------------------------------------------|
| `presence:{aci}:{device}`       | WebSocket cross-instance delivery signal.           |
| `disconnect:{aci}`              | Force-disconnect broadcast for account changes.     |

Publishers: REST/gRPC message handlers and the worker that notices new
messages while a WebSocket is open elsewhere.
Subscribers: the WebSocket session manager on every running instance.

## Push challenges

| Key pattern                 | Type     | TTL        | Purpose                               |
|-----------------------------|----------|------------|---------------------------------------|
| `pushChallenge:{challenge}` | string   | 10m        | Client push-challenge validation.     |

## Delivery-loop detection

| Key pattern                | Type     | TTL       | Purpose                                |
|----------------------------|----------|-----------|----------------------------------------|
| `loopDetect:{aci}:{msg}`   | counter  | 5m        | Count repeat deliveries of same GUID.  |

## Conventions

- Keys are lowercase ASCII.
- UUIDs use the canonical `8-4-4-4-12` format, not a collapsed form.
- Binary identifiers that can't be made ASCII-safe are base64-RawURL
  encoded.
- TTLs above 1 hour are expressed in hours to keep the config readable.
- Every new key pattern added to the codebase must land here in the
  same PR.
