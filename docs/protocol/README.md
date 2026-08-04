# Signal protocol

Documentation of Signal-protocol-level concerns as implemented in go-signal. All cryptographic primitives are provided by [go-libsignal](https://github.com/jeremyhahn/go-libsignal) — the docs here cover how go-signal wires those primitives into the server-side protocol surface.

| Document                                  | Covers                                                                |
|-------------------------------------------|-----------------------------------------------------------------------|
| [crypto.md](crypto.md) *(Phase 2)*        | Which go-libsignal packages power which server features.              |
| [pni.md](pni.md)                          | ACI vs PNI identity types, key namespacing, dual identifier routing. *(Accounts portion landed in 2.1.1; keys + routing in 2.1.2 and 2.1.3.)* |
| [zk-credentials.md](zk-credentials.md) *(Phase 2.2)* | Profile, group-send, call-link, backup zero-knowledge credentials.    |
| [pq-keys.md](pq-keys.md) *(Phase 2.3)*    | Kyber / ML-KEM key lifecycle (signed pre-keys, one-time keys, last-resort). |
| [message-delivery.md](message-delivery.md) *(Phase 2.4)* | Real-time + persisted + multi-recipient + receipts.                    |
| [sealed-sender.md](sealed-sender.md) *(Phase 2.5)* | Unidentified-access delivery and sealed-sender v2.                    |
