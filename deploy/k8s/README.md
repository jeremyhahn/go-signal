# Kubernetes manifests — go-signal full topology

These manifests deploy the 6-binary Phase 4 architecture:

| Binary | Resource | Internal port | External? |
|---|---|---|---|
| signald | `signald` Deployment + Service | 8080 (REST), 8443 (gRPC) | yes — only public entry |
| registration-service | `registration-service` Deployment + Service | 8090 (gRPC) | no |
| svr2 | `svr2` Deployment + Service | 8091 (admin HTTP), 8092 (WS) | WS via ingress |
| cdsi | `cdsi` Deployment + Service | 8094 (WS) | WS via ingress |
| storage-service | `storage-service` Deployment + Service | 8096 (HTTP) | no |
| key-transparency | `key-transparency` Deployment + Service | 8098 (gRPC) | no |

Shared:

- `postgres` StatefulSet — production storage backend.
- `redis` Deployment — WebSocket session clustering + rate limits.

Trust-anchor secrets (`signal-shared-secrets`) carry the HMAC keys
the chat-server uses to mint per-service credentials. Rotate them
together: every binary that validates inbound credentials reads from
the same key.

```sh
kubectl apply -k deploy/k8s/
```

## What's intentionally not here yet

- mTLS cert material — placeholder; production deployments wire
  cert-manager + a private PKI before flipping `RemoteInsecure: false`.
- Horizontal pod autoscalers + pod disruption budgets — added with
  Phase 5 production-readiness.
- Ingress / Service mesh — operator-specific.
