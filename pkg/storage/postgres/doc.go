// Package postgres implements the go-signal store interfaces on PostgreSQL: indexed fields as columns, opaque blobs as JSONB, expires_at instead of TTL.
// Pre-key and profile tables cascade from accounts(aci); other per-account tables have no foreign key and are deleted explicitly.
package postgres
