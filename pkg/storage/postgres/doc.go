// Package postgres implements the go-signal domain repository interfaces
// (pkg/service/*Store) against PostgreSQL. It is one of several peer storage
// backends (memory, qrdb, dynamodb, postgres) — each implements the same
// service-layer contracts natively rather than sharing a lowest-common-
// denominator KV adapter.
//
// The schema is hybrid: indexed and queried fields are promoted to columns;
// opaque server-side blobs (Account.Devices, profile encrypted fields, group
// state, message envelopes) live in JSONB. TTL is replaced by expires_at
// columns swept by per-domain workers. Conditional writes are expressed as
// ON CONFLICT clauses, UNIQUE constraints, or advisory locks where Java
// uses DynamoDB's conditional expressions or DynamoDB Lock Client.
//
// Foreign keys cascade from accounts(aci) on the per-account child tables
// where lifetime is strictly bounded by the account: pre-keys (all four
// tables) and profiles. Other tables that reference an account_uuid
// (provisioning, usernames, fido2, securestorage, spam_reports, messages,
// verification) deliberately omit the FK — some are populated before the
// account row exists (verification sessions during registration), some
// outlive the account for moderation (spam_reports), and some have their
// own lifecycle (messages clean up via TTL sweep). DeleteForAccount in
// those domains is an explicit DELETE per store.
package postgres
