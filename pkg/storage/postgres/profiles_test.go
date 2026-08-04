package postgres

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/jeremyhahn/go-signal/pkg/profiles"
)

// seedAccount is defined in keys_test.go and shared across all test files in
// this package. It inserts a minimal accounts row to satisfy the FK constraint
// on profiles(account_uuid → accounts.aci).

// newProfile builds a Profile for tests. All binary fields are non-nil so that
// round-trip tests can verify the full struct survives serialization.
func newProfile(acUUID, version string) *profiles.Profile {
	return &profiles.Profile{
		UUID:           acUUID,
		Version:        version,
		Name:           []byte("enc-name"),
		About:          []byte("enc-about"),
		AboutEmoji:     []byte("enc-emoji"),
		Avatar:         "profiles/avatar.jpg",
		Commitment:     []byte("commitment"),
		PaymentAddress: []byte("payment"),
	}
}

func TestProfiles_Set_Get_Roundtrip(t *testing.T) {
	c := newTestClient(t)
	ctx := context.Background()
	aci := uuid.NewString()
	seedAccount(t, c, aci)

	s := NewProfileStore(c.Pool())
	want := newProfile(aci, "v1")
	if err := s.Set(ctx, want); err != nil {
		t.Fatalf("Set: %v", err)
	}

	got, err := s.Get(ctx, aci, "v1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.UUID != aci || got.Version != "v1" || string(got.Name) != "enc-name" {
		t.Fatalf("Get returned unexpected profile: %+v", got)
	}
}

func TestProfiles_Set_Get_MissingVersion_ReturnsNotFound(t *testing.T) {
	c := newTestClient(t)
	ctx := context.Background()
	aci := uuid.NewString()
	seedAccount(t, c, aci)

	s := NewProfileStore(c.Pool())
	if err := s.Set(ctx, newProfile(aci, "v1")); err != nil {
		t.Fatalf("Set: %v", err)
	}

	_, err := s.Get(ctx, aci, "v999")
	var nfe *profiles.ProfileNotFoundError
	if !errors.As(err, &nfe) {
		t.Fatalf("expected ProfileNotFoundError, got %T: %v", err, err)
	}
	if nfe.UUID != aci || nfe.Version != "v999" {
		t.Fatalf("ProfileNotFoundError fields wrong: %+v", nfe)
	}
}

func TestProfiles_MultipleSet_LatestPromoted(t *testing.T) {
	c := newTestClient(t)
	ctx := context.Background()
	aci := uuid.NewString()
	seedAccount(t, c, aci)

	s := NewProfileStore(c.Pool())
	for _, ver := range []string{"v1", "v2", "v3"} {
		if err := s.Set(ctx, newProfile(aci, ver)); err != nil {
			t.Fatalf("Set %s: %v", ver, err)
		}
	}

	got, err := s.GetLatest(ctx, aci)
	if err != nil {
		t.Fatalf("GetLatest: %v", err)
	}
	// The last Set call used "v3", so that must be latest.
	if got.Version != "v3" {
		t.Fatalf("GetLatest: got version %q, want %q", got.Version, "v3")
	}
}

func TestProfiles_GetLatest_NoProfile_ReturnsNotFound(t *testing.T) {
	c := newTestClient(t)
	ctx := context.Background()
	aci := uuid.NewString()
	seedAccount(t, c, aci)

	s := NewProfileStore(c.Pool())
	_, err := s.GetLatest(ctx, aci)
	var nfe *profiles.ProfileNotFoundError
	if !errors.As(err, &nfe) {
		t.Fatalf("expected ProfileNotFoundError, got %T: %v", err, err)
	}
}

func TestProfiles_Set_Upsert_SameVersion(t *testing.T) {
	c := newTestClient(t)
	ctx := context.Background()
	aci := uuid.NewString()
	seedAccount(t, c, aci)

	s := NewProfileStore(c.Pool())
	if err := s.Set(ctx, newProfile(aci, "v1")); err != nil {
		t.Fatalf("Set #1: %v", err)
	}

	// Overwrite the same version with different data.
	updated := newProfile(aci, "v1")
	updated.Name = []byte("updated-name")
	if err := s.Set(ctx, updated); err != nil {
		t.Fatalf("Set #2 (upsert): %v", err)
	}

	got, err := s.Get(ctx, aci, "v1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(got.Name) != "updated-name" {
		t.Fatalf("upsert did not overwrite Name: %s", got.Name)
	}
}

func TestProfiles_Delete_RemovesAllVersions(t *testing.T) {
	c := newTestClient(t)
	ctx := context.Background()
	aci := uuid.NewString()
	seedAccount(t, c, aci)

	s := NewProfileStore(c.Pool())
	for _, ver := range []string{"v1", "v2"} {
		if err := s.Set(ctx, newProfile(aci, ver)); err != nil {
			t.Fatalf("Set %s: %v", ver, err)
		}
	}
	if err := s.Delete(ctx, aci); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	for _, ver := range []string{"v1", "v2"} {
		_, err := s.Get(ctx, aci, ver)
		var nfe *profiles.ProfileNotFoundError
		if !errors.As(err, &nfe) {
			t.Fatalf("after Delete, Get(%s) expected NotFound, got %T: %v", ver, err, err)
		}
	}
	_, err := s.GetLatest(ctx, aci)
	var nfe *profiles.ProfileNotFoundError
	if !errors.As(err, &nfe) {
		t.Fatalf("after Delete, GetLatest expected NotFound, got %T: %v", err, err)
	}
}

func TestProfiles_Delete_NoRows_Succeeds(t *testing.T) {
	c := newTestClient(t)
	ctx := context.Background()
	aci := uuid.NewString()
	seedAccount(t, c, aci)

	s := NewProfileStore(c.Pool())
	// Delete with no prior rows must not error (mirrors qrdb behavior).
	if err := s.Delete(ctx, aci); err != nil {
		t.Fatalf("Delete on empty: %v", err)
	}
}

func TestProfiles_Set_DifferentAccounts_Isolated(t *testing.T) {
	c := newTestClient(t)
	ctx := context.Background()

	aci1 := uuid.NewString()
	aci2 := uuid.NewString()
	seedAccount(t, c, aci1)
	seedAccount(t, c, aci2)

	s := NewProfileStore(c.Pool())
	if err := s.Set(ctx, newProfile(aci1, "v1")); err != nil {
		t.Fatalf("Set aci1: %v", err)
	}
	if err := s.Set(ctx, newProfile(aci2, "v1")); err != nil {
		t.Fatalf("Set aci2: %v", err)
	}

	// Deleting aci1 must not affect aci2.
	if err := s.Delete(ctx, aci1); err != nil {
		t.Fatalf("Delete aci1: %v", err)
	}
	got, err := s.GetLatest(ctx, aci2)
	if err != nil {
		t.Fatalf("GetLatest aci2 after deleting aci1: %v", err)
	}
	if got.UUID != aci2 {
		t.Fatalf("GetLatest aci2: unexpected UUID %q", got.UUID)
	}
}

func TestProfiles_Set_NilProfile_Rejected(t *testing.T) {
	c := newTestClient(t)
	s := NewProfileStore(c.Pool())

	err := s.Set(context.Background(), nil)
	var iae *profiles.InvalidArgumentError
	if !errors.As(err, &iae) {
		t.Fatalf("expected InvalidArgumentError, got %T: %v", err, err)
	}
}

// TestProfiles_Set_InsideTx exercises the pgx.Tx branch in Set where the
// Querier is already a transaction.
func TestProfiles_Set_InsideTx(t *testing.T) {
	c := newTestClient(t)
	ctx := context.Background()
	aci := uuid.NewString()
	seedAccount(t, c, aci)

	tx, err := c.Pool().Begin(ctx)
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	s := NewProfileStore(tx)
	if err := s.Set(ctx, newProfile(aci, "tx-v1")); err != nil {
		t.Fatalf("Set inside tx: %v", err)
	}

	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	outerStore := NewProfileStore(c.Pool())
	got, err := outerStore.Get(ctx, aci, "tx-v1")
	if err != nil {
		t.Fatalf("Get after tx commit: %v", err)
	}
	if got.Version != "tx-v1" {
		t.Fatalf("expected version tx-v1, got %q", got.Version)
	}
}

func TestProfiles_Get_PoolClosed_ReturnsError(t *testing.T) {
	c := newTestClient(t)
	aci := uuid.NewString()
	seedAccount(t, c, aci)
	s := NewProfileStore(c.Pool())
	c.Close()

	_, err := s.Get(context.Background(), aci, "v1")
	if err == nil {
		t.Fatal("expected error from closed pool")
	}
	var nfe *profiles.ProfileNotFoundError
	if errors.As(err, &nfe) {
		t.Fatal("expected pool error, not ProfileNotFoundError")
	}
}

func TestProfiles_GetLatest_PoolClosed_ReturnsError(t *testing.T) {
	c := newTestClient(t)
	aci := uuid.NewString()
	seedAccount(t, c, aci)
	s := NewProfileStore(c.Pool())
	c.Close()

	_, err := s.GetLatest(context.Background(), aci)
	if err == nil {
		t.Fatal("expected error from closed pool")
	}
	var nfe *profiles.ProfileNotFoundError
	if errors.As(err, &nfe) {
		t.Fatal("expected pool error, not ProfileNotFoundError")
	}
}

func TestProfiles_Delete_PoolClosed_ReturnsError(t *testing.T) {
	c := newTestClient(t)
	s := NewProfileStore(c.Pool())
	c.Close()

	err := s.Delete(context.Background(), uuid.NewString())
	if err == nil {
		t.Fatal("expected error from closed pool")
	}
}

func TestProfiles_Set_EmptyVersion_Rejected(t *testing.T) {
	c := newTestClient(t)
	ctx := context.Background()
	aci := uuid.NewString()
	seedAccount(t, c, aci)

	s := NewProfileStore(c.Pool())
	err := s.Set(ctx, &profiles.Profile{UUID: aci, Version: ""})
	var iae *profiles.InvalidArgumentError
	if !errors.As(err, &iae) {
		t.Fatalf("expected InvalidArgumentError for empty version, got %T: %v", err, err)
	}
}

func TestProfiles_Set_EmptyUUID_Rejected(t *testing.T) {
	c := newTestClient(t)
	s := NewProfileStore(c.Pool())

	err := s.Set(context.Background(), &profiles.Profile{UUID: "", Version: "v1"})
	var iae *profiles.InvalidArgumentError
	if !errors.As(err, &iae) {
		t.Fatalf("expected InvalidArgumentError, got %T: %v", err, err)
	}
}

// TestProfiles_Set_NonPoolQuerier_CancelledCtx_DemoteError exercises the
// demote-UPDATE error branch inside runInTx (profiles.go:67-69). When the
// Querier is a noTxQuerier (no BeginTx), Set falls through to the direct path
// (line 109) and calls runInTx(s.q). The UPDATE statement receives an
// already-cancelled context and fails immediately, hitting the demote error
// return at line 67-69.
func TestProfiles_Set_NonPoolQuerier_CancelledCtx_DemoteError(t *testing.T) {
	c := newTestClient(t)
	ctx := context.Background()
	aci := uuid.NewString()
	seedAccount(t, c, aci)

	s := NewProfileStore(noTxQuerier{c.Pool()})

	cancelledCtx, cancel := context.WithCancel(ctx)
	cancel() // cancel immediately before Set is called

	err := s.Set(cancelledCtx, &profiles.Profile{UUID: aci, Version: "v-cancelled"})
	if err == nil {
		t.Fatal("expected error from cancelled context, got nil")
	}
	var iae *profiles.InvalidArgumentError
	if errors.As(err, &iae) {
		t.Fatal("expected context error, not InvalidArgumentError")
	}
}

// TestProfiles_Set_FKViolation_ReturnsError exercises the runInTx error path
// (profiles.go:82-84 and 100-102) where the upsert INSERT fails because the
// referenced account UUID does not exist. The demote UPDATE is a no-op (no
// rows yet for this account) and succeeds; the INSERT then fails with a
// foreign-key violation, causing runInTx to return an error which the pool
// path propagates at line 101.
func TestProfiles_Set_FKViolation_ReturnsError(t *testing.T) {
	c := newTestClient(t)
	s := NewProfileStore(c.Pool())
	ctx := context.Background()

	// Use a valid UUID that has no corresponding accounts row.
	err := s.Set(ctx, &profiles.Profile{UUID: uuid.NewString(), Version: "v-fk"})
	if err == nil {
		t.Fatal("expected error for FK violation, got nil")
	}
	// Must not be a typed domain error.
	var nfe *profiles.ProfileNotFoundError
	if errors.As(err, &nfe) {
		t.Fatal("expected FK error, not ProfileNotFoundError")
	}
}

// TestProfiles_Set_NonPoolQuerier_FallsBackToDirectPath exercises the final
// fallback branch in Set (profiles.go line 109) reached when the Querier is
// neither a pgx.Tx nor a pool (txQuerier). noTxQuerier (defined in
// testhelpers_test.go) wraps the pool via the Querier interface so BeginTx is
// not promoted; Set therefore runs the two statements directly against the
// Querier without a transaction wrapper.
func TestProfiles_Set_NonPoolQuerier_FallsBackToDirectPath(t *testing.T) {
	c := newTestClient(t)
	ctx := context.Background()
	aci := uuid.NewString()
	seedAccount(t, c, aci)

	// Wrap the pool in a noTxQuerier so s.q satisfies Querier but not txQuerier.
	s := NewProfileStore(noTxQuerier{c.Pool()})
	if err := s.Set(ctx, newProfile(aci, "fallback-v1")); err != nil {
		t.Fatalf("Set via fallback path: %v", err)
	}

	// Read back through a standard store to confirm the profile was persisted.
	reader := NewProfileStore(c.Pool())
	got, err := reader.Get(ctx, aci, "fallback-v1")
	if err != nil {
		t.Fatalf("Get after fallback Set: %v", err)
	}
	if got.Version != "fallback-v1" {
		t.Fatalf("expected version fallback-v1, got %q", got.Version)
	}
}

// TestProfiles_Get_CorruptedData_UnmarshalError exercises the json.Unmarshal
// error branch in Get (profiles.go:126-128). A row is inserted via raw SQL
// with a data value whose "Name" field contains an invalid base64 string (Go
// encodes []byte as base64 in JSON), causing json.Unmarshal to fail even
// though the row exists and is found.
func TestProfiles_Get_CorruptedData_UnmarshalError(t *testing.T) {
	c := newTestClient(t)
	ctx := context.Background()
	aci := uuid.NewString()
	seedAccount(t, c, aci)

	// "!!! not valid base64 !!!" is syntactically valid JSON (a string) but
	// Go's json decoder rejects it when targeting a []byte field because it
	// cannot base64-decode it.
	_, err := c.Pool().Exec(ctx,
		`INSERT INTO profiles (account_uuid, version, data, is_latest, updated_at)
		 VALUES ($1, 'corrupt-v1', '{"Name":"!!! not valid base64 !!!"}'::jsonb, FALSE, NOW())`,
		aci,
	)
	if err != nil {
		t.Fatalf("raw insert corrupted profile: %v", err)
	}

	s := NewProfileStore(c.Pool())
	_, err = s.Get(ctx, aci, "corrupt-v1")
	if err == nil {
		t.Fatal("expected unmarshal error from corrupted data, got nil")
	}
	var nfe *profiles.ProfileNotFoundError
	if errors.As(err, &nfe) {
		t.Fatal("expected unmarshal error, not ProfileNotFoundError")
	}
}

// TestProfiles_GetLatest_CorruptedData_UnmarshalError exercises the
// json.Unmarshal error branch in GetLatest (profiles.go:146-148).
func TestProfiles_GetLatest_CorruptedData_UnmarshalError(t *testing.T) {
	c := newTestClient(t)
	ctx := context.Background()
	aci := uuid.NewString()
	seedAccount(t, c, aci)

	// Same invalid base64 trick, but this row is marked is_latest=TRUE.
	_, err := c.Pool().Exec(ctx,
		`INSERT INTO profiles (account_uuid, version, data, is_latest, updated_at)
		 VALUES ($1, 'corrupt-latest', '{"Name":"!!! not valid base64 !!!"}'::jsonb, TRUE, NOW())`,
		aci,
	)
	if err != nil {
		t.Fatalf("raw insert corrupted latest profile: %v", err)
	}

	s := NewProfileStore(c.Pool())
	_, err = s.GetLatest(ctx, aci)
	if err == nil {
		t.Fatal("expected unmarshal error from corrupted data, got nil")
	}
	var nfe *profiles.ProfileNotFoundError
	if errors.As(err, &nfe) {
		t.Fatal("expected unmarshal error, not ProfileNotFoundError")
	}
}

// TestProfiles_Set_PoolClosed_ReturnsError exercises the BeginTx failure branch
// inside Set's pool path (profiles.go lines 96-98). The pool is closed before
// Set is called so BeginTx returns an error and Set propagates it.
func TestProfiles_Set_PoolClosed_ReturnsError(t *testing.T) {
	c := newTestClient(t)
	s := NewProfileStore(c.Pool())
	c.Close()

	err := s.Set(context.Background(), &profiles.Profile{
		UUID:    uuid.NewString(),
		Version: "v1",
	})
	if err == nil {
		t.Fatal("expected error from closed pool, got nil")
	}
	var iae *profiles.InvalidArgumentError
	if errors.As(err, &iae) {
		t.Fatal("expected pool error, not InvalidArgumentError")
	}
}
