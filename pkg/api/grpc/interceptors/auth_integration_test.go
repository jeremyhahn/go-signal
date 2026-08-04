package interceptors_test

import (
	"context"
	stdbase64 "encoding/base64"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-signal/pkg/accounts"
	"github.com/jeremyhahn/go-signal/pkg/api/grpc/interceptors"
	"github.com/jeremyhahn/go-signal/pkg/auth"
	"github.com/jeremyhahn/go-signal/pkg/storage/memory"
)

func encB64(s string) string { return stdbase64.StdEncoding.EncodeToString([]byte(s)) }

// These tests exercise the happy path of AuthenticatedUnary against a
// real AccountsManager wired to the memory-backed store, so the timing
// equalisation and metadata-to-context plumbing are validated end-to-end.

// mkAccount writes an account with a primary device whose AuthTokenHash
// verifies password. It writes directly to the store, bypassing the
// manager's stricter validation (signedPreKey, etc. are not required by
// the auth path the interceptor exercises).
func mkAccount(t *testing.T, store *memory.MemoryAccountStore, uuid, password string) {
	t.Helper()
	ctx := context.Background()
	tokenHash, err := auth.NewSaltedTokenHash(password)
	if err != nil {
		t.Fatalf("NewSaltedTokenHash: %v", err)
	}
	acct := &accounts.Account{
		UUID:    uuid,
		Number:  "+1555" + uuid[:7],
		Version: 1,
		Devices: []accounts.Device{
			{
				ID:            accounts.PrimaryDeviceID,
				AuthTokenHash: tokenHash,
			},
		},
	}
	if err := store.Create(ctx, acct); err != nil {
		t.Fatalf("store create: %v", err)
	}
}

func TestAuthenticatedUnary_ValidCredentials_PopulatesContext(t *testing.T) {
	t.Parallel()
	store := memory.NewMemoryAccountStore()
	am := accounts.NewAccountsManager(store, 6)
	mkAccount(t, store, "00000000-0000-0000-0000-000000000001", "password-secret")

	var capturedCtx context.Context
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		capturedCtx = ctx
		return "ok", nil
	}

	i := interceptors.AuthenticatedUnary(am)
	md := metadata.Pairs("authorization", "Basic "+base64("00000000-0000-0000-0000-000000000001:password-secret"))
	ctx := metadata.NewIncomingContext(context.Background(), md)

	out, err := i(ctx, "req", &grpc.UnaryServerInfo{}, handler)
	if err != nil {
		t.Fatalf("authenticated call should succeed: %v", err)
	}
	if out != "ok" {
		t.Fatalf("unexpected handler output: %v", out)
	}
	got := interceptors.AccountFromContext(capturedCtx)
	if got == nil {
		t.Fatal("handler context must carry authenticated account")
		return
	}
	if got.UUID != "00000000-0000-0000-0000-000000000001" {
		t.Fatalf("wrong account: %s", got.UUID)
	}
}

func TestAuthenticatedUnary_WrongPassword_Unauthenticated(t *testing.T) {
	t.Parallel()
	store := memory.NewMemoryAccountStore()
	am := accounts.NewAccountsManager(store, 6)
	mkAccount(t, store, "00000000-0000-0000-0000-000000000002", "real-password")

	i := interceptors.AuthenticatedUnary(am)
	md := metadata.Pairs("authorization", "Basic "+base64("00000000-0000-0000-0000-000000000002:wrong-password"))
	ctx := metadata.NewIncomingContext(context.Background(), md)

	_, err := i(ctx, "req", &grpc.UnaryServerInfo{}, func(context.Context, interface{}) (interface{}, error) {
		t.Fatal("handler should not be reached on wrong password")
		return nil, nil
	})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expected Unauthenticated, got %v", err)
	}
}

func TestAuthenticatedUnary_UnknownAccount_Unauthenticated(t *testing.T) {
	t.Parallel()
	am := accounts.NewAccountsManager(memory.NewMemoryAccountStore(), 6)

	i := interceptors.AuthenticatedUnary(am)
	md := metadata.Pairs("authorization", "Basic "+base64("00000000-0000-0000-0000-000000000099:any"))
	ctx := metadata.NewIncomingContext(context.Background(), md)

	_, err := i(ctx, "req", &grpc.UnaryServerInfo{}, func(context.Context, interface{}) (interface{}, error) {
		t.Fatal("handler should not run for unknown account")
		return nil, nil
	})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expected Unauthenticated, got %v", err)
	}
}

func TestAuthenticatedUnary_DeviceSuffix_StrippedFromUUIDLookup(t *testing.T) {
	t.Parallel()
	store := memory.NewMemoryAccountStore()
	am := accounts.NewAccountsManager(store, 6)
	mkAccount(t, store, "00000000-0000-0000-0000-000000000003", "password")

	i := interceptors.AuthenticatedUnary(am)
	// Username is "uuid.1" — the ".1" names the primary device. The
	// interceptor must look up the account by the UUID portion only.
	md := metadata.Pairs("authorization", "Basic "+base64("00000000-0000-0000-0000-000000000003.1:password"))
	ctx := metadata.NewIncomingContext(context.Background(), md)

	out, err := i(ctx, "req", &grpc.UnaryServerInfo{}, func(ctx context.Context, req interface{}) (interface{}, error) {
		return "ok", nil
	})
	if err != nil || out != "ok" {
		t.Fatalf("uuid.deviceId format should authenticate: out=%v err=%v", out, err)
	}
}

// base64 encodes s in standard base64 for Basic auth headers.
func base64(s string) string {
	return encB64(s)
}
