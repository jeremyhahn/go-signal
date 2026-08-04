package interceptors

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-signal/pkg/accounts"
	"github.com/jeremyhahn/go-signal/pkg/storage/memory"
)

// noopHandler is used in tests where we only care whether the interceptor
// reached the wrapped handler.
func noopHandler(ctx context.Context, req interface{}) (interface{}, error) {
	return "ok", nil
}

// incomingCtx wraps md into an incoming gRPC metadata context.
func incomingCtx(md metadata.MD) context.Context {
	return metadata.NewIncomingContext(context.Background(), md)
}

func basicHeader(user, pass string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
}

// ---- parseBasicMetadata ---------------------------------------------

func TestParseBasicMetadata_Valid(t *testing.T) {
	t.Parallel()
	md := metadata.Pairs("authorization", basicHeader("uuid", "password"))
	u, p, err := parseBasicMetadata(md)
	if err != nil || u != "uuid" || p != "password" {
		t.Fatalf("parse failed: u=%s p=%s err=%v", u, p, err)
	}
}

func TestParseBasicMetadata_Missing(t *testing.T) {
	t.Parallel()
	if _, _, err := parseBasicMetadata(metadata.MD{}); err == nil {
		t.Fatal("expected error on missing authorization")
	}
}

func TestParseBasicMetadata_Multiple(t *testing.T) {
	t.Parallel()
	md := metadata.MD{"authorization": {"one", "two"}}
	if _, _, err := parseBasicMetadata(md); err == nil {
		t.Fatal("expected error on multiple authorization entries")
	}
}

func TestParseBasicMetadata_NotBasic(t *testing.T) {
	t.Parallel()
	md := metadata.Pairs("authorization", "Bearer abc")
	if _, _, err := parseBasicMetadata(md); err == nil {
		t.Fatal("expected error on Bearer auth")
	}
}

func TestParseBasicMetadata_BadBase64(t *testing.T) {
	t.Parallel()
	md := metadata.Pairs("authorization", "Basic not-base64!")
	if _, _, err := parseBasicMetadata(md); err == nil {
		t.Fatal("expected error on malformed base64")
	}
}

func TestParseBasicMetadata_MissingColon(t *testing.T) {
	t.Parallel()
	md := metadata.Pairs("authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("justuser")))
	if _, _, err := parseBasicMetadata(md); err == nil {
		t.Fatal("expected error when no colon separator")
	}
}

// ---- AnonymousUnary -------------------------------------------------

func TestAnonymousUnary_NoCredentials_Passes(t *testing.T) {
	t.Parallel()
	out, err := AnonymousUnary()(context.Background(), "req", &grpc.UnaryServerInfo{}, noopHandler)
	if err != nil || out != "ok" {
		t.Fatalf("anonymous without creds should pass: out=%v err=%v", out, err)
	}
}

func TestAnonymousUnary_WithCredentials_Rejected(t *testing.T) {
	t.Parallel()
	ctx := incomingCtx(metadata.Pairs("authorization", "Basic Zm9vOmJhcg=="))
	_, err := AnonymousUnary()(ctx, "req", &grpc.UnaryServerInfo{}, noopHandler)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("expected PermissionDenied, got %v", err)
	}
}

func TestAnonymousUnary_EmptyAuthorizationMetadata_Passes(t *testing.T) {
	t.Parallel()
	// Incoming metadata with non-auth values — still considered anonymous.
	ctx := incomingCtx(metadata.Pairs("user-agent", "signal-client/1.0"))
	out, err := AnonymousUnary()(ctx, "req", &grpc.UnaryServerInfo{}, noopHandler)
	if err != nil || out != "ok" {
		t.Fatalf("anonymous with non-auth metadata should pass: out=%v err=%v", out, err)
	}
}

// ---- AccountFromContext --------------------------------------------

func TestAccountFromContext_NoAccount(t *testing.T) {
	t.Parallel()
	if got := AccountFromContext(context.Background()); got != nil {
		t.Fatalf("expected nil, got %+v", got)
	}
}

// ---- AuthenticatedUnary behavioural ---------------------------------

// The authenticated interceptor depends on a live *AccountsManager.
// Constructing one is heavyweight; here we exercise the path where the
// authorization header is absent or malformed — both cases must return
// Unauthenticated without touching the manager, which means passing nil
// is safe.

func TestAuthenticatedUnary_MissingMetadata_Unauthenticated(t *testing.T) {
	t.Parallel()
	i := AuthenticatedUnary(nil)
	_, err := i(context.Background(), "req", &grpc.UnaryServerInfo{}, noopHandler)
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expected Unauthenticated on missing metadata, got %v", err)
	}
	if !strings.Contains(status.Convert(err).Message(), "missing") {
		t.Fatalf("error message should mention missing metadata: %v", err)
	}
}

func TestAuthenticatedUnary_InvalidBasic_Unauthenticated(t *testing.T) {
	t.Parallel()
	i := AuthenticatedUnary(nil)
	ctx := incomingCtx(metadata.Pairs("authorization", "not basic"))
	_, err := i(ctx, "req", &grpc.UnaryServerInfo{}, noopHandler)
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expected Unauthenticated on malformed auth, got %v", err)
	}
}

// makeTestManager seeds a memory-backed AccountsManager with one account
// whose primary device is authenticated with the returned password.
func makeTestManager(t *testing.T) (*accounts.AccountsManager, string, string) {
	t.Helper()
	store := memory.NewMemoryAccountStore()
	am := accounts.NewAccountsManager(store, 6)

	const (
		testUUID     = "550e8400-e29b-41d4-a716-446655440001"
		testPassword = "interceptor-test-token"
		testNumber   = "+15550001234"
	)
	acct := &accounts.Account{
		UUID:        testUUID,
		Number:      testNumber,
		IdentityKey: []byte("fake-identity-key"),
		Devices: []accounts.Device{{
			ID:        accounts.PrimaryDeviceID,
			AuthToken: testPassword,
			SignedPreKey: &accounts.SignedPreKey{
				KeyID:     1,
				PublicKey: []byte("pubkey"),
				Signature: []byte("sig"),
			},
		}},
	}
	if err := am.Create(context.Background(), acct); err != nil {
		t.Fatalf("create test account: %v", err)
	}
	return am, testUUID, testPassword
}

// ---- DeviceIDFromContext ---------------------------------------------------

func TestDeviceIDFromContext_NoneSet_ReturnsPrimary(t *testing.T) {
	t.Parallel()
	got := DeviceIDFromContext(context.Background())
	if got != accounts.PrimaryDeviceID {
		t.Errorf("got %d, want %d", got, accounts.PrimaryDeviceID)
	}
}

func TestDeviceIDFromContext_Set_ReturnsID(t *testing.T) {
	t.Parallel()
	ctx := context.WithValue(context.Background(), DeviceContextKey, uint64(7))
	if got := DeviceIDFromContext(ctx); got != 7 {
		t.Errorf("got %d, want 7", got)
	}
}

// ---- AuthenticatedUnary: dot-syntax device ID paths -----------------------

func TestAuthenticatedUnary_DotSyntax_ZeroDeviceID_Rejected(t *testing.T) {
	t.Parallel()
	i := AuthenticatedUnary(nil)
	ctx := incomingCtx(metadata.Pairs("authorization", basicHeader("someuuid.0", "pass")))
	_, err := i(ctx, "req", &grpc.UnaryServerInfo{}, noopHandler)
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expected Unauthenticated for device ID 0, got %v", err)
	}
}

func TestAuthenticatedUnary_DotSyntax_BadDeviceID_Rejected(t *testing.T) {
	t.Parallel()
	i := AuthenticatedUnary(nil)
	ctx := incomingCtx(metadata.Pairs("authorization", basicHeader("someuuid.notanumber", "pass")))
	_, err := i(ctx, "req", &grpc.UnaryServerInfo{}, noopHandler)
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expected Unauthenticated for non-numeric device ID, got %v", err)
	}
}

// ---- AuthenticatedUnary: account/device lookup paths ----------------------

func TestAuthenticatedUnary_AccountNotFound_Rejected(t *testing.T) {
	am, _, _ := makeTestManager(t)
	i := AuthenticatedUnary(am)
	ctx := incomingCtx(metadata.Pairs("authorization", basicHeader("no-such-uuid", "pass")))
	_, err := i(ctx, "req", &grpc.UnaryServerInfo{}, noopHandler)
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expected Unauthenticated for missing account, got %v", err)
	}
}

func TestAuthenticatedUnary_DeviceMissing_Rejected(t *testing.T) {
	am, acctUUID, _ := makeTestManager(t)
	i := AuthenticatedUnary(am)
	// Device 99 was never registered.
	ctx := incomingCtx(metadata.Pairs("authorization", basicHeader(acctUUID+".99", "pass")))
	_, err := i(ctx, "req", &grpc.UnaryServerInfo{}, noopHandler)
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expected Unauthenticated for missing device, got %v", err)
	}
}

func TestAuthenticatedUnary_WrongPassword_Rejected(t *testing.T) {
	am, acctUUID, _ := makeTestManager(t)
	i := AuthenticatedUnary(am)
	ctx := incomingCtx(metadata.Pairs("authorization", basicHeader(acctUUID, "wrong-password")))
	_, err := i(ctx, "req", &grpc.UnaryServerInfo{}, noopHandler)
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expected Unauthenticated for wrong password, got %v", err)
	}
}

func TestAuthenticatedUnary_ValidCredentials_PassesThrough(t *testing.T) {
	am, acctUUID, password := makeTestManager(t)
	i := AuthenticatedUnary(am)
	ctx := incomingCtx(metadata.Pairs("authorization", basicHeader(acctUUID, password)))
	out, err := i(ctx, "req", &grpc.UnaryServerInfo{}, func(ctx context.Context, req interface{}) (interface{}, error) {
		if AccountFromContext(ctx) == nil {
			return nil, status.Error(codes.Internal, "account not in context")
		}
		if DeviceIDFromContext(ctx) != accounts.PrimaryDeviceID {
			return nil, status.Error(codes.Internal, "device ID not in context")
		}
		return "ok", nil
	})
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if out != "ok" {
		t.Fatalf("expected 'ok', got %v", out)
	}
}
