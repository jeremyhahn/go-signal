// Package interceptors provides gRPC unary interceptors that mirror the
// authentication model established in pkg/api/rest/middleware.go. The gRPC
// and REST layers use distinct (layer-private) context keys; each layer reads
// the principal it stored via its own AccountFromContext/DeviceIDFromContext
// helper rather than sharing a single key.
package interceptors

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"

	"github.com/jeremyhahn/go-qrdb/sdk/go/secure"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-signal/pkg/accounts"
	"github.com/jeremyhahn/go-signal/pkg/auth"
)

// AccountContextKey is the context key under which authenticated accounts
// are stored by [AuthenticatedUnary]. The REST middleware uses the same
// key so handlers can share look-up helpers.
type accountCtxKey struct{}

// AccountContextKey is exported so callers in services packages can
// retrieve the authenticated account.
var AccountContextKey = accountCtxKey{}

// AccountFromContext returns the authenticated account stored in ctx by
// [AuthenticatedUnary], or nil if none is present.
func AccountFromContext(ctx context.Context) *accounts.Account {
	acct, _ := ctx.Value(AccountContextKey).(*accounts.Account)
	return acct
}

// deviceCtxKey keys the authenticated device ID set by [AuthenticatedUnary].
type deviceCtxKey struct{}

// DeviceContextKey is exported so service-layer code can read the
// authenticated device ID from the request context.
var DeviceContextKey = deviceCtxKey{}

// DeviceIDFromContext returns the authenticated device ID stored in ctx by
// [AuthenticatedUnary], or accounts.PrimaryDeviceID when none is present.
func DeviceIDFromContext(ctx context.Context) uint64 {
	if id, ok := ctx.Value(DeviceContextKey).(uint64); ok {
		return id
	}
	return accounts.PrimaryDeviceID
}

// AuthenticatedUnary returns a UnaryServerInterceptor that requires valid
// HTTP Basic credentials on every request. Credentials are parsed from the
// `authorization` gRPC metadata entry, matching the header clients already
// use for REST. The authenticated account is stored on the context under
// [AccountContextKey].
//
// Timing-equalisation: when a UUID lookup fails we still perform a full
// auth.SaltedTokenHash.Verify against a dummy hash so response latency
// does not reveal whether the account exists. This mirrors the REST
// middleware and the Java Signal-Server implementation.
func AuthenticatedUnary(am *accounts.AccountsManager) grpc.UnaryServerInterceptor {
	dummyHash, _ := auth.NewSaltedTokenHash("dummy-timing-equalization-token")

	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			return nil, status.Error(codes.Unauthenticated, "missing metadata")
		}

		username, password, err := parseBasicMetadata(md)
		if err != nil {
			return nil, status.Errorf(codes.Unauthenticated, "invalid credentials: %v", err)
		}
		// Wipe the password on every return path below, handler included.
		defer secure.Wipe(password)

		// The credential is "uuid.deviceId" or just "uuid" (primary device).
		acctUUID := username
		deviceID := accounts.PrimaryDeviceID
		if idx := strings.IndexByte(username, '.'); idx >= 0 {
			acctUUID = username[:idx]
			parsed, perr := strconv.ParseUint(username[idx+1:], 10, 64)
			if perr != nil || parsed == 0 {
				_ = dummyHash.Verify(password)
				return nil, status.Error(codes.Unauthenticated, "invalid credentials")
			}
			deviceID = parsed
		}

		acct, err := am.Get(ctx, acctUUID)
		if err != nil {
			_ = dummyHash.Verify(password)
			return nil, status.Error(codes.Unauthenticated, "invalid credentials")
		}
		// Verify against the authenticated device — not always the primary —
		// so linked devices authenticate as themselves and device-scoped
		// authorization is enforceable downstream (mirrors the REST middleware).
		device := acct.GetDevice(deviceID)
		if device == nil || device.AuthTokenHash == nil {
			_ = dummyHash.Verify(password)
			return nil, status.Error(codes.Unauthenticated, "invalid credentials")
		}
		if !device.AuthTokenHash.Verify(password) {
			return nil, status.Error(codes.Unauthenticated, "invalid credentials")
		}

		ctx = context.WithValue(ctx, AccountContextKey, acct)
		ctx = context.WithValue(ctx, DeviceContextKey, deviceID)
		return handler(ctx, req)
	}
}

// AnonymousUnary returns a UnaryServerInterceptor for services annotated
// as AUTH_ONLY_ANONYMOUS. It rejects any request that carries Basic
// credentials — anonymous services must be reached with no
// `authorization` metadata present.
//
// This mirrors Java Signal-Server's require.auth = AUTH_ONLY_ANONYMOUS
// semantic: the RPC accepts only unauthenticated callers (sealed sender,
// group-send-credentialed calls, etc.) and the transport layer enforces
// that no authenticated credential leaks into the handler.
func AnonymousUnary() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		md, ok := metadata.FromIncomingContext(ctx)
		if ok {
			if vals := md.Get("authorization"); len(vals) > 0 {
				return nil, status.Error(codes.PermissionDenied, "anonymous endpoint rejects authenticated credentials")
			}
		}
		return handler(ctx, req)
	}
}

// parseBasicMetadata extracts Basic credentials from gRPC metadata. Only
// the first `authorization` entry is examined; multiple entries return an
// error to avoid ambiguity about which one was honoured.
func parseBasicMetadata(md metadata.MD) (username string, password []byte, err error) {
	values := md.Get("authorization")
	switch len(values) {
	case 0:
		return "", nil, errors.New("no authorization metadata")
	case 1:
		// ok
	default:
		return "", nil, errors.New("multiple authorization entries")
	}
	auth := values[0]
	const prefix = "Basic "
	if !strings.HasPrefix(auth, prefix) {
		return "", nil, errors.New("not Basic auth")
	}
	// raw is an owned buffer: it is never converted to a string, and the
	// password is returned as a sub-slice of it for the caller to wipe.
	raw, err := base64.StdEncoding.DecodeString(auth[len(prefix):])
	if err != nil {
		secure.Wipe(raw)
		return "", nil, errors.New("malformed Basic credential")
	}
	idx := bytes.IndexByte(raw, ':')
	if idx < 0 {
		secure.Wipe(raw)
		return "", nil, errors.New("malformed Basic credential")
	}
	// The username is an identifier, not a secret; copy it out and wipe its
	// half of the buffer so only the password remains live.
	username = string(raw[:idx])
	secure.Wipe(raw[:idx+1])
	return username, raw[idx+1:], nil
}
