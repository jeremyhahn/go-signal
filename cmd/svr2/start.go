package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/coder/websocket"
	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-signal/pkg/attestation"
	"github.com/jeremyhahn/go-signal/pkg/config"
	"github.com/jeremyhahn/go-signal/pkg/config/secrets"
	signalerrors "github.com/jeremyhahn/go-signal/pkg/errors"
	"github.com/jeremyhahn/go-signal/pkg/extservice/common"
	"github.com/jeremyhahn/go-signal/pkg/health"
	"github.com/jeremyhahn/go-signal/pkg/metrics"
	qrdbstorage "github.com/jeremyhahn/go-signal/pkg/storage/qrdb"
	"github.com/jeremyhahn/go-signal/pkg/svr2"
)

var startCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the svr2 WebSocket + admin HTTP services",
	RunE:  runStart,
}

func init() { rootCmd.AddCommand(startCmd) }

func runStart(cmd *cobra.Command, _ []string) error {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Wipe every protected configuration secret on the way out, registered
	// before the first validation can return so an aborted startup leaves
	// nothing resident. Matters most when the command is driven in-process
	// rather than followed immediately by process exit. Destroy is
	// idempotent and nil-safe.
	defer cfg.Destroy()

	att, err := buildAttester(cfg.SVR2, logger)
	if err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "attester", err)
	}
	if att == nil {
		return errors.New("svr2: no attester configured")
	}

	storage, err := buildStorage(cfg.Storage)
	if err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "svr2 storage", err)
	}
	dispatcher := svr2.NewDispatcher(storage)
	if cfg.SVR2.SharedSecret.IsDestroyed() {
		return errors.New("svr2: shared secret is required")
	}
	hmacSecret := cfg.SVR2.SharedSecret

	wsListen := cfg.SVR2.WSListen
	httpListen := cfg.SVR2.HTTPListen

	// Snapshot the static key material once at startup. Attester's
	// PublicKey is what the NKhfs responder commits to.
	staticPub := att.PublicKey()
	staticPriv, err := staticPrivateKey(att)
	if err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "svr2", err)
	}

	wsHandler := newWebSocketHandler(logger, att, dispatcher, staticPub, staticPriv, hmacSecret)
	adminHandler := newAdminHandler(logger, storage, hmacSecret)

	wsMux := http.NewServeMux()
	wsMux.Handle("/v1/ws", wsHandler)

	adminMux := http.NewServeMux()
	adminMux.Handle("/v1/delete", adminHandler)
	probes := health.New()
	metricsReg := metrics.NewRegistry("svr2")
	health.MountAdmin(adminMux, probes, metricsReg)

	wsSrv := &http.Server{
		Addr:              wsListen,
		Handler:           wsMux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	adminSrv := &http.Server{
		Addr:              httpListen,
		Handler:           adminMux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	logger.InfoContext(ctx, "svr2 ready",
		slog.String("ws", wsListen),
		slog.String("http", httpListen),
		slog.String("attestation", att.Type()))

	errs := make(chan error, 2)
	go func() { errs <- wsSrv.ListenAndServe() }()
	go func() { errs <- adminSrv.ListenAndServe() }()

	select {
	case <-ctx.Done():
		logger.Info("svr2 shutting down")
		probes.SetUnhealthy()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = wsSrv.Shutdown(shutdownCtx)
		_ = adminSrv.Shutdown(shutdownCtx)
		return nil
	case err := <-errs:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	}
}

// staticPrivateKey extracts the X25519 static private scalar from an
// Attester. Both SoftwareAttester and TPMAttester expose it via a
// concrete method (TPMAttester's eventually moves into the TPM itself).
type privateKeyHolder interface {
	StaticPrivateKey() []byte
}

func staticPrivateKey(att attestation.Attester) ([]byte, error) {
	holder, ok := att.(privateKeyHolder)
	if !ok {
		return nil, errors.New("attester does not expose StaticPrivateKey()")
	}
	return holder.StaticPrivateKey(), nil
}

// buildStorage selects the svr2.Storage implementation based on
// cfg.Storage.Backend. The "qrdb" backend wires QrdbStorage behind
// an in-process FakeKVStore (the same pattern signald uses for the
// qrdb backend before a live qrdb transport is provisioned). Any
// other value defaults to MemoryStorage. The qrdb backend is the
// production-equivalent path; memory is for development and tests.
func buildStorage(cfg config.StorageConfig) (svr2.Storage, error) {
	switch cfg.Backend {
	case "qrdb":
		slog.Info("svr2: using qrdb storage backend (in-process fake transport)")
		kv := qrdbstorage.NewFakeKVStore()
		return svr2.NewQrdbStorage(svr2.QrdbStorageConfig{KV: kv})
	default:
		slog.Info("svr2: using memory storage backend")
		return svr2.NewMemoryStorage(), nil
	}
}

func buildAttester(c config.SVR2Config, logger *slog.Logger) (attestation.Attester, error) {
	switch strings.ToLower(c.Attestation) {
	case "", "software":
		a, err := attestation.NewSoftware(attestation.SoftwareConfig{})
		if err != nil {
			return nil, err
		}
		logger.Info("attester: software (deployment-time ed25519 signing key)",
			slog.String("signerPub", hex.EncodeToString(a.SignerPublic())))
		return a, nil
	case "tpm":
		// go-signal does not bind a TPM 2.0 transport itself. Higher-
		// level applications that need TPM attestation (e.g.,
		// go-quicbaas which already imports go-xkms) construct the
		// TrustedPlatformModule themselves and call
		// attestation.NewTPM(...) directly with it injected. Running
		// cmd/svr2 standalone with attestation="tpm" is therefore not
		// supported — the binary refuses to start with a clear
		// configuration error.
		return nil, signalerrors.New(signalerrors.ErrInternal, "attestation=\"tpm\" requires the binary to be embedded in a host application that injects a TPM via attestation.NewTPM; the standalone cmd/svr2 does not link a TPM transport. Use attestation=\"software\" for direct deployment.")
	default:
		return nil, signalerrors.New(signalerrors.ErrInvalidArgument, fmt.Sprintf("unknown attestation flavour: %q", c.Attestation))
	}
}

// newWebSocketHandler builds the /v1/ws handler. Per Java's
// architecture, mobile clients connect directly here; the chat-server
// does NOT proxy these frames.
func newWebSocketHandler(
	logger *slog.Logger,
	att attestation.Attester,
	dispatcher *svr2.Dispatcher,
	staticPub, staticPriv []byte,
	hmacSecret *secrets.SecureString,
) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identity, ok := validateBasicAuth(r, hmacSecret)
		if !ok {
			w.Header().Set("WWW-Authenticate", `Basic realm="svr2"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
			InsecureSkipVerify: false,
		})
		if err != nil {
			logger.Error("websocket accept", slog.Any("error", err))
			return
		}
		defer func() { _ = conn.Close(websocket.StatusInternalError, "closed") }()

		// First server-to-client frame: attestation evidence.
		ev, err := att.Attest(r.Context(), staticPub)
		if err != nil {
			logger.Error("attest", slog.Any("error", err))
			return
		}
		sessCfg := svr2.SessionConfig{
			Identity:         identity,
			StaticPrivateKey: staticPriv,
			StaticPublicKey:  staticPub,
			Evidence:         ev.Evidence,
			Endorsement:      ev.Endorsement,
			Dispatcher:       dispatcher,
		}
		sess, err := svr2.NewSession(sessCfg)
		if err != nil {
			logger.Error("new session", slog.Any("error", err))
			return
		}

		ctx := r.Context()
		if err := writeFrame(ctx, conn, sess.AttestationFrame()); err != nil {
			logger.Debug("send attestation frame", slog.Any("error", err))
			return
		}

		// Read client message-1; respond with message-2.
		msg1, err := readFrame(ctx, conn)
		if err != nil {
			logger.Debug("read msg1", slog.Any("error", err))
			return
		}
		msg2, err := sess.HandleHandshake(msg1)
		if err != nil {
			logger.Debug("handshake", slog.Any("error", err))
			return
		}
		if err := writeFrame(ctx, conn, msg2); err != nil {
			logger.Debug("send msg2", slog.Any("error", err))
			return
		}

		// Transport loop.
		for {
			frame, err := readFrame(ctx, conn)
			if err != nil {
				return
			}
			resp, err := sess.HandleTransport(ctx, frame)
			if err != nil {
				logger.Debug("transport", slog.Any("error", err))
				return
			}
			if err := writeFrame(ctx, conn, resp); err != nil {
				return
			}
		}
	})
}

// newAdminHandler builds the /v1/delete handler. signald authenticates
// with the same HMAC-derived Basic credentials it gives mobile clients;
// the username is the account identity to delete.
func newAdminHandler(logger *slog.Logger, storage svr2.Storage, hmacSecret *secrets.SecureString) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		identity, ok := validateBasicAuth(r, hmacSecret)
		if !ok {
			w.Header().Set("WWW-Authenticate", `Basic realm="svr2"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if err := storage.Delete(r.Context(), identity); err != nil {
			logger.Error("storage delete", slog.Any("error", err))
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}

// validateBasicAuth parses an HTTP Basic header and confirms the
// password is an HMAC-SHA256(secret, username) digest. Returns the
// username on success — the SVR2 identity for downstream lookups.
// Java's ExternalServiceCredentials uses the same construction.
//
// The secret is revealed from protected memory only for the length of the
// digest comparison; an unset or wiped secret authenticates nothing.
func validateBasicAuth(r *http.Request, secret *secrets.SecureString) (string, bool) {
	var (
		identity string
		ok       bool
	)
	secret.WithBytes(func(key []byte) { identity, ok = validateBasicAuthKey(r, key) })
	return identity, ok
}

func validateBasicAuthKey(r *http.Request, secret []byte) (string, bool) {
	// Delegated rather than repeated. This was a byte-identical third copy of
	// common.ValidateBasicAuth, and that package exists precisely to stop this
	// code diverging across services — its own doc says a divergence "would
	// silently break the HMAC contract".
	//
	// Repeating it also meant repeating its defect: the decoded
	// `username:password` buffer was left resident, and both the presented and
	// the expected credential were copied into Go strings that cannot be wiped
	// (#47). Fixing that three times would have been three chances to miss one.
	return common.ValidateBasicAuth(r.Header.Get("Authorization"), secret)
}

func writeFrame(ctx context.Context, conn *websocket.Conn, f svr2.Frame) error {
	return conn.Write(ctx, websocket.MessageBinary, svr2.MarshalFrame(f))
}

func readFrame(ctx context.Context, conn *websocket.Conn) (svr2.Frame, error) {
	mt, data, err := conn.Read(ctx)
	if err != nil {
		return svr2.Frame{}, err
	}
	if mt != websocket.MessageBinary {
		return svr2.Frame{}, signalerrors.New(signalerrors.ErrInvalidArgument, fmt.Sprintf("svr2: unexpected message type %d", mt))
	}
	return svr2.ParseFrame(data)
}

// suppress unused-import lint when io is only referenced indirectly.
var _ = io.Copy
