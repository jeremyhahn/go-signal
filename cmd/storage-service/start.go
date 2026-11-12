package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-signal/pkg/config"
	"github.com/jeremyhahn/go-signal/pkg/config/secrets"
	signalerrors "github.com/jeremyhahn/go-signal/pkg/errors"
	"github.com/jeremyhahn/go-signal/pkg/extservice/common"
	"github.com/jeremyhahn/go-signal/pkg/health"
	"github.com/jeremyhahn/go-signal/pkg/metrics"
	"github.com/jeremyhahn/go-signal/pkg/securestorage"
	memstorage "github.com/jeremyhahn/go-signal/pkg/storage/memory"
	pgstorage "github.com/jeremyhahn/go-signal/pkg/storage/postgres"
	qrdbstorage "github.com/jeremyhahn/go-signal/pkg/storage/qrdb"
)

var startCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the storage-service HTTP server",
	RunE:  runStart,
}

func init() { rootCmd.AddCommand(startCmd) }

func runStart(cmd *cobra.Command, _ []string) error {
	ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Wipe every protected configuration secret on the way out, registered
	// before the first validation can return so an aborted startup leaves
	// nothing resident. Matters most when the command is driven in-process
	// rather than followed immediately by process exit. Destroy is
	// idempotent and nil-safe.
	defer cfg.Destroy()

	if cfg.StorageService.SharedSecret.IsDestroyed(ctx) {
		return errors.New("storage-service: shared secret is required")
	}

	listen := cfg.StorageService.HTTPListen

	store, err := buildManifestStore(ctx, cfg.Storage, logger)
	if err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "manifest store", err)
	}
	probes := health.New()
	metricsReg := metrics.NewRegistry("storage-service")
	mux := http.NewServeMux()
	health.MountAdmin(mux, probes, metricsReg)
	mux.Handle("/", NewMux(store, cfg.StorageService.SharedSecret, logger))

	srv := &http.Server{
		Addr:              listen,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	logger.InfoContext(ctx, "storage-service ready", slog.String("listen", listen))

	errs := make(chan error, 1)
	go func() { errs <- srv.ListenAndServe() }()

	select {
	case <-ctx.Done():
		logger.Info("storage-service shutting down")
		probes.SetUnhealthy()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
		return nil
	case err := <-errs:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	}
}

// buildManifestStore selects the securestorage.ManifestStore implementation
// based on cfg.Backend. "qrdb" wires a QrdbSecureStorageStore behind an
// in-process FakeKVStore (production-equivalent domain store, placeholder
// transport — same pattern signald uses). "postgres" opens a Postgres
// pool and runs migrations. Any other value defaults to MemoryManifestStore.
func buildManifestStore(ctx context.Context, cfg config.StorageConfig, logger *slog.Logger) (securestorage.ManifestStore, error) {
	switch cfg.Backend {
	case "qrdb":
		logger.Info("storage-service: using qrdb storage backend (in-process fake transport)")
		kv := qrdbstorage.NewFakeKVStore()
		return qrdbstorage.NewSecureStorageStore(kv), nil
	case "postgres":
		logger.Info("storage-service: using postgres storage backend")
		dsn, err := cfg.Postgres.DSN(ctx)
		if err != nil {
			return nil, signalerrors.Wrap(signalerrors.ErrInternal, "postgres dsn", err)
		}
		pgClient, err := pgstorage.New(ctx, pgstorage.Config{
			DSN:             dsn,
			MaxConns:        int32(cfg.Postgres.MaxConns),
			MinConns:        int32(cfg.Postgres.MinConns),
			MaxConnLifetime: cfg.Postgres.MaxConnLifetime,
			MaxConnIdleTime: cfg.Postgres.MaxConnIdleTime,
			ConnectTimeout:  cfg.Postgres.ConnectTimeout,
			Logger:          logger,
		})
		if err != nil {
			return nil, signalerrors.Wrap(signalerrors.ErrInternal, "postgres connect", err)
		}
		if err := pgClient.Migrate(ctx); err != nil {
			pgClient.Close()
			return nil, signalerrors.Wrap(signalerrors.ErrInternal, "postgres migrate", err)
		}
		return pgstorage.NewManifestStore(pgClient), nil
	default:
		logger.Info("storage-service: using memory storage backend")
		return memstorage.NewMemoryManifestStore(), nil
	}
}

// NewMux returns the http.Handler exposing the full storage-service
// REST surface. Factored out of runStart so e2e tests can mount it
// onto httptest.NewServer.
func NewMux(store securestorage.ManifestStore, hmacSecret *secrets.SecureString, logger *slog.Logger) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /v1/storage/manifest", basicAuth(hmacSecret, getManifest(store)))
	mux.Handle("PUT /v1/storage/manifest", basicAuth(hmacSecret, putManifest(store)))
	mux.Handle("GET /v1/storage/item/{key}", basicAuth(hmacSecret, getItem(store)))
	mux.Handle("PUT /v1/storage/item/{key}", basicAuth(hmacSecret, putItem(store)))
	mux.Handle("DELETE /v1/storage/item/{key}", basicAuth(hmacSecret, deleteItem(store)))
	mux.Handle("DELETE /v1/storage", basicAuth(hmacSecret, deleteAll(store, logger)))
	return mux
}

// identityCtxKey is the context key under which the authenticated
// identity (account UUID) is stored after Basic-auth validation.
type identityCtxKey struct{}

// basicAuth wraps an http.Handler with HMAC-Basic credential
// validation. On success it stores the identity in the request
// context so handlers can look it up via identityFromContext.
func basicAuth(secret *secrets.SecureString, next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identity, ok := validateBasicAuth(r, secret)
		if !ok {
			w.Header().Set("WWW-Authenticate", `Basic realm="storage-service"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), identityCtxKey{}, identity)))
	})
}

func identityFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(identityCtxKey{}).(string); ok {
		return v
	}
	return ""
}

// validateBasicAuth parses an HTTP Basic header and confirms the password is
// an HMAC-SHA256(secret, username) digest, returning the username on success.
//
// The secret is revealed from protected memory only for the length of the
// digest comparison; an unset or wiped secret authenticates nothing.
func validateBasicAuth(r *http.Request, secret *secrets.SecureString) (string, bool) {
	var (
		identity string
		ok       bool
	)
	secret.WithBytes(r.Context(), func(key []byte) { identity, ok = validateBasicAuthKey(r, key) })
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

// manifestJSON is the wire shape for GET/PUT /v1/storage/manifest.
// Both fields are base64-encoded so the JSON is portable across
// transports that mangle raw bytes.
type manifestJSON struct {
	Version uint64 `json:"version"`
	Value   string `json:"value"`
}

// itemJSON is the wire shape for GET/PUT /v1/storage/item/{key}.
type itemJSON struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

func getManifest(store securestorage.ManifestStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		identity := identityFromContext(r.Context())
		m, err := store.GetManifest(r.Context(), identity)
		if err != nil {
			var notFound *securestorage.ManifestNotFoundError
			if errors.As(err, &notFound) {
				http.Error(w, "manifest not found", http.StatusNotFound)
				return
			}
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, manifestJSON{
			Version: m.Version,
			Value:   base64.StdEncoding.EncodeToString(m.Value),
		})
	}
}

func putManifest(store securestorage.ManifestStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		identity := identityFromContext(r.Context())
		var req manifestJSON
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid body", http.StatusBadRequest)
			return
		}
		value, err := base64.StdEncoding.DecodeString(req.Value)
		if err != nil {
			http.Error(w, "value not base64", http.StatusBadRequest)
			return
		}
		err = store.PutManifest(r.Context(), identity, &securestorage.StorageManifest{
			Version: req.Version, Value: value,
		})
		if err != nil {
			var conflict *securestorage.ManifestVersionConflictError
			if errors.As(err, &conflict) {
				http.Error(w, "version conflict", http.StatusConflict)
				return
			}
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func getItem(store securestorage.ManifestStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		identity := identityFromContext(r.Context())
		key, ok := decodePathKey(r)
		if !ok {
			http.Error(w, "invalid key", http.StatusBadRequest)
			return
		}
		item, err := store.GetItem(r.Context(), identity, key)
		if err != nil {
			var notFound *securestorage.StorageItemNotFoundError
			if errors.As(err, &notFound) {
				http.Error(w, "item not found", http.StatusNotFound)
				return
			}
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, itemJSON{
			Key:   base64.StdEncoding.EncodeToString(item.Key),
			Value: base64.StdEncoding.EncodeToString(item.Value),
		})
	}
}

func putItem(store securestorage.ManifestStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		identity := identityFromContext(r.Context())
		key, ok := decodePathKey(r)
		if !ok {
			http.Error(w, "invalid key", http.StatusBadRequest)
			return
		}
		var req itemJSON
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid body", http.StatusBadRequest)
			return
		}
		value, err := base64.StdEncoding.DecodeString(req.Value)
		if err != nil {
			http.Error(w, "value not base64", http.StatusBadRequest)
			return
		}
		if err := store.PutItem(r.Context(), identity, &securestorage.StorageItem{
			Key: key, Value: value,
		}); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func deleteItem(store securestorage.ManifestStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		identity := identityFromContext(r.Context())
		key, ok := decodePathKey(r)
		if !ok {
			http.Error(w, "invalid key", http.StatusBadRequest)
			return
		}
		if err := store.DeleteItem(r.Context(), identity, key); err != nil {
			var notFound *securestorage.StorageItemNotFoundError
			if errors.As(err, &notFound) {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func deleteAll(store securestorage.ManifestStore, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		identity := identityFromContext(r.Context())
		if err := store.DeleteAll(r.Context(), identity); err != nil {
			logger.Error("DeleteAll", slog.Any("error", err))
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func decodePathKey(r *http.Request) ([]byte, bool) {
	raw := r.PathValue("key")
	if raw == "" {
		return nil, false
	}
	// The wire encodes the key as URL-safe base64 (no padding) so it
	// fits cleanly in a path segment.
	if dec, err := base64.RawURLEncoding.DecodeString(raw); err == nil && len(dec) > 0 {
		return dec, true
	}
	// Fall back to PathEscape-style hex for clients that prefer it.
	if dec, err := url.PathUnescape(raw); err == nil && len(dec) > 0 {
		return []byte(dec), true
	}
	return nil, false
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	// Connection is already half-written; nothing the handler can do
	// if encode fails — the client will see a truncated body.
	_ = json.NewEncoder(w).Encode(body)
}
