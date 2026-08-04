package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/coder/websocket"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	dirpb "github.com/jeremyhahn/go-signal/pkg/api/grpc/genproto/directory"
	"github.com/jeremyhahn/go-signal/pkg/attestation"
	"github.com/jeremyhahn/go-signal/pkg/cdsi"
	"github.com/jeremyhahn/go-signal/pkg/config"
	signalerrors "github.com/jeremyhahn/go-signal/pkg/errors"
	"github.com/jeremyhahn/go-signal/pkg/health"
	"github.com/jeremyhahn/go-signal/pkg/health/checks"
	"github.com/jeremyhahn/go-signal/pkg/metrics"
)

const defaultWSListen = "0.0.0.0:8094"

var startCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the cdsi WebSocket service",
	RunE:  runStart,
}

func init() { rootCmd.AddCommand(startCmd) }

func runStart(cmd *cobra.Command, _ []string) error {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if cfg.CDSI.SharedSecret == "" {
		return errors.New("cdsi: shared secret is required")
	}
	if cfg.CDSI.SignaldDirectoryAddr == "" {
		return errors.New("cdsi: signald directory address is required")
	}

	att, err := buildAttester(cfg.CDSI, logger)
	if err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "attester", err)
	}
	staticPub := att.PublicKey()
	staticPriv, err := staticPrivateKey(att)
	if err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "cdsi", err)
	}

	directory := cdsi.NewMemoryDirectory()
	dispatcher := cdsi.NewDispatcher(directory)

	// Open the gRPC channel to signald and stream the directory.
	conn, err := dialSignald(cfg.CDSI)
	if err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "dial signald", err)
	}
	defer func() { _ = conn.Close() }()
	dirClient := dirpb.NewDirectoryServiceClient(conn)
	if err := cdsi.LoadFromSignald(ctx, dirClient, directory, 1000); err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "load directory", err)
	}
	logger.InfoContext(ctx, "directory loaded",
		slog.Int("entries", directory.Count()))

	// Live-replication: stream DirectoryService.Subscribe and apply
	// change events to the local index. The loop reconnects with
	// exponential backoff and persists resume tokens in-process so
	// short blips don't trigger full resyncs.
	go func() {
		err := cdsi.SubscribeAndApply(ctx, cdsi.SubscribeConfig{
			Client:     dirClient,
			Directory:  directory,
			Logger:     logger,
			TokenStore: cdsi.NewMemoryResumeTokenStore(),
		})
		if err != nil && !errors.Is(err, context.Canceled) {
			logger.ErrorContext(ctx, "directory subscribe loop exited",
				slog.Any("error", err))
		}
	}()

	wsListen := cfg.CDSI.WSListen
	if wsListen == "" {
		wsListen = defaultWSListen
	}
	wsMux := http.NewServeMux()
	wsMux.Handle("/v1/lookup", newWebSocketHandler(logger, att, dispatcher, staticPub, staticPriv, []byte(cfg.CDSI.SharedSecret)))
	probes := health.New()
	metricsReg := metrics.NewRegistry("cdsi")
	// signald's DirectoryService is cdsi's only critical upstream — if
	// the channel is in TransientFailure /readyz reports unready so
	// kubelet drains traffic.
	probes.Add("signald-directory", checks.GRPCConn(conn))
	health.MountAdmin(wsMux, probes, metricsReg)
	wsSrv := &http.Server{
		Addr:              wsListen,
		Handler:           wsMux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	logger.InfoContext(ctx, "cdsi ready",
		slog.String("listen", wsListen),
		slog.String("attestation", att.Type()))

	errs := make(chan error, 1)
	go func() { errs <- wsSrv.ListenAndServe() }()

	select {
	case <-ctx.Done():
		logger.Info("cdsi shutting down")
		probes.SetUnhealthy()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = wsSrv.Shutdown(shutdownCtx)
		return nil
	case err := <-errs:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	}
}

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

func buildAttester(c config.CDSIConfig, logger *slog.Logger) (attestation.Attester, error) {
	switch strings.ToLower(c.Attestation) {
	case "", "software":
		a, err := attestation.NewSoftware(attestation.SoftwareConfig{})
		if err != nil {
			return nil, err
		}
		logger.Info("attester: software",
			slog.String("signerPub", hex.EncodeToString(a.SignerPublic())))
		return a, nil
	case "tpm":
		// See cmd/svr2/start.go for the rationale: go-signal injects
		// TPM implementations rather than binding a TPM transport.
		// Standalone cmd/cdsi runs require attestation="software".
		return nil, signalerrors.New(signalerrors.ErrInternal, "attestation=\"tpm\" requires the binary to be embedded in a host application that injects a TPM via attestation.NewTPM; the standalone cmd/cdsi does not link a TPM transport. Use attestation=\"software\" for direct deployment.")
	default:
		return nil, signalerrors.New(signalerrors.ErrInvalidArgument, fmt.Sprintf("unknown attestation flavour: %q", c.Attestation))
	}
}

func dialSignald(c config.CDSIConfig) (*grpc.ClientConn, error) {
	var opts []grpc.DialOption
	if c.SignaldDirectoryInsecure {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	} else {
		opts = append(opts,
			grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12})))
	}
	return grpc.NewClient(c.SignaldDirectoryAddr, opts...)
}

func newWebSocketHandler(
	logger *slog.Logger,
	att attestation.Attester,
	dispatcher *cdsi.Dispatcher,
	staticPub, staticPriv, hmacSecret []byte,
) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identity, ok := validateBasicAuth(r, hmacSecret)
		if !ok {
			w.Header().Set("WWW-Authenticate", `Basic realm="cdsi"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			logger.Error("ws accept", slog.Any("error", err))
			return
		}
		defer func() { _ = conn.Close(websocket.StatusInternalError, "closed") }()

		ev, err := att.Attest(r.Context(), staticPub)
		if err != nil {
			logger.Error("attest", slog.Any("error", err))
			return
		}
		sess, err := cdsi.NewSession(cdsi.SessionConfig{
			Identity:         identity,
			StaticPrivateKey: staticPriv,
			StaticPublicKey:  staticPub,
			Evidence:         ev.Evidence,
			Endorsement:      ev.Endorsement,
			Dispatcher:       dispatcher,
		})
		if err != nil {
			logger.Error("new session", slog.Any("error", err))
			return
		}

		ctx := r.Context()
		if err := writeFrame(ctx, conn, sess.AttestationFrame()); err != nil {
			return
		}
		msg1, err := readFrame(ctx, conn)
		if err != nil {
			return
		}
		msg2, err := sess.HandleHandshake(msg1)
		if err != nil {
			logger.Debug("handshake", slog.Any("error", err))
			return
		}
		if err := writeFrame(ctx, conn, msg2); err != nil {
			return
		}
		for {
			in, err := readFrame(ctx, conn)
			if err != nil {
				return
			}
			out, err := sess.HandleTransport(ctx, in)
			if err != nil {
				logger.Debug("transport", slog.Any("error", err))
				return
			}
			if err := writeFrame(ctx, conn, out); err != nil {
				return
			}
		}
	})
}

func validateBasicAuth(r *http.Request, secret []byte) (string, bool) {
	const prefix = "Basic "
	hdr := r.Header.Get("Authorization")
	if !strings.HasPrefix(hdr, prefix) {
		return "", false
	}
	raw, err := base64.StdEncoding.DecodeString(hdr[len(prefix):])
	if err != nil {
		return "", false
	}
	sep := strings.IndexByte(string(raw), ':')
	if sep < 0 {
		return "", false
	}
	username := string(raw[:sep])
	password := string(raw[sep+1:])
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(username))
	want := hex.EncodeToString(mac.Sum(nil))
	if subtle.ConstantTimeCompare([]byte(password), []byte(want)) != 1 {
		return "", false
	}
	return username, true
}

func writeFrame(ctx context.Context, conn *websocket.Conn, f cdsi.Frame) error {
	return conn.Write(ctx, websocket.MessageBinary, cdsi.MarshalFrame(f))
}

func readFrame(ctx context.Context, conn *websocket.Conn) (cdsi.Frame, error) {
	mt, data, err := conn.Read(ctx)
	if err != nil {
		return cdsi.Frame{}, err
	}
	if mt != websocket.MessageBinary {
		return cdsi.Frame{}, signalerrors.New(signalerrors.ErrInvalidArgument, fmt.Sprintf("cdsi: unexpected message type %d", mt))
	}
	return cdsi.ParseFrame(data)
}
