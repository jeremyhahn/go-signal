//go:build fido2

package main

import (
	"log/slog"
	"os"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"gopkg.in/yaml.v3"

	"github.com/jeremyhahn/go-signal/pkg/api/rest"
	"github.com/jeremyhahn/go-signal/pkg/config"
	"github.com/jeremyhahn/go-signal/pkg/fido2"
)

// initFIDO2 reads the fido2 section from the config file, initializes the
// FIDO2 accounts manager, and registers the FIDO2 routes on the given
// server. Only compiled with the fido2 build tag.
func initFIDO2(srv *rest.Server, configPath string, logger *slog.Logger) {
	rawYAML, err := os.ReadFile(configPath)
	if err != nil {
		logger.Warn("FIDO2: could not read config file", slog.String("error", err.Error()))
		return
	}

	var wrapper struct {
		FIDO2 config.FIDO2Config `yaml:"fido2"`
	}
	if err := yaml.Unmarshal(rawYAML, &wrapper); err != nil {
		logger.Warn("FIDO2: failed to parse fido2 config section", slog.String("error", err.Error()))
		return
	}

	cfg := &wrapper.FIDO2
	if !cfg.Enabled {
		logger.Info("FIDO2 disabled in config")
		return
	}

	cfg.ApplyDefaults()
	if err := cfg.Validate(); err != nil {
		logger.Error("FIDO2: invalid config", slog.String("error", err.Error()))
		return
	}

	// Create the WebAuthn provider.
	wa, err := webauthn.New(&webauthn.Config{
		RPDisplayName: cfg.RPName,
		RPID:          cfg.RPID,
		RPOrigins:     cfg.RPOrigins,
	})
	if err != nil {
		logger.Error("FIDO2: failed to create WebAuthn provider", slog.String("error", err.Error()))
		return
	}

	provider := fido2.NewDefaultWebAuthnProvider(wa)
	fido2Store := fido2.NewMemoryFIDO2AccountsStore()
	manager := fido2.NewFIDO2AccountsManager(fido2Store, provider, fido2.FIDO2AccountsManagerConfig{
		SessionTimeout: time.Duration(cfg.TimeoutSeconds) * time.Second,
	})

	restCfg := &rest.FIDO2Config{
		Enabled:          cfg.Enabled,
		RPID:             cfg.RPID,
		RPName:           cfg.RPName,
		AllowFIDO2Only:   cfg.AllowFIDO2Only,
		RequireMFA:       cfg.RequireMFA,
		Attestation:      cfg.Attestation,
		UserVerification: cfg.UserVerification,
	}

	srv.RegisterFIDO2(manager, restCfg)

	logger.Info("FIDO2 WebAuthn routes registered",
		slog.String("rpId", cfg.RPID),
		slog.String("rpName", cfg.RPName),
		slog.Int("origins", len(cfg.RPOrigins)))
}
