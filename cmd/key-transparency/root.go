package main

import (
	"log/slog"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-signal/pkg/config"
	signalerrors "github.com/jeremyhahn/go-signal/pkg/errors"
)

var (
	cfgPath string
	cfg     *config.Config

	// logger is the binary's configured logger. Execute sets it to the one
	// main built; the default stands in only when a test drives a command
	// directly.
	logger = slog.Default()

	// startSecureMemory hardens the process and installs its locked-memory
	// budget. Execute sets it to the Start of main's securemem.Lifecycle.
	startSecureMemory func() error
)

// secretFreeCommands neither load configuration nor construct secrets, so
// they run without the secure-memory lifecycle, on any host memlock limit.
var secretFreeCommands = map[string]struct{}{"version": {}, "help": {}}

// addressKeys are the listen addresses key-transparency binds, each
// settable by flag, environment and config file.
var addressKeys = []config.AddressKey{config.KeyKeyTransparencyGRPCListen, config.KeyHealthListen}

var rootCmd = &cobra.Command{
	Use:   "key-transparency",
	Short: "Signal key-transparency query service",
	Long: "Standalone KT service: hosts the KeyTransparencyQueryService " +
		"gRPC contract over an append-only log. signald reads from this " +
		"service to answer the mobile-client REST endpoints.",
	PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
		if _, ok := secretFreeCommands[cmd.Name()]; ok {
			return nil
		}
		// Configuration loading seals secrets, so the lifecycle comes first.
		if err := startSecureMemory(); err != nil {
			return err
		}
		loaded, err := config.LoadWithFlags(cmd.Context(), cfgPath, cmd.Flags())
		if err != nil {
			return signalerrors.Wrap(signalerrors.ErrInternal, "loading configuration", err)
		}
		cfg = loaded
		return nil
	},
	SilenceUsage:  true,
	SilenceErrors: true,
}

func init() {
	config.AddAddressFlags(rootCmd.PersistentFlags(), addressKeys...)
	rootCmd.PersistentFlags().StringVar(&cfgPath, "config",
		"configs/key-transparency.yml",
		"path to configuration file")
}

// Execute runs the root command with main's logger, starting secure memory
// through start before any command loads configuration.
func Execute(l *slog.Logger, start func() error) error {
	logger, startSecureMemory = l, start
	return rootCmd.Execute()
}
