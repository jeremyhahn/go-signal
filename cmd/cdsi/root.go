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

// addressKeys are the listen addresses cdsi binds, each settable by flag,
// environment and config file.
var addressKeys = []config.AddressKey{config.KeyCDSIWSListen}

var rootCmd = &cobra.Command{
	Use:   "cdsi",
	Short: "Signal Contact Discovery v2 service",
	Long: "Standalone CDSI service: hosts the contact-discovery " +
		"protocol over a Noise NKhfs-encrypted WebSocket. " +
		"Populates its in-memory directory by streaming from " +
		"signald's DirectoryService at startup.",
	PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
		if _, ok := secretFreeCommands[cmd.Name()]; ok {
			return nil
		}
		// Configuration loading seals secrets, so the lifecycle comes first.
		if err := startSecureMemory(); err != nil {
			return err
		}
		loaded, err := config.LoadWithFlags(cfgPath, cmd.Flags())
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
		"configs/cdsi.yml",
		"path to configuration file")
}

// Execute runs the root command with main's logger, starting secure memory
// through start before any command loads configuration.
func Execute(l *slog.Logger, start func() error) error {
	logger, startSecureMemory = l, start
	return rootCmd.Execute()
}
