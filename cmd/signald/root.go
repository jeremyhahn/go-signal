package main

import (
	"log/slog"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-signal/pkg/config"
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

// addressKeys are the addresses signald binds, dials or advertises, each
// settable by flag, environment and config file (flags > env > file >
// defaults).
var addressKeys = []config.AddressKey{
	config.KeyHealthListen,
	config.KeyServerHTTPListen,
	config.KeyServerGRPCListen,
	config.KeyKeyTransparencyRemoteAddr,
	config.KeyVerificationRemoteAddr,
	config.KeyStorageServiceRemoteURL,
	config.KeySVR2RemoteURL,
	config.KeyAttachmentsTusURI,
}

// rootCmd is the base command for the signald server.
var rootCmd = &cobra.Command{
	Use:   "signald",
	Short: "Signal messaging server",
	Long:  "A Go implementation of the Signal messaging server providing encrypted messaging, voice, and video services.",
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		if _, ok := secretFreeCommands[cmd.Name()]; ok {
			return nil
		}
		// Configuration loading seals secrets, so the lifecycle comes first.
		if err := startSecureMemory(); err != nil {
			return err
		}

		loaded, err := config.LoadWithFlags(cfgPath, cmd.Flags())
		if err != nil {
			return &StartupError{Stage: "loading configuration", Cause: err}
		}
		cfg = loaded
		return nil
	},
	SilenceUsage:  true,
	SilenceErrors: true,
}

func init() {
	config.AddAddressFlags(rootCmd.PersistentFlags(), addressKeys...)
	rootCmd.PersistentFlags().StringVar(&cfgPath, "config", "configs/signal-server.yml", "path to configuration file")
}

// Execute runs the root command with main's logger, starting secure memory
// through start before any command loads configuration, and returns any
// error.
func Execute(l *slog.Logger, start func() error) error {
	logger, startSecureMemory = l, start
	return rootCmd.Execute()
}
