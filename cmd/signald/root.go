package main

import (
	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-signal/pkg/config"
)

var (
	cfgPath string
	cfg     *config.Config
)

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
		// Skip config loading for commands that do not require it.
		if cmd.Name() == "version" {
			return nil
		}

		loaded, err := config.LoadWithFlags(cmd.Context(), cfgPath, cmd.Flags())
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

// Execute runs the root command and returns any error.
func Execute() error {
	return rootCmd.Execute()
}
