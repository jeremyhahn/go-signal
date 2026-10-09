package main

import (
	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-signal/pkg/config"
	signalerrors "github.com/jeremyhahn/go-signal/pkg/errors"
)

var (
	cfgPath string
	cfg     *config.Config
)

// addressKeys are the listen addresses storage-service binds, each
// settable by flag, environment and config file.
var addressKeys = []config.AddressKey{config.KeyStorageServiceHTTPListen}

var rootCmd = &cobra.Command{
	Use:   "storage-service",
	Short: "Signal user-manifest storage service",
	Long: "Standalone storage-service: per-account encrypted manifest + " +
		"item storage with HMAC Basic auth. signald only issues " +
		"credentials and calls the admin DELETE endpoint.",
	PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
		if cmd.Name() == "version" {
			return nil
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
		"configs/storage-service.yml",
		"path to configuration file")
}

// Execute runs the root command.
func Execute() error { return rootCmd.Execute() }
