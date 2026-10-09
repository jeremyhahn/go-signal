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
		if cmd.Name() == "version" {
			return nil
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
		"configs/key-transparency.yml",
		"path to configuration file")
}

// Execute runs the root command.
func Execute() error { return rootCmd.Execute() }
