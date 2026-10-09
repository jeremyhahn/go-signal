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

// addressKeys are the listen addresses registration-service binds, each
// settable by flag, environment and config file.
var addressKeys = []config.AddressKey{config.KeyVerificationGRPCListen, config.KeyHealthListen}

var rootCmd = &cobra.Command{
	Use:   "registration-service",
	Short: "Signal registration service",
	Long: "Standalone registration service: hosts the gRPC " +
		"RegistrationService contract that signald and other Signal " +
		"server components consume for phone-number verification.",
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
		"configs/registration-service.yml",
		"path to configuration file")
}

// Execute runs the root command.
func Execute() error { return rootCmd.Execute() }
