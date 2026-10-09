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
		"configs/cdsi.yml",
		"path to configuration file")
}

// Execute runs the root command.
func Execute() error { return rootCmd.Execute() }
