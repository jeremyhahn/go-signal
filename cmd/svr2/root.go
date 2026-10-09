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

var rootCmd = &cobra.Command{
	Use:   "svr2",
	Short: "Signal SVR2 (Secure Value Recovery v2) service",
	Long: "Standalone SVR2 service: hosts the SVR4 state machine over a " +
		"Noise NKhfs-encrypted WebSocket, plus an admin HTTP endpoint " +
		"that the chat-server (signald) calls on account deletion.",
	PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
		if cmd.Name() == "version" {
			return nil
		}
		loaded, err := config.Load(cmd.Context(), cfgPath)
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
	rootCmd.PersistentFlags().StringVar(&cfgPath, "config",
		"configs/svr2.yml",
		"path to configuration file")
}

// Execute runs the root command.
func Execute() error { return rootCmd.Execute() }
