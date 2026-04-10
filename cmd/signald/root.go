package main

import (
	"fmt"

	"github.com/jeremyhahn/go-signal/pkg/config"
	"github.com/spf13/cobra"
)

var (
	cfgPath string
	cfg     *config.Config
)

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

		loaded, err := config.Load(cfgPath)
		if err != nil {
			return fmt.Errorf("loading configuration: %w", err)
		}
		cfg = loaded
		return nil
	},
	SilenceUsage:  true,
	SilenceErrors: true,
}

func init() {
	rootCmd.PersistentFlags().StringVar(&cfgPath, "config", "configs/signal-server.yml", "path to configuration file")
}

// Execute runs the root command and returns any error.
func Execute() error {
	return rootCmd.Execute()
}
