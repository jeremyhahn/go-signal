package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print registration-service version information",
	Run: func(cmd *cobra.Command, _ []string) {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(),
			"registration-service %s\n  commit: %s\n  built:  %s\n",
			version, gitCommit, buildDate)
	},
}

func init() { rootCmd.AddCommand(versionCmd) }
