package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print svr2 version information",
	Run: func(cmd *cobra.Command, _ []string) {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(),
			"svr2 %s\n  commit: %s\n  built:  %s\n",
			version, gitCommit, buildDate)
	},
}

func init() { rootCmd.AddCommand(versionCmd) }
