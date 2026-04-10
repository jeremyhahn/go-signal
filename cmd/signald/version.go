package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print server version information",
	Long:  "Print the version, git commit hash, and build date of the Signal server.",
	Run:   runVersion,
}

func init() {
	rootCmd.AddCommand(versionCmd)
}

func runVersion(cmd *cobra.Command, args []string) {
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "signald %s\n  commit: %s\n  built:  %s\n", version, gitCommit, buildDate)
}
