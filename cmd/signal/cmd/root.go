package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

var (
	Version   = "dev"
	GitCommit = "unknown"
	BuildDate = "unknown"
)

// Global flag values.
var (
	configDir  string
	account    string
	serverURL  string
	caCertFile string
	outputFmt  string
	verbose    bool
)

// startSecureMemory hardens the process and installs its locked-memory
// budget. Execute sets it to the Start of main's securemem.Lifecycle.
var startSecureMemory func() error

// secretFreeCommands neither open an account's store nor construct secrets,
// so they run without the secure-memory lifecycle, on any host memlock limit.
var secretFreeCommands = map[string]struct{}{"version": {}, "help": {}}

var rootCmd = &cobra.Command{
	Use:   "signal",
	Short: "Signal messenger client",
	Long: `Signal is a command-line and graphical client for the Signal messaging protocol.

When run without subcommands and a display is available, a graphical
interface is shown. Otherwise, commands are executed in CLI mode.

All server URLs, certificates, and credentials are fully configurable
for self-hosted deployments.`,
	PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
		if _, ok := secretFreeCommands[cmd.Name()]; ok {
			return nil
		}
		// Every other command opens an account's store or handles its keys,
		// so the lifecycle comes first.
		return startSecureMemory()
	},
	SilenceUsage:  true,
	SilenceErrors: true,
}

func init() {
	defaultConfig := filepath.Join(homeDir(), ".config", "signal")

	rootCmd.PersistentFlags().StringVar(&configDir, "config", defaultConfig, "data directory for accounts, keys, and messages")
	rootCmd.PersistentFlags().StringVarP(&account, "account", "a", "", "account phone number (e.g., +15555550100)")
	rootCmd.PersistentFlags().StringVar(&serverURL, "server", "", "server URL (e.g., https://signal.example.com:8081)")
	rootCmd.PersistentFlags().StringVar(&caCertFile, "ca-cert", "", "path to CA certificate PEM file for TLS verification")
	rootCmd.PersistentFlags().StringVar(&outputFmt, "output", "text", "output format: text or json")
	rootCmd.PersistentFlags().BoolVar(&verbose, "verbose", false, "enable debug logging")

	rootCmd.AddCommand(versionCmd)
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run: func(cmd *cobra.Command, args []string) {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "signal %s\n  commit: %s\n  built:  %s\n", Version, GitCommit, BuildDate)
	},
}

// Execute runs the root command, starting secure memory through start
// before any command that holds secrets.
func Execute(start func() error) error {
	startSecureMemory = start
	return rootCmd.Execute()
}

func homeDir() string {
	if h, err := os.UserHomeDir(); err == nil {
		return h
	}
	return "."
}
