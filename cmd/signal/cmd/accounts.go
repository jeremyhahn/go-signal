package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	signal "github.com/jeremyhahn/go-signal/sdk/go"
	"golang.org/x/term"

	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(listAccountsCmd)
	rootCmd.AddCommand(unregisterCmd)
	rootCmd.AddCommand(deleteLocalDataCmd)
	rootCmd.AddCommand(updateAccountCmd)
	rootCmd.AddCommand(whoamiCmd)

	updateAccountCmd.Flags().StringVar(&acctDeviceName, "device-name", "", "set device name")
	updateAccountCmd.Flags().StringVar(&acctDiscoverable, "discoverable-by-number", "", "true or false")
	updateAccountCmd.Flags().StringVar(&acctUsername, "username", "", "set username")
	updateAccountCmd.Flags().BoolVar(&acctDeleteUser, "delete-username", false, "delete username")

	setPinCmd.Flags().SortFlags = false
	rootCmd.AddCommand(setPinCmd)
	rootCmd.AddCommand(removePinCmd)

	updateConfigurationCmd.Flags().String("read-receipts", "", "true or false")
	updateConfigurationCmd.Flags().String("typing-indicators", "", "true or false")
	updateConfigurationCmd.Flags().String("link-previews", "", "true or false")
	rootCmd.AddCommand(updateConfigurationCmd)
}

var listAccountsCmd = &cobra.Command{
	Use:   "listAccounts",
	Short: "List registered accounts",
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := newClient()
		if err != nil {
			return err
		}
		defer func() { _ = client.Close() }()

		accounts, err := client.ListAccounts()
		if err != nil {
			return err
		}

		if outputFmt == "json" {
			return json.NewEncoder(cmd.OutOrStdout()).Encode(accounts)
		}

		if len(accounts) == 0 {
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), "No registered accounts.")
			return nil
		}
		for _, a := range accounts {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s (UUID: %s, device: %d)\n", a.Number, a.UUID, a.DeviceID)
		}
		return nil
	},
}

var whoamiCmd = &cobra.Command{
	Use:   "whoami",
	Short: "Show authenticated account identity",
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := newClient()
		if err != nil {
			return err
		}
		defer func() { _ = client.Close() }()

		result, err := client.WhoAmI(cmd.Context())
		if err != nil {
			return err
		}

		if outputFmt == "json" {
			return json.NewEncoder(cmd.OutOrStdout()).Encode(result)
		}
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Number: %s\nUUID: %s\nPNI: %s\n", result.Number, result.UUID, result.PNI)
		return nil
	},
}

var unregisterCmd = &cobra.Command{
	Use:   "unregister",
	Short: "Unregister the account from the server",
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := newClient()
		if err != nil {
			return err
		}
		defer func() { _ = client.Close() }()
		return client.Unregister(cmd.Context())
	},
}

var deleteLocalDataCmd = &cobra.Command{
	Use:   "deleteLocalAccountData",
	Short: "Delete all locally stored account data (irreversible)",
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := newClient()
		if err != nil {
			return err
		}
		// Close first to flush any pending store writes, then remove the data.
		// Destroy() only zeroes credential memory; config.DataDir remains valid.
		if err := client.Close(); err != nil {
			return &CLIError{Op: "close client", Cause: err}
		}
		if err := client.DeleteLocalData(); err != nil {
			return &CLIError{Op: "delete local data", Cause: err}
		}
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Local account data deleted.")
		return nil
	},
}

var (
	acctDeviceName   string
	acctDiscoverable string
	acctUsername     string
	acctDeleteUser   bool
)

var updateAccountCmd = &cobra.Command{
	Use:   "updateAccount",
	Short: "Update account settings",
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := newClient()
		if err != nil {
			return err
		}
		defer func() { _ = client.Close() }()

		if acctDeviceName != "" {
			if err := client.UpdateAccountSettings(cmd.Context(), map[string]any{
				"name": acctDeviceName,
			}); err != nil {
				return &CLIError{Op: "set device name", Cause: err}
			}
		}

		if acctDiscoverable != "" {
			disc := acctDiscoverable == "true"
			if err := client.SetPhoneNumberDiscoverability(cmd.Context(), disc); err != nil {
				return &CLIError{Op: "set discoverability", Cause: err}
			}
		}

		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Account updated.")
		return nil
	},
}

var setPinCmd = &cobra.Command{
	Use:   "setPin",
	Short: "Set registration lock PIN (reads PIN securely from stdin)",
	RunE: func(cmd *cobra.Command, args []string) error {
		_, _ = fmt.Fprint(os.Stderr, "Enter PIN: ")
		pinBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
		_, _ = fmt.Fprintln(os.Stderr)
		if err != nil {
			return &CLIError{Op: "read PIN", Cause: err}
		}
		pin := strings.TrimRight(string(pinBytes), "\r\n")

		client, err := newClient()
		if err != nil {
			return err
		}
		defer func() { _ = client.Close() }()
		return client.SetPin(cmd.Context(), pin)
	},
}

var removePinCmd = &cobra.Command{
	Use:   "removePin",
	Short: "Remove registration lock PIN",
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := newClient()
		if err != nil {
			return err
		}
		defer func() { _ = client.Close() }()
		return client.RemovePin(cmd.Context())
	},
}

var updateConfigurationCmd = &cobra.Command{
	Use:   "updateConfiguration",
	Short: "Update messaging configuration",
	Long: `Update per-account messaging preferences on the server.

At least one flag must be supplied. Pass "true" or "false" for each setting.

Examples:
  signal updateConfiguration --read-receipts true --typing-indicators false
  signal updateConfiguration --link-previews true`,
	RunE: func(cmd *cobra.Command, args []string) error {
		readReceipts, _ := cmd.Flags().GetString("read-receipts")
		typingIndicators, _ := cmd.Flags().GetString("typing-indicators")
		linkPreviews, _ := cmd.Flags().GetString("link-previews")

		if readReceipts == "" && typingIndicators == "" && linkPreviews == "" {
			return &UsageError{Message: "at least one configuration flag must be set (--read-receipts, --typing-indicators, --link-previews)"}
		}

		cfg := signal.AccountConfiguration{}
		if readReceipts != "" {
			v := readReceipts == "true"
			cfg.ReadReceipts = &v
		}
		if typingIndicators != "" {
			v := typingIndicators == "true"
			cfg.TypingIndicators = &v
		}
		if linkPreviews != "" {
			v := linkPreviews == "true"
			cfg.LinkPreviews = &v
		}

		client, err := newClient()
		if err != nil {
			return err
		}
		defer func() { _ = client.Close() }()

		if err := client.UpdateConfiguration(cmd.Context(), cfg); err != nil {
			return &CLIError{Op: "update configuration", Cause: err}
		}
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Configuration updated.")
		return nil
	},
}
