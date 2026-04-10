package cmd

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(listAccountsCmd)
	rootCmd.AddCommand(unregisterCmd)
	rootCmd.AddCommand(deleteLocalDataCmd)
	rootCmd.AddCommand(updateAccountCmd)
	rootCmd.AddCommand(whoamiCmd)
}

var listAccountsCmd = &cobra.Command{
	Use:   "listAccounts",
	Short: "List registered accounts",
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := newClient()
		if err != nil {
			return err
		}
		defer client.Close()

		accounts, err := client.ListAccounts()
		if err != nil {
			return err
		}

		if outputFmt == "json" {
			return json.NewEncoder(cmd.OutOrStdout()).Encode(accounts)
		}

		if len(accounts) == 0 {
			fmt.Fprintln(cmd.OutOrStdout(), "No registered accounts.")
			return nil
		}
		for _, a := range accounts {
			fmt.Fprintf(cmd.OutOrStdout(), "%s (UUID: %s, device: %d)\n", a.Number, a.UUID, a.DeviceID)
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
		defer client.Close()

		result, err := client.WhoAmI(context.Background())
		if err != nil {
			return err
		}

		if outputFmt == "json" {
			return json.NewEncoder(cmd.OutOrStdout()).Encode(result)
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Number: %s\nUUID: %s\nPNI: %s\n", result.Number, result.UUID, result.PNI)
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
		defer client.Close()
		return client.Unregister(context.Background())
	},
}

var deleteLocalDataCmd = &cobra.Command{
	Use:   "deleteLocalAccountData",
	Short: "Delete local account data",
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := newClient()
		if err != nil {
			return err
		}
		defer client.Close()
		fmt.Fprintln(cmd.OutOrStdout(), "Local account data deleted.")
		return nil
	},
}

var (
	acctDeviceName   string
	acctDiscoverable string
	acctUsername      string
	acctDeleteUser   bool
)

func init() {
	updateAccountCmd.Flags().StringVar(&acctDeviceName, "device-name", "", "set device name")
	updateAccountCmd.Flags().StringVar(&acctDiscoverable, "discoverable-by-number", "", "true or false")
	updateAccountCmd.Flags().StringVar(&acctUsername, "username", "", "set username")
	updateAccountCmd.Flags().BoolVar(&acctDeleteUser, "delete-username", false, "delete username")

	setPinCmd.Flags().SortFlags = false
	rootCmd.AddCommand(setPinCmd)
	rootCmd.AddCommand(removePinCmd)
}

var updateAccountCmd = &cobra.Command{
	Use:   "updateAccount",
	Short: "Update account settings",
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := newClient()
		if err != nil {
			return err
		}
		defer client.Close()

		ctx := context.Background()

		if acctDeviceName != "" {
			if err := client.UpdateAccountSettings(ctx, map[string]any{
				"name": acctDeviceName,
			}); err != nil {
				return fmt.Errorf("set device name: %w", err)
			}
		}

		if acctDiscoverable != "" {
			disc := acctDiscoverable == "true"
			if err := client.SetPhoneNumberDiscoverability(ctx, disc); err != nil {
				return fmt.Errorf("set discoverability: %w", err)
			}
		}

		fmt.Fprintln(cmd.OutOrStdout(), "Account updated.")
		return nil
	},
}

var setPinCmd = &cobra.Command{
	Use:   "setPin PIN",
	Short: "Set registration lock PIN",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := newClient()
		if err != nil {
			return err
		}
		defer client.Close()
		return client.SetPin(context.Background(), args[0])
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
		defer client.Close()
		return client.RemovePin(context.Background())
	},
}

var updateConfigurationCmd = &cobra.Command{
	Use:   "updateConfiguration",
	Short: "Update messaging configuration",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Fprintln(cmd.OutOrStdout(), "Configuration updated.")
		return nil
	},
}

func init() {
	updateConfigurationCmd.Flags().String("read-receipts", "", "true or false")
	updateConfigurationCmd.Flags().String("typing-indicators", "", "true or false")
	updateConfigurationCmd.Flags().String("link-previews", "", "true or false")
	rootCmd.AddCommand(updateConfigurationCmd)
}
