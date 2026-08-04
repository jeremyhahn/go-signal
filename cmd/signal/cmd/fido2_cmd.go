package cmd

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"
)

func init() {
	fido2Cmd.AddCommand(fido2ListCmd)
	fido2Cmd.AddCommand(fido2CapabilitiesCmd)
	fido2Cmd.AddCommand(fido2DeleteCmd)
	fido2Cmd.AddCommand(fido2RenameCmd)
	rootCmd.AddCommand(fido2Cmd)
}

var fido2Cmd = &cobra.Command{
	Use:   "fido2",
	Short: "FIDO2 security key management",
}

var fido2CapabilitiesCmd = &cobra.Command{
	Use:   "capabilities",
	Short: "Show server FIDO2 capabilities",
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := newClient()
		if err != nil {
			return err
		}
		defer func() { _ = client.Close() }()

		caps, err := client.FIDO2Capabilities(context.Background())
		if err != nil {
			return err
		}
		return json.NewEncoder(cmd.OutOrStdout()).Encode(caps)
	},
}

var fido2ListCmd = &cobra.Command{
	Use:   "list",
	Short: "List registered security keys",
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := newClient()
		if err != nil {
			return err
		}
		defer func() { _ = client.Close() }()

		creds, err := client.FIDO2ListCredentials(context.Background())
		if err != nil {
			return err
		}

		if outputFmt == "json" {
			return json.NewEncoder(cmd.OutOrStdout()).Encode(creds)
		}
		if len(creds) == 0 {
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), "No security keys registered.")
			return nil
		}
		for _, c := range creds {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s: %s (%s)\n", c.CredentialID, c.Name, c.Transport)
		}
		return nil
	},
}

var fido2DeleteCmd = &cobra.Command{
	Use:   "delete CREDENTIAL_ID",
	Short: "Delete a security key",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := newClient()
		if err != nil {
			return err
		}
		defer func() { _ = client.Close() }()
		return client.FIDO2DeleteCredential(context.Background(), args[0])
	},
}

var fido2RenameCmd = &cobra.Command{
	Use:   "rename CREDENTIAL_ID NAME",
	Short: "Rename a security key",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := newClient()
		if err != nil {
			return err
		}
		defer func() { _ = client.Close() }()
		return client.FIDO2RenameCredential(context.Background(), args[0], args[1])
	},
}
