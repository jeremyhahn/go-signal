package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(listIdentitiesCmd)
	rootCmd.AddCommand(trustCmd)
}

var listIdentitiesCmd = &cobra.Command{
	Use:   "listIdentities",
	Short: "List known identity keys",
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := newClient(cmd.Context())
		if err != nil {
			return err
		}
		defer func() { _ = client.Close() }()

		identities, err := client.ListIdentities(cmd.Context())
		if err != nil {
			return err
		}

		if outputFmt == "json" {
			return json.NewEncoder(cmd.OutOrStdout()).Encode(identities)
		}
		for _, id := range identities {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s: %s (%s)\n", id.Number, id.Fingerprint, id.TrustLevel)
		}
		return nil
	},
}

var trustCmd = &cobra.Command{
	Use:   "trust NUMBER",
	Short: "Trust a contact's identity key",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := newClient(cmd.Context())
		if err != nil {
			return err
		}
		defer func() { _ = client.Close() }()
		return client.TrustIdentity(cmd.Context(), args[0])
	},
}
