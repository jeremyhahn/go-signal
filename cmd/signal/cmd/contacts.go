package cmd

import (
	"context"
	"encoding/json"
	"fmt"

	signal "github.com/jeremyhahn/go-signal/sdk/go"
	"github.com/spf13/cobra"
)

var (
	contactGivenName  string
	contactFamilyName string
)

func init() {
	listContactsCmd.Flags().Bool("all-recipients", false, "include all known recipients")
	updateContactCmd.Flags().StringVar(&contactGivenName, "given-name", "", "first name")
	updateContactCmd.Flags().StringVar(&contactFamilyName, "family-name", "", "last name")
	removeContactCmd.Flags().Bool("forget", false, "forget all data about contact")

	rootCmd.AddCommand(listContactsCmd)
	rootCmd.AddCommand(updateContactCmd)
	rootCmd.AddCommand(removeContactCmd)
	rootCmd.AddCommand(blockCmd)
	rootCmd.AddCommand(unblockCmd)
}

var listContactsCmd = &cobra.Command{
	Use:   "listContacts",
	Short: "List contacts",
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := newClient()
		if err != nil {
			return err
		}
		defer client.Close()

		contacts, err := client.ListContacts(context.Background())
		if err != nil {
			return err
		}

		if outputFmt == "json" {
			return json.NewEncoder(cmd.OutOrStdout()).Encode(contacts)
		}
		for _, c := range contacts {
			name := c.GivenName
			if c.FamilyName != "" {
				name += " " + c.FamilyName
			}
			blocked := ""
			if c.Blocked {
				blocked = " [BLOCKED]"
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%s %s%s\n", c.Number, name, blocked)
		}
		return nil
	},
}

var updateContactCmd = &cobra.Command{
	Use:   "updateContact NUMBER",
	Short: "Add or update a contact",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := newClient()
		if err != nil {
			return err
		}
		defer client.Close()

		return client.UpdateContact(context.Background(), signal.Contact{
			Number:     args[0],
			GivenName:  contactGivenName,
			FamilyName: contactFamilyName,
		})
	},
}

var removeContactCmd = &cobra.Command{
	Use:   "removeContact NUMBER",
	Short: "Remove a contact",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := newClient()
		if err != nil {
			return err
		}
		defer client.Close()
		return client.RemoveContact(context.Background(), args[0])
	},
}

var blockCmd = &cobra.Command{
	Use:   "block NUMBER",
	Short: "Block a contact",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := newClient()
		if err != nil {
			return err
		}
		defer client.Close()
		return client.Block(context.Background(), args[0])
	},
}

var unblockCmd = &cobra.Command{
	Use:   "unblock NUMBER",
	Short: "Unblock a contact",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := newClient()
		if err != nil {
			return err
		}
		defer client.Close()
		return client.Unblock(context.Background(), args[0])
	},
}
