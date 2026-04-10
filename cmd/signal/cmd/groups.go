package cmd

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(listGroupsCmd)
	rootCmd.AddCommand(updateGroupCmd)
	rootCmd.AddCommand(quitGroupCmd)
	rootCmd.AddCommand(joinGroupCmd)

	updateGroupCmd.Flags().String("name", "", "group name")
	updateGroupCmd.Flags().String("group-id", "", "existing group ID")
	updateGroupCmd.Flags().String("description", "", "group description")
	updateGroupCmd.Flags().StringSlice("member", nil, "add member")

	quitGroupCmd.Flags().String("group-id", "", "group ID to leave")
	joinGroupCmd.Flags().String("uri", "", "group invite URI")
}

var listGroupsCmd = &cobra.Command{
	Use:   "listGroups",
	Short: "List groups",
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := newClient()
		if err != nil {
			return err
		}
		defer client.Close()

		groups, err := client.ListGroups(context.Background())
		if err != nil {
			return err
		}

		if outputFmt == "json" {
			return json.NewEncoder(cmd.OutOrStdout()).Encode(groups)
		}
		if len(groups) == 0 {
			fmt.Fprintln(cmd.OutOrStdout(), "No groups.")
			return nil
		}
		for _, g := range groups {
			fmt.Fprintf(cmd.OutOrStdout(), "%s: %s\n", g.ID, g.Name)
		}
		return nil
	},
}

var updateGroupCmd = &cobra.Command{
	Use:   "updateGroup",
	Short: "Create or modify a group",
	RunE: func(cmd *cobra.Command, args []string) error {
		return fmt.Errorf("updateGroup: not yet fully implemented")
	},
}

var quitGroupCmd = &cobra.Command{
	Use:   "quitGroup",
	Short: "Leave a group",
	RunE: func(cmd *cobra.Command, args []string) error {
		return fmt.Errorf("quitGroup: not yet implemented")
	},
}

var joinGroupCmd = &cobra.Command{
	Use:   "joinGroup",
	Short: "Join a group via invite link",
	RunE: func(cmd *cobra.Command, args []string) error {
		return fmt.Errorf("joinGroup: not yet implemented")
	},
}
