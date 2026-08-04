package cmd

import (
	"encoding/json"
	"fmt"

	signal "github.com/jeremyhahn/go-signal/sdk/go"
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
		defer func() { _ = client.Close() }()

		groups, err := client.ListGroups(cmd.Context())
		if err != nil {
			return err
		}

		if outputFmt == "json" {
			return json.NewEncoder(cmd.OutOrStdout()).Encode(groups)
		}
		if len(groups) == 0 {
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), "No groups.")
			return nil
		}
		for _, g := range groups {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s: %s\n", g.ID, g.Name)
		}
		return nil
	},
}

var updateGroupCmd = &cobra.Command{
	Use:   "updateGroup",
	Short: "Create or modify a group",
	RunE: func(cmd *cobra.Command, args []string) error {
		name, _ := cmd.Flags().GetString("name")
		groupID, _ := cmd.Flags().GetString("group-id")
		description, _ := cmd.Flags().GetString("description")
		members, _ := cmd.Flags().GetStringSlice("member")

		client, err := newClient()
		if err != nil {
			return err
		}
		defer func() { _ = client.Close() }()

		ctx := cmd.Context()
		opts := signal.CreateGroupOptions{
			Name:        name,
			Description: description,
			Members:     members,
		}

		if groupID != "" {
			group, err := client.UpdateGroup(ctx, groupID, opts)
			if err != nil {
				return &CLIError{Op: "update group", Cause: err}
			}
			if outputFmt == "json" {
				return json.NewEncoder(cmd.OutOrStdout()).Encode(group)
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Group updated: %s (%s)\n", group.Name, group.ID)
			return nil
		}

		// No group ID provided: create a new group.
		if name == "" {
			return &UsageError{Message: "group name is required (--name)"}
		}
		group, err := client.CreateGroup(ctx, opts)
		if err != nil {
			return &CLIError{Op: "create group", Cause: err}
		}
		if outputFmt == "json" {
			return json.NewEncoder(cmd.OutOrStdout()).Encode(group)
		}
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Group created: %s (%s)\n", group.Name, group.ID)
		return nil
	},
}

var quitGroupCmd = &cobra.Command{
	Use:   "quitGroup",
	Short: "Leave a group",
	RunE: func(cmd *cobra.Command, args []string) error {
		groupID, _ := cmd.Flags().GetString("group-id")
		if groupID == "" {
			return &UsageError{Message: "group ID is required (--group-id)"}
		}

		client, err := newClient()
		if err != nil {
			return err
		}
		defer func() { _ = client.Close() }()

		if err := client.QuitGroup(cmd.Context(), groupID); err != nil {
			return &CLIError{Op: "quit group", Cause: err}
		}
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Left group.")
		return nil
	},
}

var joinGroupCmd = &cobra.Command{
	Use:   "joinGroup",
	Short: "Join a group via invite link",
	RunE: func(cmd *cobra.Command, args []string) error {
		uri, _ := cmd.Flags().GetString("uri")
		if uri == "" {
			return &UsageError{Message: "group invite URI is required (--uri)"}
		}

		client, err := newClient()
		if err != nil {
			return err
		}
		defer func() { _ = client.Close() }()

		group, err := client.JoinGroup(cmd.Context(), uri)
		if err != nil {
			return &CLIError{Op: "join group", Cause: err}
		}
		if outputFmt == "json" {
			return json.NewEncoder(cmd.OutOrStdout()).Encode(group)
		}
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Joined group: %s\n", group.Name)
		return nil
	},
}
