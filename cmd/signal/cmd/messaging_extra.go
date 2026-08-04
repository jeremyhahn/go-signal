package cmd

import (
	"fmt"
	"strconv"
	"strings"

	signal "github.com/jeremyhahn/go-signal/sdk/go"
	"github.com/spf13/cobra"
)

func init() {
	sendReactionCmd.Flags().String("emoji", "", "emoji character")
	sendReactionCmd.Flags().String("target-author", "", "message author")
	sendReactionCmd.Flags().String("target-timestamp", "", "message timestamp")
	sendReactionCmd.Flags().Bool("remove", false, "remove reaction")
	sendReceiptCmd.Flags().String("type", "read", "receipt type: read or viewed")
	sendReceiptCmd.Flags().StringSliceP("timestamps", "t", nil, "message timestamps")
	sendTypingCmd.Flags().Bool("stop", false, "stop typing indicator")
	remoteDeleteCmd.Flags().String("target-timestamp", "", "timestamp of message to delete")

	rootCmd.AddCommand(sendReactionCmd)
	rootCmd.AddCommand(sendReceiptCmd)
	rootCmd.AddCommand(sendTypingCmd)
	rootCmd.AddCommand(remoteDeleteCmd)
	rootCmd.AddCommand(sendContactsCmd)
}

var sendReactionCmd = &cobra.Command{
	Use:   "sendReaction RECIPIENT",
	Short: "Send an emoji reaction to a message",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		emoji, _ := cmd.Flags().GetString("emoji")
		if emoji == "" {
			return &UsageError{Message: "emoji is required (--emoji)"}
		}
		author, _ := cmd.Flags().GetString("target-author")
		tsStr, _ := cmd.Flags().GetString("target-timestamp")
		remove, _ := cmd.Flags().GetBool("remove")

		var ts int64
		if tsStr != "" {
			n, err := strconv.ParseInt(tsStr, 10, 64)
			if err != nil {
				return &UsageError{Message: "invalid target-timestamp: " + tsStr}
			}
			ts = n
		}

		client, err := newClient()
		if err != nil {
			return err
		}
		defer func() { _ = client.Close() }()

		reaction := signal.Reaction{
			Emoji:     emoji,
			Author:    author,
			Timestamp: ts,
			Remove:    remove,
		}
		if err := client.SendReaction(cmd.Context(), args[0], reaction); err != nil {
			return &CLIError{Op: "send reaction", Cause: err}
		}
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Reaction sent.")
		return nil
	},
}

var sendReceiptCmd = &cobra.Command{
	Use:   "sendReceipt RECIPIENT",
	Short: "Send a read/viewed receipt",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		receiptType, _ := cmd.Flags().GetString("type")
		tsStrs, _ := cmd.Flags().GetStringSlice("timestamps")

		if len(tsStrs) == 0 {
			return &UsageError{Message: "at least one timestamp is required (-t)"}
		}

		timestamps := make([]int64, 0, len(tsStrs))
		for _, s := range tsStrs {
			n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
			if err != nil {
				return &UsageError{Message: "invalid timestamp: " + s}
			}
			timestamps = append(timestamps, n)
		}

		client, err := newClient()
		if err != nil {
			return err
		}
		defer func() { _ = client.Close() }()

		if err := client.SendReceipt(cmd.Context(), args[0], strings.ToUpper(receiptType), timestamps); err != nil {
			return &CLIError{Op: "send receipt", Cause: err}
		}
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Receipt sent.")
		return nil
	},
}

var sendTypingCmd = &cobra.Command{
	Use:   "sendTyping RECIPIENT",
	Short: "Send a typing indicator",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		stop, _ := cmd.Flags().GetBool("stop")

		client, err := newClient()
		if err != nil {
			return err
		}
		defer func() { _ = client.Close() }()

		if err := client.SendTyping(cmd.Context(), args[0], stop); err != nil {
			return &CLIError{Op: "send typing", Cause: err}
		}
		return nil
	},
}

var remoteDeleteCmd = &cobra.Command{
	Use:   "remoteDelete RECIPIENT",
	Short: "Delete a message for the recipient",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		tsStr, _ := cmd.Flags().GetString("target-timestamp")
		if tsStr == "" {
			return &UsageError{Message: "target timestamp is required (--target-timestamp)"}
		}
		ts, err := strconv.ParseInt(tsStr, 10, 64)
		if err != nil {
			return &UsageError{Message: "invalid target-timestamp: " + tsStr}
		}

		client, err := newClient()
		if err != nil {
			return err
		}
		defer func() { _ = client.Close() }()

		if err := client.RemoteDelete(cmd.Context(), args[0], ts); err != nil {
			return &CLIError{Op: "remote delete", Cause: err}
		}
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Message deleted.")
		return nil
	},
}

var sendContactsCmd = &cobra.Command{
	Use:   "sendContacts",
	Short: "Sync contacts to all linked devices",
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := newClient()
		if err != nil {
			return err
		}
		defer func() { _ = client.Close() }()

		if err := client.SendContacts(cmd.Context()); err != nil {
			return &CLIError{Op: "send contacts", Cause: err}
		}
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Contacts sync sent.")
		return nil
	},
}
