package cmd

import (
	"fmt"

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
	Use:   "sendReaction [RECIPIENT]",
	Short: "Send an emoji reaction to a message",
	RunE: func(cmd *cobra.Command, args []string) error {
		return fmt.Errorf("sendReaction: not yet implemented (requires Signal Protocol encryption)")
	},
}

var sendReceiptCmd = &cobra.Command{
	Use:   "sendReceipt [RECIPIENT]",
	Short: "Send a read/viewed receipt",
	RunE: func(cmd *cobra.Command, args []string) error {
		return fmt.Errorf("sendReceipt: not yet implemented (requires Signal Protocol encryption)")
	},
}

var sendTypingCmd = &cobra.Command{
	Use:   "sendTyping [RECIPIENT]",
	Short: "Send a typing indicator",
	RunE: func(cmd *cobra.Command, args []string) error {
		return fmt.Errorf("sendTyping: not yet implemented (requires Signal Protocol encryption)")
	},
}

var remoteDeleteCmd = &cobra.Command{
	Use:   "remoteDelete [RECIPIENT]",
	Short: "Delete a message for the recipient",
	RunE: func(cmd *cobra.Command, args []string) error {
		return fmt.Errorf("remoteDelete: not yet implemented (requires Signal Protocol encryption)")
	},
}

var sendContactsCmd = &cobra.Command{
	Use:   "sendContacts",
	Short: "Upload contacts blob",
	RunE: func(cmd *cobra.Command, args []string) error {
		return fmt.Errorf("sendContacts: not yet implemented")
	},
}

