package cmd

import (
	"context"
	"encoding/json"
	"fmt"

	signal "github.com/jeremyhahn/go-signal/sdk/go"
	"github.com/spf13/cobra"
)

var (
	receiveTimeout           int
	receiveIgnoreAttachments bool
	receiveSendReadReceipts  bool
)

func init() {
	receiveCmd.Flags().IntVar(&receiveTimeout, "timeout", 5, "receive timeout in seconds")
	receiveCmd.Flags().BoolVar(&receiveIgnoreAttachments, "ignore-attachments", false, "skip downloading attachments")
	receiveCmd.Flags().BoolVar(&receiveSendReadReceipts, "send-read-receipts", false, "send read receipts for received messages")
	rootCmd.AddCommand(receiveCmd)
}

var receiveCmd = &cobra.Command{
	Use:   "receive",
	Short: "Receive pending messages",
	Long: `Fetch and display pending messages from the Signal server.

Examples:
  signal receive -a +15555550100 --timeout 10
  signal receive -a +15555550100 --output json`,
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := newClient()
		if err != nil {
			return err
		}
		defer client.Close()

		ctx := context.Background()

		opts := &signal.ReceiveOptions{
			Timeout:           receiveTimeout,
			IgnoreAttachments: receiveIgnoreAttachments,
			SendReadReceipts:  receiveSendReadReceipts,
		}

		messages, err := client.Receive(ctx, opts)
		if err != nil {
			return fmt.Errorf("receive failed: %w", err)
		}

		if outputFmt == "json" {
			return json.NewEncoder(cmd.OutOrStdout()).Encode(messages)
		}

		if len(messages) == 0 {
			fmt.Fprintln(cmd.OutOrStdout(), "No messages.")
			return nil
		}

		for _, msg := range messages {
			fmt.Fprintf(cmd.OutOrStdout(), "[%d] From: %s (device %d): %s\n",
				msg.Timestamp, msg.Source, msg.SourceDevice, msg.Content)
		}
		return nil
	},
}
