package cmd

import (
	"context"
	"encoding/json"
	"fmt"

	signal "github.com/jeremyhahn/go-signal/sdk/go"
	"github.com/spf13/cobra"
)

var (
	sendMessage    string
	sendGroupID    string
	sendNoteToSelf bool
	sendEndSession bool
)

func init() {
	sendCmd.Flags().StringVarP(&sendMessage, "message", "m", "", "message text to send")
	sendCmd.Flags().StringVar(&sendGroupID, "group-id", "", "send to group instead of individual")
	sendCmd.Flags().BoolVar(&sendNoteToSelf, "note-to-self", false, "send message to self")
	sendCmd.Flags().BoolVar(&sendEndSession, "end-session", false, "end the encrypted session")
	rootCmd.AddCommand(sendCmd)
}

var sendCmd = &cobra.Command{
	Use:   "send [RECIPIENT]",
	Short: "Send a message",
	Long: `Send a text message to a Signal recipient (phone number or UUID).

Examples:
  signal send -a +15555550100 -m "Hello" +15555550200
  signal send -a +15555550100 -m "Group msg" --group-id GROUP_ID
  signal send -a +15555550100 -m "Note" --note-to-self`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if sendMessage == "" {
			return fmt.Errorf("message text is required (-m)")
		}

		var recipient string
		if len(args) > 0 {
			recipient = args[0]
		} else if sendNoteToSelf {
			recipient = account // send to self
		} else if sendGroupID == "" {
			return fmt.Errorf("recipient is required (or use --note-to-self or --group-id)")
		}

		client, err := newClient()
		if err != nil {
			return err
		}
		defer client.Close()

		ctx := context.Background()

		opts := &signal.SendOptions{
			GroupID:    sendGroupID,
			NoteToSelf: sendNoteToSelf,
			EndSession: sendEndSession,
		}

		result, err := client.Send(ctx, recipient, sendMessage, opts)
		if err != nil {
			return fmt.Errorf("send failed: %w", err)
		}

		if outputFmt == "json" {
			return json.NewEncoder(cmd.OutOrStdout()).Encode(result)
		}

		fmt.Fprintf(cmd.OutOrStdout(), "Message sent (timestamp: %d)\n", result.Timestamp)
		return nil
	},
}
