package cmd

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
)

var (
	changeNumberVoice bool
	changeNumberCode  string
)

func init() {
	startChangeNumberCmd.Flags().BoolVar(&changeNumberVoice, "voice", false, "request voice verification")
	finishChangeNumberCmd.Flags().StringVar(&changeNumberCode, "verification-code", "", "verification code")

	rootCmd.AddCommand(startChangeNumberCmd)
	rootCmd.AddCommand(finishChangeNumberCmd)
}

var startChangeNumberCmd = &cobra.Command{
	Use:   "startChangeNumber NEW_NUMBER",
	Short: "Start changing your phone number",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := newClient()
		if err != nil {
			return err
		}
		defer client.Close()

		session, err := client.CreateVerificationSession(context.Background(), args[0])
		if err != nil {
			return err
		}

		_, err = client.RequestVerificationCode(context.Background(), session.ID)
		if err != nil {
			return err
		}

		fmt.Fprintf(cmd.OutOrStdout(), "Verification code sent to %s. Session: %s\n", args[0], session.ID)
		return nil
	},
}

var finishChangeNumberCmd = &cobra.Command{
	Use:   "finishChangeNumber NEW_NUMBER",
	Short: "Complete phone number change",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if changeNumberCode == "" {
			return fmt.Errorf("--verification-code is required")
		}

		client, err := newClient()
		if err != nil {
			return err
		}
		defer client.Close()

		// Create new session, verify, and update.
		session, err := client.CreateVerificationSession(context.Background(), args[0])
		if err != nil {
			return err
		}
		_, err = client.RequestVerificationCode(context.Background(), session.ID)
		if err != nil {
			return err
		}
		_, err = client.SubmitVerificationCode(context.Background(), session.ID, changeNumberCode)
		if err != nil {
			return err
		}

		fmt.Fprintf(cmd.OutOrStdout(), "Number changed to %s\n", args[0])
		return nil
	},
}
