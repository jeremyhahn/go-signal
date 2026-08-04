package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"
)

var verifySessionID string

func init() {
	verifyCmd.Flags().StringVar(&verifySessionID, "session", "", "verification session ID (from register command)")
	rootCmd.AddCommand(verifyCmd)
}

var verifyCmd = &cobra.Command{
	Use:   "verify NUMBER CODE",
	Short: "Verify a phone number and complete registration",
	Long: `Submit the verification code received via SMS/voice and register
the account with the Signal server.

If --session is provided, it uses the existing session. Otherwise,
it creates a new session and performs the full registration flow.`,
	Args: cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		number := args[0]
		code := args[1]

		client, err := newClient()
		if err != nil {
			return err
		}
		defer func() { _ = client.Close() }()

		ctx := cmd.Context()

		if verifySessionID != "" {
			// Submit code to existing session, then register.
			verified, err := client.SubmitVerificationCode(ctx, verifySessionID, code)
			if err != nil {
				return &CLIError{Op: "verification", Cause: err}
			}
			if !verified.Verified {
				return &UsageError{Message: "verification failed: invalid code"}
			}

			result, err := client.Register(ctx, number, verifySessionID)
			if err != nil {
				return &CLIError{Op: "registration", Cause: err}
			}

			if outputFmt == "json" {
				return json.NewEncoder(cmd.OutOrStdout()).Encode(result)
			}

			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Account registered successfully.\n")
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "UUID: %s\n", result.UUID)
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "PNI:  %s\n", result.PNI)
			return nil
		}

		// Full flow: create session + request code + verify + register.
		result, err := client.Verify(ctx, number, code)
		if err != nil {
			return &CLIError{Op: "registration", Cause: err}
		}

		if outputFmt == "json" {
			return json.NewEncoder(cmd.OutOrStdout()).Encode(result)
		}

		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Account registered successfully.\n")
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "UUID: %s\n", result.UUID)
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "PNI:  %s\n", result.PNI)
		return nil
	},
}
