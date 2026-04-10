package cmd

import (
	"context"
	"fmt"

	signal "github.com/jeremyhahn/go-signal/sdk/go"
	"github.com/spf13/cobra"
)

var (
	challengeToken  string
	challengeCaptcha string
)

func init() {
	submitChallengeCmd.Flags().StringVar(&challengeToken, "challenge", "", "challenge token")
	submitChallengeCmd.Flags().StringVar(&challengeCaptcha, "captcha", "", "captcha solution")
	rootCmd.AddCommand(submitChallengeCmd)
}

var submitChallengeCmd = &cobra.Command{
	Use:   "submitRateLimitChallenge",
	Short: "Submit a rate limit challenge response",
	RunE: func(cmd *cobra.Command, args []string) error {
		if challengeToken == "" {
			return fmt.Errorf("--challenge is required")
		}
		client, err := newClient()
		if err != nil {
			return err
		}
		defer client.Close()

		err = client.SubmitChallenge(context.Background(), challengeToken, challengeCaptcha)
		if err != nil {
			return err
		}
		fmt.Fprintln(cmd.OutOrStdout(), "Challenge submitted.")
		return nil
	},
}

// Ensure SDK has SubmitChallenge method.
var _ = (*signal.Client)(nil)
