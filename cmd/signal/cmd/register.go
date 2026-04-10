package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	signal "github.com/jeremyhahn/go-signal/sdk/go"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(registerCmd)
}

var registerCmd = &cobra.Command{
	Use:   "register NUMBER",
	Short: "Register a phone number with the Signal server",
	Long: `Register a new Signal account with the given phone number.
This creates a verification session and requests a verification code.
Use 'signal verify' to complete registration.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		number := args[0]

		client, err := newClient()
		if err != nil {
			return err
		}
		defer client.Close()

		ctx := context.Background()

		// Create verification session.
		session, err := client.CreateVerificationSession(ctx, number)
		if err != nil {
			return fmt.Errorf("failed to create verification session: %w", err)
		}

		// Request code.
		session, err = client.RequestVerificationCode(ctx, session.ID)
		if err != nil {
			return fmt.Errorf("failed to request verification code: %w", err)
		}

		if outputFmt == "json" {
			return json.NewEncoder(cmd.OutOrStdout()).Encode(session)
		}

		fmt.Fprintf(cmd.OutOrStdout(), "Verification code requested for %s\n", number)
		fmt.Fprintf(cmd.OutOrStdout(), "Session ID: %s\n", session.ID)
		fmt.Fprintf(cmd.OutOrStdout(), "Use 'signal verify %s CODE --session %s' to complete registration.\n", number, session.ID)
		return nil
	},
}

// newClient creates a Signal SDK client from CLI flags.
func newClient() (*signal.Client, error) {
	cfg := signal.ClientConfig{
		ServerURL: serverURL,
		DataDir:   configDir,
		Account:   account,
		Verbose:   verbose,
	}

	// Load CA cert into secure memory if specified.
	if caCertFile != "" {
		certData, err := os.ReadFile(caCertFile)
		if err != nil {
			return nil, fmt.Errorf("read CA cert: %w", err)
		}
		cfg.CACert = signal.NewSecurePassword(string(certData))
		// Wipe the file buffer.
		for i := range certData {
			certData[i] = 0
		}
	}

	return signal.NewClient(cfg)
}
