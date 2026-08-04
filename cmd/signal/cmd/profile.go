package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	signal "github.com/jeremyhahn/go-signal/sdk/go"
	"github.com/spf13/cobra"
)

var (
	profileGivenName  string
	profileFamilyName string
	profileAbout      string
	profileAboutEmoji string
)

func init() {
	updateProfileCmd.Flags().StringVar(&profileGivenName, "given-name", "", "first name")
	updateProfileCmd.Flags().StringVar(&profileFamilyName, "family-name", "", "last name")
	updateProfileCmd.Flags().StringVar(&profileAbout, "about", "", "about text")
	updateProfileCmd.Flags().StringVar(&profileAboutEmoji, "about-emoji", "", "about emoji")
	rootCmd.AddCommand(updateProfileCmd)
	rootCmd.AddCommand(getUserStatusCmd)
}

var updateProfileCmd = &cobra.Command{
	Use:   "updateProfile",
	Short: "Update your Signal profile",
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := newClient()
		if err != nil {
			return err
		}
		defer func() { _ = client.Close() }()

		return client.UpdateProfile(cmd.Context(), signal.Profile{
			GivenName:  profileGivenName,
			FamilyName: profileFamilyName,
			About:      profileAbout,
			AboutEmoji: profileAboutEmoji,
		})
	},
}

var getUserStatusCmd = &cobra.Command{
	Use:   "getUserStatus NUMBER...",
	Short: "Check if users are registered on Signal",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := newClient()
		if err != nil {
			return err
		}
		defer func() { _ = client.Close() }()

		for _, number := range args {
			profile, err := client.GetProfile(cmd.Context(), number)
			if err != nil {
				if isNotFoundError(err) {
					if outputFmt == "json" {
						_ = json.NewEncoder(cmd.OutOrStdout()).Encode(map[string]any{
							"number":     number,
							"registered": false,
						})
					} else {
						_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s: not registered\n", number)
					}
				} else {
					_, _ = fmt.Fprintf(os.Stderr, "%s: error: %v\n", number, err)
					if outputFmt == "json" {
						_ = json.NewEncoder(cmd.OutOrStdout()).Encode(map[string]any{
							"number": number,
							"error":  err.Error(),
						})
					}
				}
				continue
			}
			if outputFmt == "json" {
				_ = json.NewEncoder(cmd.OutOrStdout()).Encode(map[string]any{
					"number":     number,
					"registered": true,
					"profile":    profile,
				})
			} else {
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s: registered\n", number)
			}
		}
		return nil
	},
}

// isNotFoundError reports whether err indicates the account does not exist.
// It matches signal.NotRegisteredError directly or an APIError with HTTP 404.
func isNotFoundError(err error) bool {
	var notReg *signal.NotRegisteredError
	if errors.As(err, &notReg) {
		return true
	}
	var apiErr *signal.APIError
	return errors.As(err, &apiErr) && apiErr.StatusCode == 404
}
