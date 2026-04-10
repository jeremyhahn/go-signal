package cmd

import (
	"context"
	"encoding/json"
	"fmt"

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
		defer client.Close()

		return client.UpdateProfile(context.Background(), signal.Profile{
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
		defer client.Close()

		for _, number := range args {
			profile, err := client.GetProfile(context.Background(), number)
			if err != nil {
				fmt.Fprintf(cmd.OutOrStdout(), "%s: not registered\n", number)
				continue
			}
			if outputFmt == "json" {
				json.NewEncoder(cmd.OutOrStdout()).Encode(map[string]any{
					"number":     number,
					"registered": true,
					"profile":    profile,
				})
			} else {
				fmt.Fprintf(cmd.OutOrStdout(), "%s: registered\n", number)
			}
		}
		return nil
	},
}
