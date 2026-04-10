package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(listStickerPacksCmd)
	rootCmd.AddCommand(uploadStickerPackCmd)
	rootCmd.AddCommand(addStickerPackCmd)
	rootCmd.AddCommand(getStickerCmd)

	addStickerPackCmd.Flags().String("uri", "", "sticker pack URI")
	getStickerCmd.Flags().String("pack-id", "", "sticker pack ID")
	getStickerCmd.Flags().String("sticker-id", "", "sticker ID within pack")
}

var listStickerPacksCmd = &cobra.Command{
	Use:   "listStickerPacks",
	Short: "List installed sticker packs",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Fprintln(cmd.OutOrStdout(), "[]")
		return nil
	},
}

var uploadStickerPackCmd = &cobra.Command{
	Use:   "uploadStickerPack DIRECTORY",
	Short: "Upload a sticker pack",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		// TODO: read manifest.json, encrypt stickers, upload to CDN
		fmt.Fprintf(cmd.OutOrStdout(), "Sticker pack uploaded from %s\n", args[0])
		return nil
	},
}

var addStickerPackCmd = &cobra.Command{
	Use:   "addStickerPack",
	Short: "Add a sticker pack by URI",
	RunE: func(cmd *cobra.Command, args []string) error {
		uri, _ := cmd.Flags().GetString("uri")
		if uri == "" {
			return fmt.Errorf("--uri is required")
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Sticker pack added: %s\n", uri)
		return nil
	},
}

var getStickerCmd = &cobra.Command{
	Use:   "getSticker",
	Short: "Download a sticker",
	RunE: func(cmd *cobra.Command, args []string) error {
		packID, _ := cmd.Flags().GetString("pack-id")
		stickerID, _ := cmd.Flags().GetString("sticker-id")
		if packID == "" || stickerID == "" {
			return fmt.Errorf("--pack-id and --sticker-id are required")
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Sticker %s:%s downloaded\n", packID, stickerID)
		return nil
	},
}
