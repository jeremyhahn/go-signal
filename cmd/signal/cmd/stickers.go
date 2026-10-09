package cmd

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-signal/pkg/stickers"
	signal "github.com/jeremyhahn/go-signal/sdk/go"
)

func init() {
	rootCmd.AddCommand(listStickerPacksCmd)
	rootCmd.AddCommand(uploadStickerPackCmd)
	rootCmd.AddCommand(addStickerPackCmd)
	rootCmd.AddCommand(getStickerCmd)

	addStickerPackCmd.Flags().String("uri", "", "sticker pack share URL (https://signal.art/addstickers/#pack_id=...&pack_key=...)")

	getStickerCmd.Flags().String("pack-id", "", "sticker pack ID (hex)")
	getStickerCmd.Flags().Int("sticker-id", -1, "sticker ID within pack (use -1 for the manifest)")
	getStickerCmd.Flags().String("pack-key", "", "sticker pack key (hex, 32 bytes)")
	getStickerCmd.Flags().String("out", "", "output path; defaults to stdout")
}

var listStickerPacksCmd = &cobra.Command{
	Use:   "listStickerPacks",
	Short: "List installed sticker packs",
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := newClient(cmd.Context())
		if err != nil {
			return err
		}
		defer func() { _ = client.Close() }()
		packs, err := client.ListStickerPacks()
		if err != nil {
			return err
		}
		if outputFmt == "json" {
			return json.NewEncoder(cmd.OutOrStdout()).Encode(packs)
		}
		if len(packs) == 0 {
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), "(no installed sticker packs)")
			return nil
		}
		for _, p := range packs {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s\t%s\n", p.PackID, p.URL)
		}
		return nil
	},
}

var uploadStickerPackCmd = &cobra.Command{
	Use:   "uploadStickerPack PATH",
	Short: "Upload a sticker pack",
	Long: `Upload a sticker pack to the configured Signal server.

PATH may be a directory containing manifest.json, the manifest.json file
itself, or a .zip archive of the same layout. Each sticker is HKDF-derived
AES-256-CBC + HMAC-SHA256 encrypted with a freshly generated pack key
before upload. The pack key is printed on success; persist it or hand out
the share URL — Signal stores no copy server-side.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := newClient(cmd.Context())
		if err != nil {
			return err
		}
		defer func() { _ = client.Close() }()

		result, err := client.UploadStickerPack(cmd.Context(), args[0])
		if err != nil {
			return err
		}

		if outputFmt == "json" {
			return json.NewEncoder(cmd.OutOrStdout()).Encode(map[string]string{
				"packId":  result.PackID,
				"packKey": fmt.Sprintf("%x", result.PackKey),
				"url":     result.URL,
			})
		}
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), result.URL)
		return nil
	},
}

var addStickerPackCmd = &cobra.Command{
	Use:   "addStickerPack",
	Short: "Add a sticker pack from its share URL",
	Long: `Parse a Signal sticker-pack share URL and persist the pack into the
local registry. The URL takes the canonical form

  https://signal.art/addstickers/#pack_id=<hex>&pack_key=<hex>

After save, subsequent "signal getSticker --pack-id ..." invocations
look up the pack key from the registry — the operator only supplies
the URL once.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		uri, err := cmd.Flags().GetString("uri")
		if err != nil {
			return &CLIError{Op: "get --uri flag", Cause: err}
		}
		if uri == "" {
			return &UsageError{Message: "--uri is required"}
		}
		parsed, err := stickers.ParsePackURL(uri)
		if err != nil {
			return err
		}

		client, err := newClient(cmd.Context())
		if err != nil {
			return err
		}
		defer func() { _ = client.Close() }()

		pack := &signal.InstalledStickerPack{
			PackID:  parsed.PackID,
			PackKey: hex.EncodeToString(parsed.PackKey),
			URL:     uri,
		}
		if err := client.SaveStickerPack(pack); err != nil {
			return err
		}

		if outputFmt == "json" {
			return json.NewEncoder(cmd.OutOrStdout()).Encode(pack)
		}
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "installed sticker pack %s\n", parsed.PackID)
		return nil
	},
}

var getStickerCmd = &cobra.Command{
	Use:   "getSticker",
	Short: "Download and decrypt a sticker",
	Long: `Download an encrypted sticker payload from the configured Signal
server and decrypt it. The pack key is looked up from the local
registry (populated by "addStickerPack") when --pack-key is omitted.

Writes the raw decrypted bytes to --out or stdout. Use
--sticker-id -1 to retrieve the encoded Pack manifest instead of a
sticker image.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		packID, err := cmd.Flags().GetString("pack-id")
		if err != nil {
			return &CLIError{Op: "get --pack-id flag", Cause: err}
		}
		stickerID, err := cmd.Flags().GetInt("sticker-id")
		if err != nil {
			return &CLIError{Op: "get --sticker-id flag", Cause: err}
		}
		packKeyHex, err := cmd.Flags().GetString("pack-key")
		if err != nil {
			return &CLIError{Op: "get --pack-key flag", Cause: err}
		}
		outPath, err := cmd.Flags().GetString("out")
		if err != nil {
			return &CLIError{Op: "get --out flag", Cause: err}
		}
		if packID == "" {
			return &UsageError{Message: "--pack-id is required"}
		}

		client, err := newClient(cmd.Context())
		if err != nil {
			return err
		}
		defer func() { _ = client.Close() }()

		if packKeyHex == "" {
			// Resolve from the local registry.
			packs, err := client.ListStickerPacks()
			if err != nil {
				return &CLIError{Op: "look up pack", Cause: err}
			}
			for _, p := range packs {
				if p.PackID == packID {
					packKeyHex = p.PackKey
					break
				}
			}
			if packKeyHex == "" {
				return &UsageError{Message: fmt.Sprintf("--pack-key not supplied and pack %s is not in the local registry (run addStickerPack first)", packID)}
			}
		}
		if len(packKeyHex) != 2*stickers.PackKeyLen {
			return &UsageError{Message: fmt.Sprintf("pack-key must be %d hex chars (%d bytes), got %d", 2*stickers.PackKeyLen, stickers.PackKeyLen, len(packKeyHex))}
		}
		packKey, err := hex.DecodeString(packKeyHex)
		if err != nil {
			return &CLIError{Op: "parse pack-key hex", Cause: err}
		}

		payload, err := client.GetSticker(cmd.Context(), packID, stickerID, packKey)
		if err != nil {
			return err
		}

		if outPath != "" {
			if err := os.WriteFile(outPath, payload, 0600); err != nil {
				return &CLIError{Op: "write " + outPath, Cause: err}
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "wrote %d bytes to %s\n", len(payload), outPath)
			return nil
		}
		_, _ = cmd.OutOrStdout().Write(payload)
		return nil
	},
}
