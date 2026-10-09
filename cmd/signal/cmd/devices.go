package cmd

import (
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(listDevicesCmd)
	rootCmd.AddCommand(removeDeviceCmd)
	rootCmd.AddCommand(addDeviceCmd)

	addDeviceCmd.Flags().String("uri", "", "provisioning URI from the new device QR code")
}

var listDevicesCmd = &cobra.Command{
	Use:   "listDevices",
	Short: "List linked devices",
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := newClient(cmd.Context())
		if err != nil {
			return err
		}
		defer func() { _ = client.Close() }()

		devices, err := client.ListDevices(cmd.Context())
		if err != nil {
			return err
		}

		if outputFmt == "json" {
			return json.NewEncoder(cmd.OutOrStdout()).Encode(devices)
		}
		for _, d := range devices {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Device %d: %s\n", d.ID, d.Name)
		}
		return nil
	},
}

var removeDeviceCmd = &cobra.Command{
	Use:   "removeDevice DEVICE_ID",
	Short: "Remove a linked device",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		deviceID, err := strconv.Atoi(args[0])
		if err != nil {
			return &UsageError{Message: fmt.Sprintf("invalid device ID: %s", args[0])}
		}
		client, err := newClient(cmd.Context())
		if err != nil {
			return err
		}
		defer func() { _ = client.Close() }()
		return client.RemoveDevice(cmd.Context(), deviceID)
	},
}

var addDeviceCmd = &cobra.Command{
	Use:   "addDevice",
	Short: "Link a new device via provisioning URI",
	RunE: func(cmd *cobra.Command, args []string) error {
		uri, _ := cmd.Flags().GetString("uri")
		if uri == "" {
			return &UsageError{Message: "provisioning URI is required (--uri)"}
		}

		client, err := newClient(cmd.Context())
		if err != nil {
			return err
		}
		defer func() { _ = client.Close() }()

		if err := client.AddDevice(cmd.Context(), uri); err != nil {
			return &CLIError{Op: "add device", Cause: err}
		}
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Device linked successfully.")
		return nil
	},
}
