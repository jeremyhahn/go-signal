package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(listDevicesCmd)
	rootCmd.AddCommand(removeDeviceCmd)
	rootCmd.AddCommand(addDeviceCmd)
}

var listDevicesCmd = &cobra.Command{
	Use:   "listDevices",
	Short: "List linked devices",
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := newClient()
		if err != nil {
			return err
		}
		defer client.Close()

		devices, err := client.ListDevices(context.Background())
		if err != nil {
			return err
		}

		if outputFmt == "json" {
			return json.NewEncoder(cmd.OutOrStdout()).Encode(devices)
		}
		for _, d := range devices {
			fmt.Fprintf(cmd.OutOrStdout(), "Device %d: %s\n", d.ID, d.Name)
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
			return fmt.Errorf("invalid device ID: %s", args[0])
		}
		client, err := newClient()
		if err != nil {
			return err
		}
		defer client.Close()
		return client.RemoveDevice(context.Background(), deviceID)
	},
}

var addDeviceCmd = &cobra.Command{
	Use:   "addDevice",
	Short: "Link a new device via provisioning URI",
	RunE: func(cmd *cobra.Command, args []string) error {
		return fmt.Errorf("addDevice: not yet implemented")
	},
}
