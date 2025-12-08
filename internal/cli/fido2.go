// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package cli

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/jeremyhahn/go-keychain/pkg/fido2"
	"github.com/spf13/cobra"
)

// fido2Cmd represents the fido2 command
var fido2Cmd = &cobra.Command{
	Use:   "fido2",
	Short: "Manage FIDO2 security keys",
	Long:  `Commands for managing FIDO2/WebAuthn security keys for authentication`,
}

// fido2ListDevicesCmd lists available FIDO2 devices
var fido2ListDevicesCmd = &cobra.Command{
	Use:   "list-devices",
	Short: "List available FIDO2 security keys",
	Long:  `Enumerate and display all connected FIDO2-compatible security keys`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		printVerbose("Enumerating FIDO2 devices...")

		// Create FIDO2 handler
		fidoConfig := fido2.DefaultConfig
		enumerator := fido2.NewDefaultEnumerator()

		handler, err := fido2.NewHandler(&fidoConfig, enumerator)
		if err != nil {
			handleError(fmt.Errorf("failed to create FIDO2 handler: %w", err))
			return
		}
		defer func() { _ = handler.Close() }()

		// List devices
		devices, err := handler.ListDevices()
		if err != nil {
			handleError(fmt.Errorf("failed to list FIDO2 devices: %w", err))
			return
		}

		if len(devices) == 0 {
			if err := printer.PrintMessage("No FIDO2 devices found"); err != nil {
				handleError(err)
			}
			return
		}

		printVerbose("Found %d FIDO2 device(s)", len(devices))

		// Convert to CLI types
		cliDevices := make([]fido2Device, len(devices))
		for i, dev := range devices {
			cliDevices[i] = fido2Device{
				Path:         dev.Path,
				VendorID:     dev.VendorID,
				ProductID:    dev.ProductID,
				Manufacturer: dev.Manufacturer,
				Product:      dev.Product,
				SerialNumber: dev.SerialNumber,
				Transport:    dev.Transport,
			}
		}

		if err := printer.PrintFIDO2Devices(cliDevices); err != nil {
			handleError(err)
		}
	},
}

// fido2WaitDeviceCmd waits for a FIDO2 device to be connected
var fido2WaitDeviceCmd = &cobra.Command{
	Use:   "wait-device",
	Short: "Wait for a FIDO2 security key to be connected",
	Long:  `Wait until a FIDO2-compatible security key is connected to the system`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		timeout, _ := cmd.Flags().GetDuration("timeout")

		if err := printer.PrintMessage("Waiting for FIDO2 device... (press Ctrl+C to cancel)"); err != nil {
			handleError(err)
			return
		}

		// Create FIDO2 handler
		fidoConfig := fido2.DefaultConfig
		enumerator := fido2.NewDefaultEnumerator()

		handler, err := fido2.NewHandler(&fidoConfig, enumerator)
		if err != nil {
			handleError(fmt.Errorf("failed to create FIDO2 handler: %w", err))
			return
		}
		defer func() { _ = handler.Close() }()

		// Wait for device
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		device, err := handler.WaitForDevice(ctx)
		if err != nil {
			handleError(fmt.Errorf("failed while waiting for device: %w", err))
			return
		}

		if err := printer.PrintSuccess(fmt.Sprintf("Device found: %s (%s)", device.Product, device.Path)); err != nil {
			handleError(err)
		}
	},
}

// fido2RegisterCmd registers a new FIDO2 credential
var fido2RegisterCmd = &cobra.Command{
	Use:   "register <username>",
	Short: "Register a new FIDO2 credential for a user",
	Long: `Register a new FIDO2 credential using a connected security key.
This will create a new credential that can be used for authentication.

The credential information (credential ID and salt) will be output
and should be stored securely for later use during authentication.`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		username := args[0]
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		rpID, _ := cmd.Flags().GetString("rp-id")
		rpName, _ := cmd.Flags().GetString("rp-name")
		displayName, _ := cmd.Flags().GetString("display-name")
		timeout, _ := cmd.Flags().GetDuration("timeout")
		devicePath, _ := cmd.Flags().GetString("device")
		requireUV, _ := cmd.Flags().GetBool("user-verification")

		if displayName == "" {
			displayName = username
		}

		printVerbose("Registering FIDO2 credential for user: %s", username)

		// Create FIDO2 handler
		fidoConfig := fido2.DefaultConfig
		fidoConfig.DevicePath = devicePath
		fidoConfig.RequireUserVerification = requireUV
		enumerator := fido2.NewDefaultEnumerator()

		handler, err := fido2.NewHandler(&fidoConfig, enumerator)
		if err != nil {
			handleError(fmt.Errorf("failed to create FIDO2 handler: %w", err))
			return
		}
		defer func() { _ = handler.Close() }()

		// Create enrollment config
		enrollConfig := fido2.DefaultEnrollmentConfig(username)
		enrollConfig.RelyingParty.ID = rpID
		enrollConfig.RelyingParty.Name = rpName
		enrollConfig.User.DisplayName = displayName
		enrollConfig.Timeout = timeout
		enrollConfig.RequireUserVerification = requireUV

		if err := printer.PrintMessage("Please touch your security key to register..."); err != nil {
			handleError(err)
			return
		}

		// Register the credential
		result, err := handler.EnrollKey(enrollConfig)
		if err != nil {
			handleError(fmt.Errorf("failed to register credential: %w", err))
			return
		}

		printVerbose("Credential registered successfully")

		// Convert to CLI type
		cliResult := &fido2EnrollmentResult{
			CredentialID: result.CredentialID,
			PublicKey:    result.PublicKey,
			AAGUID:       result.AAGUID,
			SignCount:    result.SignCount,
			Salt:         result.Salt,
			User: fido2User{
				ID:          result.User.ID,
				Name:        result.User.Name,
				DisplayName: result.User.DisplayName,
				Icon:        result.User.Icon,
			},
			RelyingParty: fido2RelyingParty{
				ID:   result.RelyingParty.ID,
				Name: result.RelyingParty.Name,
				Icon: result.RelyingParty.Icon,
			},
			Created: result.Created,
		}

		if err := printer.PrintFIDO2Registration(cliResult); err != nil {
			handleError(err)
		}
	},
}

// fido2AuthenticateCmd authenticates using a FIDO2 credential
var fido2AuthenticateCmd = &cobra.Command{
	Use:   "authenticate",
	Short: "Authenticate using a FIDO2 credential",
	Long: `Authenticate using a previously registered FIDO2 credential.
This will derive a secret using the credential ID and salt.

The credential ID and salt must be provided (typically stored during registration).`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		credIDStr, _ := cmd.Flags().GetString("credential-id")
		saltStr, _ := cmd.Flags().GetString("salt")
		rpID, _ := cmd.Flags().GetString("rp-id")
		timeout, _ := cmd.Flags().GetDuration("timeout")
		devicePath, _ := cmd.Flags().GetString("device")
		requireUV, _ := cmd.Flags().GetBool("user-verification")
		outputHex, _ := cmd.Flags().GetBool("hex")

		if credIDStr == "" {
			handleError(fmt.Errorf("credential-id is required"))
			return
		}
		if saltStr == "" {
			handleError(fmt.Errorf("salt is required"))
			return
		}

		// Decode credential ID and salt (support both base64 and hex)
		credID, err := decodeCredentialData(credIDStr)
		if err != nil {
			handleError(fmt.Errorf("invalid credential-id: %w", err))
			return
		}

		salt, err := decodeCredentialData(saltStr)
		if err != nil {
			handleError(fmt.Errorf("invalid salt: %w", err))
			return
		}

		printVerbose("Authenticating with FIDO2 credential...")

		// Create FIDO2 handler
		fidoConfig := fido2.DefaultConfig
		fidoConfig.DevicePath = devicePath
		fidoConfig.RequireUserVerification = requireUV
		enumerator := fido2.NewDefaultEnumerator()

		handler, err := fido2.NewHandler(&fidoConfig, enumerator)
		if err != nil {
			handleError(fmt.Errorf("failed to create FIDO2 handler: %w", err))
			return
		}
		defer func() { _ = handler.Close() }()

		// Create authentication config
		authConfig := fido2.DefaultAuthenticationConfig(credID, salt)
		authConfig.RelyingPartyID = rpID
		authConfig.Timeout = timeout
		authConfig.RequireUserVerification = requireUV

		if err := printer.PrintMessage("Please touch your security key to authenticate..."); err != nil {
			handleError(err)
			return
		}

		// Authenticate
		derivedKey, err := handler.UnlockWithKey(authConfig)
		if err != nil {
			handleError(fmt.Errorf("authentication failed: %w", err))
			return
		}

		printVerbose("Authentication successful")

		// Output the derived key
		var keyOutput string
		if outputHex {
			keyOutput = hex.EncodeToString(derivedKey)
		} else {
			keyOutput = base64.StdEncoding.EncodeToString(derivedKey)
		}

		if cfg.OutputFormat == "json" {
			result := map[string]interface{}{
				"success":     true,
				"derived_key": keyOutput,
				"key_length":  len(derivedKey),
			}
			data, _ := json.MarshalIndent(result, "", "  ")
			fmt.Println(string(data))
		} else {
			if err := printer.PrintSuccess("Authentication successful"); err != nil {
				handleError(err)
			}
			fmt.Printf("Derived Key (%d bytes): %s\n", len(derivedKey), keyOutput)
		}
	},
}

// fido2InfoCmd gets information about a connected FIDO2 device
var fido2InfoCmd = &cobra.Command{
	Use:   "info",
	Short: "Get information about a connected FIDO2 device",
	Long:  `Display detailed information about a connected FIDO2 security key`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		devicePath, _ := cmd.Flags().GetString("device")

		printVerbose("Getting FIDO2 device info...")

		// Create FIDO2 handler with specific device path if provided
		fidoConfig := fido2.DefaultConfig
		fidoConfig.DevicePath = devicePath
		enumerator := fido2.NewDefaultEnumerator()

		handler, err := fido2.NewHandler(&fidoConfig, enumerator)
		if err != nil {
			handleError(fmt.Errorf("failed to create FIDO2 handler: %w", err))
			return
		}
		defer func() { _ = handler.Close() }()

		// List devices and get info for first one (or specified device)
		devices, err := handler.ListDevices()
		if err != nil {
			handleError(fmt.Errorf("failed to list devices: %w", err))
			return
		}

		if len(devices) == 0 {
			handleError(fmt.Errorf("no FIDO2 devices found"))
			return
		}

		// Select device (first one if no path specified)
		var targetDevice fido2.Device
		if devicePath != "" {
			found := false
			for _, dev := range devices {
				if dev.Path == devicePath {
					targetDevice = dev
					found = true
					break
				}
			}
			if !found {
				handleError(fmt.Errorf("device not found: %s", devicePath))
				return
			}
		} else {
			targetDevice = devices[0]
		}

		// Convert to CLI type
		cliDevice := fido2Device{
			Path:         targetDevice.Path,
			VendorID:     targetDevice.VendorID,
			ProductID:    targetDevice.ProductID,
			Manufacturer: targetDevice.Manufacturer,
			Product:      targetDevice.Product,
			SerialNumber: targetDevice.SerialNumber,
			Transport:    targetDevice.Transport,
		}

		if err := printer.PrintFIDO2DeviceInfo(cliDevice); err != nil {
			handleError(err)
		}
	},
}

func init() {
	// Add subcommands
	fido2Cmd.AddCommand(fido2ListDevicesCmd)
	fido2Cmd.AddCommand(fido2WaitDeviceCmd)
	fido2Cmd.AddCommand(fido2RegisterCmd)
	fido2Cmd.AddCommand(fido2AuthenticateCmd)
	fido2Cmd.AddCommand(fido2InfoCmd)

	// wait-device flags
	fido2WaitDeviceCmd.Flags().Duration("timeout", 60*time.Second, "timeout waiting for device")

	// register flags
	fido2RegisterCmd.Flags().String("rp-id", "go-keychain", "relying party ID")
	fido2RegisterCmd.Flags().String("rp-name", "Go Keychain", "relying party name")
	fido2RegisterCmd.Flags().String("display-name", "", "user display name (defaults to username)")
	fido2RegisterCmd.Flags().Duration("timeout", 30*time.Second, "timeout for user presence")
	fido2RegisterCmd.Flags().String("device", "", "specific device path to use")
	fido2RegisterCmd.Flags().Bool("user-verification", false, "require user verification (PIN)")

	// authenticate flags
	fido2AuthenticateCmd.Flags().String("credential-id", "", "credential ID (base64 or hex encoded)")
	fido2AuthenticateCmd.Flags().String("salt", "", "salt value (base64 or hex encoded)")
	fido2AuthenticateCmd.Flags().String("rp-id", "go-keychain", "relying party ID")
	fido2AuthenticateCmd.Flags().Duration("timeout", 30*time.Second, "timeout for user presence")
	fido2AuthenticateCmd.Flags().String("device", "", "specific device path to use")
	fido2AuthenticateCmd.Flags().Bool("user-verification", false, "require user verification (PIN)")
	fido2AuthenticateCmd.Flags().Bool("hex", false, "output derived key in hex format instead of base64")
	_ = fido2AuthenticateCmd.MarkFlagRequired("credential-id")
	_ = fido2AuthenticateCmd.MarkFlagRequired("salt")

	// info flags
	fido2InfoCmd.Flags().String("device", "", "specific device path to use")
}

// decodeCredentialData decodes a credential string that may be base64 or hex encoded
func decodeCredentialData(s string) ([]byte, error) {
	// Try base64 first
	data, err := base64.StdEncoding.DecodeString(s)
	if err == nil {
		return data, nil
	}

	// Try base64 URL encoding
	data, err = base64.URLEncoding.DecodeString(s)
	if err == nil {
		return data, nil
	}

	// Try hex
	data, err = hex.DecodeString(s)
	if err == nil {
		return data, nil
	}

	return nil, fmt.Errorf("could not decode as base64 or hex")
}
