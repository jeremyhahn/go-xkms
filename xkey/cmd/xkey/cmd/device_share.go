// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

//go:build ble

package cmd

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/phone"
)

// Key sharing errors.
var (
	// ErrSharePolicyDenied indicates the sharing policy denies this operation.
	ErrSharePolicyDenied = errors.New("device: sharing denied by policy")

	// ErrShareConnectFailed indicates the connection to the phone failed during sharing.
	ErrShareConnectFailed = errors.New("device: share connection failed")

	// ErrShareRequestFailed indicates the sharing request to the phone failed.
	ErrShareRequestFailed = errors.New("device: share request failed")

	// ErrShareImportFailed indicates the key import from the phone failed.
	ErrShareImportFailed = errors.New("device: share import failed")

	// ErrSharePolicyStoreFailed indicates the sharing policy store could not be loaded.
	ErrSharePolicyStoreFailed = errors.New("device: sharing policy store failed")
)

// deviceShareCmd shares a key with a paired phone device.
var deviceShareCmd = &cobra.Command{
	Use:   "share <backend> <key-id>",
	Short: "Share a key with a paired phone",
	Long: `Share a key with a paired phone device.

The key's public key and certificate (if any) are sent to the phone.
For symmetric keys with sharing enabled, the key material is also shared.

Hardware-bound keys (TPM, Android Keystore) can only share their public
key and certificate. The private key remains on the originating device.

Examples:
  xkey device share software my-key
  xkey device share tpm2 ek --device "Pixel 8"`,
	Args: cobra.ExactArgs(2),
	RunE: runDeviceShare,
}

// deviceImportCmd imports a shared key from a paired phone device.
var deviceImportCmd = &cobra.Command{
	Use:   "import <key-id>",
	Short: "Import a shared key from a paired phone",
	Long: `Import a key that was shared by a paired phone device.

Retrieves the key's public key, certificate, and optionally symmetric
key material from the phone.

Examples:
  xkey device import my-phone-key
  xkey device import my-phone-key --backend software`,
	Args: cobra.ExactArgs(1),
	RunE: runDeviceImport,
}

func init() {
	deviceCmd.AddCommand(deviceShareCmd)
	deviceCmd.AddCommand(deviceImportCmd)

	// Share command flags
	deviceShareCmd.Flags().String("device", "", "Paired device name to share with")
	deviceShareCmd.Flags().String("label", "", "Label for the shared key on the phone")
	deviceShareCmd.Flags().Duration("timeout", 60*time.Second, "Operation timeout")

	// Import command flags
	deviceImportCmd.Flags().String("backend", "software", "Target backend for imported key")
	deviceImportCmd.Flags().String("device", "", "Paired device name to import from")
	deviceImportCmd.Flags().Duration("timeout", 60*time.Second, "Operation timeout")

	// Bind flags to viper
	_ = viper.BindPFlag("device.share.device", deviceShareCmd.Flags().Lookup("device"))
	_ = viper.BindPFlag("device.share.label", deviceShareCmd.Flags().Lookup("label"))
	_ = viper.BindPFlag("device.share.timeout", deviceShareCmd.Flags().Lookup("timeout"))
	_ = viper.BindPFlag("device.import.backend", deviceImportCmd.Flags().Lookup("backend"))
	_ = viper.BindPFlag("device.import.device", deviceImportCmd.Flags().Lookup("device"))
	_ = viper.BindPFlag("device.import.timeout", deviceImportCmd.Flags().Lookup("timeout"))
}

// runDeviceShare shares a key with a paired phone device.
func runDeviceShare(cmd *cobra.Command, args []string) error {
	backend := args[0]
	keyID := args[1]
	deviceName, _ := cmd.Flags().GetString("device")
	label, _ := cmd.Flags().GetString("label")
	timeout, _ := cmd.Flags().GetDuration("timeout")
	logger := slog.Default()

	// Load phone config
	cfg, err := loadDevicesConfig()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return ErrDeviceNotPaired
		}
		return fmt.Errorf("%w: %v", ErrDeviceConfigLoadFailed, err)
	}

	if len(cfg.Devices) == 0 {
		return ErrDeviceNotPaired
	}

	// Select device
	device := selectDevice(cfg, deviceName)
	if device == nil {
		if deviceName != "" {
			return fmt.Errorf("%w: %s", ErrDeviceNotFound, deviceName)
		}
		return ErrDeviceNotPaired
	}

	// Load sharing policy store
	store, err := loadSharingPolicyStore()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrSharePolicyStoreFailed, err)
	}

	// Check if sharing is allowed for this key
	allowed, err := store.IsShareAllowed(backend, keyID, device.DeviceFingerprint)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrSharePolicyStoreFailed, err)
	}
	if !allowed {
		return fmt.Errorf("%w: no sharing policy allows %s/%s for device %s",
			ErrSharePolicyDenied, backend, keyID, device.Name)
	}

	// Get the policy to check what can be shared
	policy, err := store.GetPolicy(backend, keyID)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrSharePolicyStoreFailed, err)
	}

	fmt.Fprintf(cmd.OutOrStdout(), "Sharing key \"%s\" (backend: %s) with device \"%s\"...\n\n",
		keyID, backend, device.Name)

	// Decode pairing keys
	localPrivateKey, err := base64.StdEncoding.DecodeString(device.LocalNoisePrivateKey)
	if err != nil {
		return fmt.Errorf("invalid local noise key: %w", err)
	}
	remotePublicKey, err := base64.StdEncoding.DecodeString(device.NoisePublicKey)
	if err != nil {
		return fmt.Errorf("invalid phone noise key: %w", err)
	}

	localKey, err := phone.LoadStaticKey(localPrivateKey)
	if err != nil {
		return fmt.Errorf("invalid local noise key: %w", err)
	}

	// Connect to phone
	phoneBackend, err := phone.NewPhoneKeyBackend(&phone.PhoneKeyBackendConfig{
		DeviceAddress:        device.Address,
		LocalStaticKey:       localKey,
		ExpectedRemoteStatic: remotePublicKey,
		ScanTimeout:          30 * time.Second,
		ConnectTimeout:       30 * time.Second,
		OperationTimeout:     timeout,
		Logger:               logger,
	})
	if err != nil {
		return fmt.Errorf("%w: %v", ErrShareConnectFailed, err)
	}
	defer phoneBackend.Close()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	fmt.Fprintln(cmd.OutOrStdout(), "Connecting to phone...")
	if err := phoneBackend.Connect(ctx); err != nil {
		return fmt.Errorf("%w: %v", ErrShareConnectFailed, err)
	}

	// Share public key if policy allows
	if policy.SharePublic {
		fmt.Fprintln(cmd.OutOrStdout(), "Sending public key to phone...")

		req := phone.NewRequest(phone.MethodLocalSharePublicKey, &phone.LocalSharePublicKeyParams{
			Backend:   backend,
			KeyID:     keyID,
			Algorithm: "", // Phone will detect from the key
			Label:     label,
		})

		resp, err := phoneBackend.SendRequest(ctx, req)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrShareRequestFailed, err)
		}
		if resp.Error != nil {
			return fmt.Errorf("%w: [%d] %s", ErrShareRequestFailed, resp.Error.Code, resp.Error.Message)
		}

		result, err := phone.DecodeResult[phone.LocalSharePublicKeyResult](resp)
		if err != nil {
			return fmt.Errorf("failed to decode share result: %w", err)
		}

		if result.Accepted {
			fmt.Fprintf(cmd.OutOrStdout(), "  Public key accepted (import ID: %s)\n", result.ImportID)
		} else {
			fmt.Fprintln(cmd.OutOrStdout(), "  Public key rejected by phone.")
		}
	}

	// Share symmetric key material if policy allows
	if policy.ShareSymmetric {
		fmt.Fprintln(cmd.OutOrStdout(), "Sending symmetric key material to phone...")

		req := phone.NewRequest(phone.MethodLocalShareSymmetric, &phone.LocalShareSymmetricParams{
			Backend: backend,
			KeyID:   keyID,
			Label:   label,
		})

		resp, err := phoneBackend.SendRequest(ctx, req)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrShareRequestFailed, err)
		}
		if resp.Error != nil {
			return fmt.Errorf("%w: [%d] %s", ErrShareRequestFailed, resp.Error.Code, resp.Error.Message)
		}

		result, err := phone.DecodeResult[phone.LocalShareSymmetricResult](resp)
		if err != nil {
			return fmt.Errorf("failed to decode share result: %w", err)
		}

		if result.Accepted {
			fmt.Fprintf(cmd.OutOrStdout(), "  Symmetric key accepted (import ID: %s)\n", result.ImportID)
		} else {
			fmt.Fprintln(cmd.OutOrStdout(), "  Symmetric key rejected by phone.")
		}
	}

	fmt.Fprintln(cmd.OutOrStdout())
	fmt.Fprintln(cmd.OutOrStdout(), "Key sharing completed successfully.")

	return nil
}

// runDeviceImport imports a shared key from a paired phone device.
func runDeviceImport(cmd *cobra.Command, args []string) error {
	keyID := args[0]
	targetBackend, _ := cmd.Flags().GetString("backend")
	deviceName, _ := cmd.Flags().GetString("device")
	timeout, _ := cmd.Flags().GetDuration("timeout")
	logger := slog.Default()

	// Load phone config
	cfg, err := loadDevicesConfig()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return ErrDeviceNotPaired
		}
		return fmt.Errorf("%w: %v", ErrDeviceConfigLoadFailed, err)
	}

	if len(cfg.Devices) == 0 {
		return ErrDeviceNotPaired
	}

	// Select device
	device := selectDevice(cfg, deviceName)
	if device == nil {
		if deviceName != "" {
			return fmt.Errorf("%w: %s", ErrDeviceNotFound, deviceName)
		}
		return ErrDeviceNotPaired
	}

	fmt.Fprintf(cmd.OutOrStdout(), "Importing key \"%s\" from device \"%s\"...\n\n", keyID, device.Name)

	// Decode pairing keys
	localPrivateKey, err := base64.StdEncoding.DecodeString(device.LocalNoisePrivateKey)
	if err != nil {
		return fmt.Errorf("invalid local noise key: %w", err)
	}
	remotePublicKey, err := base64.StdEncoding.DecodeString(device.NoisePublicKey)
	if err != nil {
		return fmt.Errorf("invalid phone noise key: %w", err)
	}

	localKey, err := phone.LoadStaticKey(localPrivateKey)
	if err != nil {
		return fmt.Errorf("invalid local noise key: %w", err)
	}

	// Connect to phone
	phoneBackend, err := phone.NewPhoneKeyBackend(&phone.PhoneKeyBackendConfig{
		DeviceAddress:        device.Address,
		LocalStaticKey:       localKey,
		ExpectedRemoteStatic: remotePublicKey,
		ScanTimeout:          30 * time.Second,
		ConnectTimeout:       30 * time.Second,
		OperationTimeout:     timeout,
		Logger:               logger,
	})
	if err != nil {
		return fmt.Errorf("%w: %v", ErrShareConnectFailed, err)
	}
	defer phoneBackend.Close()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	fmt.Fprintln(cmd.OutOrStdout(), "Connecting to phone...")
	if err := phoneBackend.Connect(ctx); err != nil {
		return fmt.Errorf("%w: %v", ErrShareConnectFailed, err)
	}

	// Request key import from phone
	fmt.Fprintln(cmd.OutOrStdout(), "Requesting key from phone (check phone for biometric prompt)...")
	fmt.Fprintln(cmd.OutOrStdout())

	req := phone.NewRequest(phone.MethodLocalImportSharedKey, &phone.LocalImportSharedKeyParams{
		KeyID: keyID,
	})

	resp, err := phoneBackend.SendRequest(ctx, req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrShareImportFailed, err)
	}
	if resp.Error != nil {
		return fmt.Errorf("%w: [%d] %s", ErrShareImportFailed, resp.Error.Code, resp.Error.Message)
	}

	result, err := phone.DecodeResult[phone.LocalImportSharedKeyResult](resp)
	if err != nil {
		return fmt.Errorf("failed to decode import result: %w", err)
	}

	// Display imported key information
	fmt.Fprintln(cmd.OutOrStdout(), "Import Result")
	fmt.Fprintln(cmd.OutOrStdout(), strings.Repeat("=", 60))
	fmt.Fprintf(cmd.OutOrStdout(), "  Key ID:          %s\n", keyID)
	fmt.Fprintf(cmd.OutOrStdout(), "  Algorithm:       %s\n", result.Algorithm)
	fmt.Fprintf(cmd.OutOrStdout(), "  Key Type:        %s\n", result.KeyType)
	fmt.Fprintf(cmd.OutOrStdout(), "  Exportable:      %v\n", result.Exportable)
	fmt.Fprintf(cmd.OutOrStdout(), "  Target Backend:  %s\n", targetBackend)

	if len(result.PublicKeyPEM) > 0 {
		fmt.Fprintf(cmd.OutOrStdout(), "  Public Key:      %d bytes (PEM)\n", len(result.PublicKeyPEM))
	}
	if len(result.CertificatePEM) > 0 {
		fmt.Fprintf(cmd.OutOrStdout(), "  Certificate:     %d bytes (PEM)\n", len(result.CertificatePEM))
	}
	if len(result.WrappedKey) > 0 {
		fmt.Fprintf(cmd.OutOrStdout(), "  Wrapped Key:     %d bytes\n", len(result.WrappedKey))
		fmt.Fprintf(cmd.OutOrStdout(), "  Key Size:        %d bits\n", result.KeySize)
	}

	fmt.Fprintln(cmd.OutOrStdout())
	fmt.Fprintln(cmd.OutOrStdout(), "Key imported successfully.")

	return nil
}
