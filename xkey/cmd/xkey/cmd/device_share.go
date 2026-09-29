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
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/pairing"
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

	// ErrShareKeyLoadFailed indicates the key material to share could not be
	// read from the backend.
	ErrShareKeyLoadFailed = errors.New("device: failed to load key material")

	// ErrShareNoPublicKey indicates the backend holds no public key for the
	// requested key, so there is nothing to share.
	ErrShareNoPublicKey = errors.New("device: backend returned no public key")

	// ErrShareNoKeyMaterial indicates the backend would not export the key
	// material the sharing policy asked to send.
	ErrShareNoKeyMaterial = errors.New("device: backend returned no exportable key material")
)

// sharedKeyMaterial holds everything a share request needs about a key held
// by a local xkmsd backend.
type sharedKeyMaterial struct {
	Algorithm      string
	PublicKeyPEM   []byte
	CertificatePEM []byte
	KeyMaterial    *secure.Buffer
	KeySize        int
}

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
func runDeviceShare(cmd *cobra.Command, args []string) (err error) {
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
		return &SentinelCauseError{Sentinel: ErrDeviceConfigLoadFailed, Cause: err}
	}

	if len(cfg.Devices) == 0 {
		return ErrDeviceNotPaired
	}

	// Select device
	device, err := selectDevice(cfg, deviceName)
	if err != nil {
		return err
	}
	if device == nil {
		if deviceName != "" {
			return &DetailError{Err: ErrDeviceNotFound, Detail: fmt.Sprintf(": %s", deviceName)}
		}
		return ErrDeviceNotPaired
	}

	// Load sharing policy store
	store, err := loadSharingPolicyStore()
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrSharePolicyStoreFailed, Cause: err}
	}

	// Check if sharing is allowed for this key
	allowed, err := store.IsShareAllowed(backend, keyID, device.DeviceFingerprint)
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrSharePolicyStoreFailed, Cause: err}
	}
	if !allowed {
		return &DetailError{Err: ErrSharePolicyDenied, Detail: fmt.Sprintf(": no sharing policy allows %s/%s for device %s", backend, keyID, device.Name)}
	}

	// Get the policy to check what can be shared
	policy, err := store.GetPolicy(backend, keyID)
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrSharePolicyStoreFailed, Cause: err}
	}

	// Read the key material before any radio work. Sending a share request
	// with nothing in it makes the phone reject it with a confusing
	// "missing public_key_pem", so an unreadable key must fail here.
	material, err := loadSharedKeyMaterial(backend, keyID, policy.ShareSymmetric, logger)
	if err != nil {
		return err
	}
	defer material.KeyMaterial.Destroy()
	if policy.SharePublic && len(material.PublicKeyPEM) == 0 {
		return &DetailError{Err: ErrShareNoPublicKey, Detail: fmt.Sprintf(": %s/%s", backend, keyID)}
	}
	if policy.ShareSymmetric && material.KeyMaterial.Size() == 0 {
		return &DetailError{Err: ErrShareNoKeyMaterial, Detail: fmt.Sprintf(": %s/%s", backend, keyID)}
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Sharing key \"%s\" (backend: %s) with device \"%s\"...\n\n",
		keyID, backend, device.Name)

	// The pairing keys, the stored fingerprint and the #129 liveness
	// requirement all come from newPairedDeviceBackendConfig, which is the one
	// place that assembles them. Key ownership transfers to the backend: it is
	// the only thing that knows whether a reader is still live at shutdown,
	// where a caller-side destroy would free pages that reader is still using.
	// Ownership transfers to the component below. It is the only thing that
	// knows whether a reader is still live at shutdown: on an incomplete
	// shutdown it retains the key for the process lifetime, where a
	// caller-side destroy would free pages that reader is still using.

	// Connect to phone
	backendCfg, err := newPairedDeviceBackendConfig(device, timeout, logger)
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrShareConnectFailed, Cause: err}
	}

	phoneBackend, err := phone.NewPhoneKeyBackend(backendCfg)
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrShareConnectFailed, Cause: err}
	}
	defer func() {
		if closeErr := phoneBackend.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Connecting to phone...")
	if err := phoneBackend.Connect(ctx); err != nil {
		return &SentinelCauseError{Sentinel: ErrShareConnectFailed, Cause: err}
	}

	// Share public key if policy allows
	if policy.SharePublic {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Sending public key to phone...")

		req := pairing.NewRequest(pairing.MethodLocalSharePublicKey, &pairing.LocalSharePublicKeyParams{
			Backend:        backend,
			KeyID:          keyID,
			PublicKeyPEM:   material.PublicKeyPEM,
			CertificatePEM: material.CertificatePEM,
			Algorithm:      material.Algorithm,
			Label:          label,
		})

		resp, err := phoneBackend.SendRequest(ctx, req)
		if err != nil {
			return &SentinelCauseError{Sentinel: ErrShareRequestFailed, Cause: err}
		}
		if resp.Error != nil {
			return &DetailError{Err: ErrShareRequestFailed, Detail: fmt.Sprintf(": [%d] %s", resp.Error.Code, resp.Error.Message)}
		}

		result, err := pairing.DecodeResult[pairing.LocalSharePublicKeyResult](resp)
		if err != nil {
			return &WrappedError{Msg: "failed to decode share result", Err: err}
		}

		if result.Accepted {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  Public key accepted (import ID: %s)\n", result.ImportID)
		} else {
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), "  Public key rejected by phone.")
		}
	}

	// Share symmetric key material if policy allows
	if policy.ShareSymmetric {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Sending symmetric key material to phone...")

		// The plaintext key material only materializes for the duration of
		// the request marshal + send, borrowed from protected memory rather
		// than copied into a long-lived local.
		var resp *pairing.Response
		withErr := material.KeyMaterial.WithBytes(func(b []byte) error {
			req := pairing.NewRequest(pairing.MethodLocalShareSymmetric, &pairing.LocalShareSymmetricParams{
				Backend:    backend,
				KeyID:      keyID,
				WrappedKey: b,
				Algorithm:  material.Algorithm,
				KeySize:    material.KeySize,
				Label:      label,
			})

			var sendErr error
			resp, sendErr = phoneBackend.SendRequest(ctx, req)
			return sendErr
		})
		if withErr != nil {
			return &SentinelCauseError{Sentinel: ErrShareRequestFailed, Cause: withErr}
		}
		if resp.Error != nil {
			return &DetailError{Err: ErrShareRequestFailed, Detail: fmt.Sprintf(": [%d] %s", resp.Error.Code, resp.Error.Message)}
		}

		result, err := pairing.DecodeResult[pairing.LocalShareSymmetricResult](resp)
		if err != nil {
			return &WrappedError{Msg: "failed to decode share result", Err: err}
		}

		if result.Accepted {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  Symmetric key accepted (import ID: %s)\n", result.ImportID)
		} else {
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), "  Symmetric key rejected by phone.")
		}
	}

	_, _ = fmt.Fprintln(cmd.OutOrStdout())
	_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Key sharing completed successfully.")

	return nil
}

// loadSharedKeyMaterial reads a key from a local xkmsd backend so it can be
// sent to the phone. The public key and certificate are always fetched; raw
// key material is exported only when the sharing policy asks for it.
func loadSharedKeyMaterial(backend, keyID string, includeSecret bool, logger *slog.Logger) (_ *sharedKeyMaterial, err error) {
	client, err := dialXKMSd(loadXKMSdBridgeConfig(), logger)
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrShareKeyLoadFailed, Cause: err}
	}
	defer func() {
		if closeErr := client.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), defaultXKMSdRequestTimeout)
	defer cancel()

	key, err := client.GetKey(ctx, backend, keyID)
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrShareKeyLoadFailed, Cause: err}
	}

	material := &sharedKeyMaterial{Algorithm: key.Algorithm}
	if key.PublicKeyPEM != "" {
		material.PublicKeyPEM = []byte(key.PublicKeyPEM)
	}

	// A missing certificate is normal, so it never fails the share.
	if cert, certErr := client.GetCertificate(ctx, backend, keyID); certErr == nil && cert != nil {
		material.CertificatePEM = []byte(cert.CertificatePEM)
	}

	if !includeSecret {
		return material, nil
	}

	export, err := client.ExportKeyMaterial(ctx, &transport.ExportKeyMaterialRequest{
		Backend: backend,
		KeyID:   keyID,
	})
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrShareKeyLoadFailed, Cause: err}
	}
	if len(export.KeyMaterial) > 0 {
		buf, bufErr := secure.NewBufferFromBytes(export.KeyMaterial)
		if bufErr != nil {
			return nil, &SentinelCauseError{Sentinel: ErrShareKeyLoadFailed, Cause: bufErr}
		}
		material.KeyMaterial = buf
	}
	material.KeySize = export.KeySize
	if material.Algorithm == "" {
		material.Algorithm = export.KeyType
	}

	return material, nil
}

// runDeviceImport imports a shared key from a paired phone device.
func runDeviceImport(cmd *cobra.Command, args []string) (err error) {
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
		return &SentinelCauseError{Sentinel: ErrDeviceConfigLoadFailed, Cause: err}
	}

	if len(cfg.Devices) == 0 {
		return ErrDeviceNotPaired
	}

	// Select device
	device, err := selectDevice(cfg, deviceName)
	if err != nil {
		return err
	}
	if device == nil {
		if deviceName != "" {
			return &DetailError{Err: ErrDeviceNotFound, Detail: fmt.Sprintf(": %s", deviceName)}
		}
		return ErrDeviceNotPaired
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Importing key \"%s\" from device \"%s\"...\n\n", keyID, device.Name)

	// The pairing keys, the stored fingerprint and the #129 liveness
	// requirement all come from newPairedDeviceBackendConfig, which is the one
	// place that assembles them. Key ownership transfers to the backend: it is
	// the only thing that knows whether a reader is still live at shutdown,
	// where a caller-side destroy would free pages that reader is still using.
	// Ownership transfers to the component below. It is the only thing that
	// knows whether a reader is still live at shutdown: on an incomplete
	// shutdown it retains the key for the process lifetime, where a
	// caller-side destroy would free pages that reader is still using.

	// Connect to phone
	backendCfg, err := newPairedDeviceBackendConfig(device, timeout, logger)
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrShareConnectFailed, Cause: err}
	}

	phoneBackend, err := phone.NewPhoneKeyBackend(backendCfg)
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrShareConnectFailed, Cause: err}
	}
	defer func() {
		if closeErr := phoneBackend.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Connecting to phone...")
	if err := phoneBackend.Connect(ctx); err != nil {
		return &SentinelCauseError{Sentinel: ErrShareConnectFailed, Cause: err}
	}

	// Request key import from phone
	_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Requesting key from phone (check phone for biometric prompt)...")
	_, _ = fmt.Fprintln(cmd.OutOrStdout())

	req := pairing.NewRequest(pairing.MethodLocalImportSharedKey, &pairing.LocalImportSharedKeyParams{
		KeyID: keyID,
	})

	resp, err := phoneBackend.SendRequest(ctx, req)
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrShareImportFailed, Cause: err}
	}
	if resp.Error != nil {
		return &DetailError{Err: ErrShareImportFailed, Detail: fmt.Sprintf(": [%d] %s", resp.Error.Code, resp.Error.Message)}
	}

	result, err := pairing.DecodeResult[pairing.LocalImportSharedKeyResult](resp)
	if err != nil {
		return &WrappedError{Msg: "failed to decode import result", Err: err}
	}

	// Display imported key information
	_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Import Result")
	_, _ = fmt.Fprintln(cmd.OutOrStdout(), strings.Repeat("=", 60))
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  Key ID:          %s\n", keyID)
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  Algorithm:       %s\n", result.Algorithm)
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  Key Type:        %s\n", result.KeyType)
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  Exportable:      %v\n", result.Exportable)
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  Target Backend:  %s\n", targetBackend)

	if len(result.PublicKeyPEM) > 0 {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  Public Key:      %d bytes (PEM)\n", len(result.PublicKeyPEM))
	}
	if len(result.CertificatePEM) > 0 {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  Certificate:     %d bytes (PEM)\n", len(result.CertificatePEM))
	}
	if len(result.WrappedKey) > 0 {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  Wrapped Key:     %d bytes\n", len(result.WrappedKey))
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  Key Size:        %d bits\n", result.KeySize)
	}

	_, _ = fmt.Fprintln(cmd.OutOrStdout())
	_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Key imported successfully.")

	return nil
}
