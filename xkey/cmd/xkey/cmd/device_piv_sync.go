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
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/pivcert"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/phone"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// PIV phone sync errors.
var (
	// ErrPIVDeviceSyncFailed indicates PIV sync with phone failed.
	ErrPIVDeviceSyncFailed = errors.New("piv: phone sync failed")

	// ErrPIVDevicePushCertFailed indicates pushing certificate to phone failed.
	ErrPIVDevicePushCertFailed = errors.New("piv: push certificate to phone failed")

	// ErrPIVDevicePullCertFailed indicates pulling certificate from phone failed.
	ErrPIVDevicePullCertFailed = errors.New("piv: pull certificate from phone failed")

	// ErrPIVDeviceListSlotsFailed indicates listing phone PIV slots failed.
	ErrPIVDeviceListSlotsFailed = errors.New("piv: list phone slots failed")

	// ErrPIVDeviceGenerateKeyFailed indicates generating key on phone failed.
	ErrPIVDeviceGenerateKeyFailed = errors.New("piv: generate key on phone failed")
)

// pivDeviceListCmd lists PIV slots on a paired phone.
var pivDeviceListCmd = &cobra.Command{
	Use:   "phone-list",
	Short: "List PIV slots on a paired phone",
	Long: `List the PIV slot contents on a paired phone device over a secure
BLE Noise protocol channel.

Displays which slots have keys and/or certificates, their algorithms,
and certificate subjects.

Examples:
  xkey piv phone-list
  xkey piv phone-list --device "Pixel 8"`,
	RunE: runPIVDeviceList,
}

// pivDevicePushCertCmd pushes a certificate to a PIV slot on a paired phone.
var pivDevicePushCertCmd = &cobra.Command{
	Use:   "phone-push-cert <slot> <cert-file>",
	Short: "Push certificate to a PIV slot on a paired phone",
	Long: `Push a PEM or DER encoded certificate to a PIV slot on a paired phone
device over a secure BLE Noise protocol channel.

Valid slots are:
  9a - PIV Authentication
  9c - Digital Signature
  9d - Key Management
  9e - Card Authentication

Examples:
  xkey piv phone-push-cert 9a /path/to/cert.pem
  xkey piv phone-push-cert 9c signing-cert.pem --device "Pixel 8"`,
	Args: cobra.ExactArgs(2),
	RunE: runPIVDevicePushCert,
}

// pivDevicePullCertCmd pulls a certificate from a PIV slot on a paired phone.
var pivDevicePullCertCmd = &cobra.Command{
	Use:   "phone-pull-cert <slot>",
	Short: "Pull certificate from a PIV slot on a paired phone",
	Long: `Pull a certificate from a PIV slot on a paired phone device over
a secure BLE Noise protocol channel.

The certificate is retrieved and can be saved to a file or displayed.

Valid slots are:
  9a - PIV Authentication
  9c - Digital Signature
  9d - Key Management
  9e - Card Authentication

Examples:
  xkey piv phone-pull-cert 9a --output cert.pem
  xkey piv phone-pull-cert 9c --device "Pixel 8"`,
	Args: cobra.ExactArgs(1),
	RunE: runPIVDevicePullCert,
}

// pivDeviceGenerateKeyCmd generates a key on a PIV slot on a paired phone.
var pivDeviceGenerateKeyCmd = &cobra.Command{
	Use:   "phone-generate <slot>",
	Short: "Generate key in a PIV slot on a paired phone",
	Long: `Request a paired phone device to generate a key pair in the specified
PIV slot over a secure BLE Noise protocol channel.

The key is generated in the phone's hardware-backed keystore. The public
key is returned for certificate enrollment.

Valid slots are:
  9a - PIV Authentication
  9c - Digital Signature
  9d - Key Management
  9e - Card Authentication

Examples:
  xkey piv phone-generate 9a
  xkey piv phone-generate 9c --algorithm ECDSA-P256 --device "Pixel 8"`,
	Args: cobra.ExactArgs(1),
	RunE: runPIVDeviceGenerateKey,
}

func init() {
	PIVCmd.AddCommand(pivDeviceListCmd)
	PIVCmd.AddCommand(pivDevicePushCertCmd)
	PIVCmd.AddCommand(pivDevicePullCertCmd)
	PIVCmd.AddCommand(pivDeviceGenerateKeyCmd)

	// Phone-list flags
	pivDeviceListCmd.Flags().String("device", "", "Paired device name")
	pivDeviceListCmd.Flags().Duration("timeout", 60*time.Second, "Operation timeout")

	// Phone-push-cert flags
	pivDevicePushCertCmd.Flags().String("device", "", "Paired device name")
	pivDevicePushCertCmd.Flags().Duration("timeout", 60*time.Second, "Operation timeout")

	// Phone-pull-cert flags
	pivDevicePullCertCmd.Flags().String("device", "", "Paired device name")
	pivDevicePullCertCmd.Flags().Duration("timeout", 60*time.Second, "Operation timeout")
	pivDevicePullCertCmd.Flags().String("output", "", "Output file path (default: stdout)")

	// Phone-generate flags
	pivDeviceGenerateKeyCmd.Flags().String("device", "", "Paired device name")
	pivDeviceGenerateKeyCmd.Flags().Duration("timeout", 60*time.Second, "Operation timeout")
	pivDeviceGenerateKeyCmd.Flags().StringP("algorithm", "a", "ECDSA-P256",
		"Key algorithm (ECDSA-P256, ECDSA-P384, RSA-2048)")

	// Bind flags to viper
	_ = viper.BindPFlag("piv.phone_list.device", pivDeviceListCmd.Flags().Lookup("device"))
	_ = viper.BindPFlag("piv.phone_list.timeout", pivDeviceListCmd.Flags().Lookup("timeout"))
	_ = viper.BindPFlag("piv.phone_push_cert.device", pivDevicePushCertCmd.Flags().Lookup("device"))
	_ = viper.BindPFlag("piv.phone_push_cert.timeout", pivDevicePushCertCmd.Flags().Lookup("timeout"))
	_ = viper.BindPFlag("piv.phone_pull_cert.device", pivDevicePullCertCmd.Flags().Lookup("device"))
	_ = viper.BindPFlag("piv.phone_pull_cert.timeout", pivDevicePullCertCmd.Flags().Lookup("timeout"))
	_ = viper.BindPFlag("piv.phone_generate.device", pivDeviceGenerateKeyCmd.Flags().Lookup("device"))
	_ = viper.BindPFlag("piv.phone_generate.timeout", pivDeviceGenerateKeyCmd.Flags().Lookup("timeout"))
}

// runPIVDeviceList lists PIV slot contents on a paired phone.
func runPIVDeviceList(cmd *cobra.Command, args []string) error {
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

	fmt.Fprintf(cmd.OutOrStdout(), "Listing PIV slots on device \"%s\"...\n\n", device.Name)

	// Connect to phone
	phoneBackend, err := connectToPhone(device, timeout, logger)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrPIVDeviceListSlotsFailed, err)
	}
	defer phoneBackend.Close()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	fmt.Fprintln(cmd.OutOrStdout(), "Connecting to phone...")
	if err := phoneBackend.Connect(ctx); err != nil {
		return fmt.Errorf("%w: %v", ErrPIVDeviceListSlotsFailed, err)
	}

	// Request PIV slot listing
	req := phone.NewRequest(phone.MethodLocalPIVListSlots, &phone.LocalPIVListSlotsParams{})
	resp, err := phoneBackend.SendRequest(ctx, req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrPIVDeviceListSlotsFailed, err)
	}
	if resp.Error != nil {
		return fmt.Errorf("%w: [%d] %s", ErrPIVDeviceListSlotsFailed, resp.Error.Code, resp.Error.Message)
	}

	result, err := phone.DecodeResult[phone.LocalPIVListSlotsResult](resp)
	if err != nil {
		return fmt.Errorf("%w: failed to decode result: %v", ErrPIVDeviceListSlotsFailed, err)
	}

	if len(result.Slots) == 0 {
		fmt.Fprintln(cmd.OutOrStdout(), "No PIV slots configured on phone.")
		return nil
	}

	fmt.Fprintf(cmd.OutOrStdout(), "Phone PIV Slots (%d):\n\n", len(result.Slots))
	fmt.Fprintf(cmd.OutOrStdout(), "  %-6s %-24s %-12s %-5s %-5s %s\n",
		"SLOT", "LABEL", "ALGORITHM", "KEY", "CERT", "SUBJECT")
	fmt.Fprintf(cmd.OutOrStdout(), "  %s\n", strings.Repeat("-", 80))

	for _, slot := range result.Slots {
		keyStr := "no"
		if slot.HasKey {
			keyStr = "yes"
		}
		certStr := "no"
		if slot.HasCertificate {
			certStr = "yes"
		}
		subject := slot.CertSubject
		if subject == "" {
			subject = "-"
		}

		fmt.Fprintf(cmd.OutOrStdout(), "  %-6s %-24s %-12s %-5s %-5s %s\n",
			slot.Slot,
			truncateSlotLabel(slot.Label),
			slot.Algorithm,
			keyStr,
			certStr,
			subject,
		)
	}

	fmt.Fprintln(cmd.OutOrStdout())
	return nil
}

// runPIVDevicePushCert pushes a certificate to a PIV slot on a phone.
func runPIVDevicePushCert(cmd *cobra.Command, args []string) error {
	slotStr := args[0]
	certFile := args[1]
	deviceName, _ := cmd.Flags().GetString("device")
	timeout, _ := cmd.Flags().GetDuration("timeout")
	logger := slog.Default()

	// Validate slot
	slot, err := validatePIVSlot(slotStr)
	if err != nil {
		return err
	}

	// Read and parse certificate
	certData, err := os.ReadFile(certFile)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrPIVCertificateReadFailed, err)
	}

	cert, _, err := parseCertificateAuto(certData)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrPIVCertificateParseFailed, err)
	}

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

	slotName := pivcert.SlotName(slot)
	fmt.Fprintf(cmd.OutOrStdout(), "Pushing certificate to slot %s (%s) on device \"%s\"...\n\n",
		slot, slotName, device.Name)

	// Connect to phone
	phoneBackend, err := connectToPhone(device, timeout, logger)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrPIVDevicePushCertFailed, err)
	}
	defer phoneBackend.Close()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	fmt.Fprintln(cmd.OutOrStdout(), "Connecting to phone...")
	if err := phoneBackend.Connect(ctx); err != nil {
		return fmt.Errorf("%w: %v", ErrPIVDevicePushCertFailed, err)
	}

	// Send certificate to phone
	fmt.Fprintln(cmd.OutOrStdout(), "Sending certificate...")
	req := phone.NewRequest(phone.MethodLocalPIVImportCert, &phone.LocalPIVImportCertParams{
		Slot:           string(slot),
		CertificateDER: cert.Raw,
	})

	resp, err := phoneBackend.SendRequest(ctx, req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrPIVDevicePushCertFailed, err)
	}
	if resp.Error != nil {
		return fmt.Errorf("%w: [%d] %s", ErrPIVDevicePushCertFailed, resp.Error.Code, resp.Error.Message)
	}

	result, err := phone.DecodeResult[phone.LocalPIVImportCertResult](resp)
	if err != nil {
		return fmt.Errorf("%w: failed to decode result: %v", ErrPIVDevicePushCertFailed, err)
	}

	if result.Success {
		fmt.Fprintf(cmd.OutOrStdout(), "  Subject: %s\n", cert.Subject.CommonName)
		fmt.Fprintf(cmd.OutOrStdout(), "  Expires: %s\n", cert.NotAfter.Format(time.RFC3339))
	}

	fmt.Fprintln(cmd.OutOrStdout())
	fmt.Fprintln(cmd.OutOrStdout(), "Certificate pushed successfully.")

	return nil
}

// runPIVDevicePullCert pulls a certificate from a PIV slot on a phone.
func runPIVDevicePullCert(cmd *cobra.Command, args []string) error {
	slotStr := args[0]
	deviceName, _ := cmd.Flags().GetString("device")
	timeout, _ := cmd.Flags().GetDuration("timeout")
	outputPath, _ := cmd.Flags().GetString("output")
	logger := slog.Default()

	// Validate slot
	slot, err := validatePIVSlot(slotStr)
	if err != nil {
		return err
	}

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

	slotName := pivcert.SlotName(slot)
	fmt.Fprintf(cmd.OutOrStdout(), "Pulling certificate from slot %s (%s) on device \"%s\"...\n\n",
		slot, slotName, device.Name)

	// Connect to phone
	phoneBackend, err := connectToPhone(device, timeout, logger)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrPIVDevicePullCertFailed, err)
	}
	defer phoneBackend.Close()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	fmt.Fprintln(cmd.OutOrStdout(), "Connecting to phone...")
	if err := phoneBackend.Connect(ctx); err != nil {
		return fmt.Errorf("%w: %v", ErrPIVDevicePullCertFailed, err)
	}

	// Request certificate from phone
	fmt.Fprintln(cmd.OutOrStdout(), "Retrieving certificate...")
	req := phone.NewRequest(phone.MethodLocalPIVGetCert, &phone.LocalPIVGetCertParams{
		Slot: string(slot),
	})

	resp, err := phoneBackend.SendRequest(ctx, req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrPIVDevicePullCertFailed, err)
	}
	if resp.Error != nil {
		return fmt.Errorf("%w: [%d] %s", ErrPIVDevicePullCertFailed, resp.Error.Code, resp.Error.Message)
	}

	result, err := phone.DecodeResult[phone.LocalPIVGetCertResult](resp)
	if err != nil {
		return fmt.Errorf("%w: failed to decode result: %v", ErrPIVDevicePullCertFailed, err)
	}

	if len(result.CertificateDER) == 0 {
		return fmt.Errorf("%w: no certificate in slot %s", ErrPIVCertificateNotFound, slot)
	}

	// Parse certificate to display info
	cert, parseErr := x509.ParseCertificate(result.CertificateDER)
	if parseErr != nil {
		return fmt.Errorf("%w: %v", ErrPIVDevicePullCertFailed, parseErr)
	}

	// Encode as PEM
	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})

	if outputPath != "" {
		if writeErr := os.WriteFile(outputPath, pemData, 0600); writeErr != nil {
			return fmt.Errorf("%w: %v", ErrPIVDevicePullCertFailed, writeErr)
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Certificate saved to: %s\n", outputPath)
	} else {
		fmt.Fprintln(cmd.OutOrStdout(), string(pemData))
	}

	fmt.Fprintf(cmd.OutOrStdout(), "  Subject: %s\n", cert.Subject.CommonName)
	fmt.Fprintf(cmd.OutOrStdout(), "  Issuer:  %s\n", cert.Issuer.CommonName)
	fmt.Fprintf(cmd.OutOrStdout(), "  Expires: %s\n", cert.NotAfter.Format(time.RFC3339))

	return nil
}

// runPIVDeviceGenerateKey generates a key in a PIV slot on a phone.
func runPIVDeviceGenerateKey(cmd *cobra.Command, args []string) error {
	slotStr := args[0]
	deviceName, _ := cmd.Flags().GetString("device")
	timeout, _ := cmd.Flags().GetDuration("timeout")
	algorithm, _ := cmd.Flags().GetString("algorithm")
	logger := slog.Default()

	// Validate slot
	slot, err := validatePIVSlot(slotStr)
	if err != nil {
		return err
	}

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

	slotName := pivcert.SlotName(slot)
	fmt.Fprintf(cmd.OutOrStdout(), "Generating key in slot %s (%s) on device \"%s\"...\n\n",
		slot, slotName, device.Name)

	// Connect to phone
	phoneBackend, err := connectToPhone(device, timeout, logger)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrPIVDeviceGenerateKeyFailed, err)
	}
	defer phoneBackend.Close()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	fmt.Fprintln(cmd.OutOrStdout(), "Connecting to phone...")
	if err := phoneBackend.Connect(ctx); err != nil {
		return fmt.Errorf("%w: %v", ErrPIVDeviceGenerateKeyFailed, err)
	}

	// Request key generation on phone
	fmt.Fprintf(cmd.OutOrStdout(), "Generating %s key (check phone for biometric prompt)...\n", algorithm)
	req := phone.NewRequest(phone.MethodLocalPIVGenerateKey, &phone.LocalPIVGenerateKeyParams{
		Slot:      string(slot),
		Algorithm: algorithm,
	})

	resp, err := phoneBackend.SendRequest(ctx, req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrPIVDeviceGenerateKeyFailed, err)
	}
	if resp.Error != nil {
		return fmt.Errorf("%w: [%d] %s", ErrPIVDeviceGenerateKeyFailed, resp.Error.Code, resp.Error.Message)
	}

	result, err := phone.DecodeResult[phone.LocalPIVGenerateKeyResult](resp)
	if err != nil {
		return fmt.Errorf("%w: failed to decode result: %v", ErrPIVDeviceGenerateKeyFailed, err)
	}

	fmt.Fprintf(cmd.OutOrStdout(), "  Slot:      %s (%s)\n", result.Slot, slotName)
	fmt.Fprintf(cmd.OutOrStdout(), "  Algorithm: %s\n", result.Algorithm)
	if len(result.PublicKeyDER) > 0 {
		fmt.Fprintf(cmd.OutOrStdout(), "  Public Key: %d bytes (DER)\n", len(result.PublicKeyDER))
	}

	fmt.Fprintln(cmd.OutOrStdout())
	fmt.Fprintln(cmd.OutOrStdout(), "Key generated successfully.")

	return nil
}

// truncateSlotLabel truncates a slot label for table display.
func truncateSlotLabel(label string) string {
	if len(label) > 24 {
		return label[:21] + "..."
	}
	return label
}
