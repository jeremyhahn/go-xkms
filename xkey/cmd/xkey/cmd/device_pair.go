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
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/phone"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// devicePairCmd handles pairing with a new phone device.
var devicePairCmd = &cobra.Command{
	Use:   "pair",
	Short: "Pair with a phone key backend",
	Long: `Scan for and pair with a xKey-enabled Android phone.

This command performs the following steps:
  1. Enables the Bluetooth adapter
  2. Scans for devices advertising the xKey service
  3. Displays found devices and lets you select one
  4. Initiates BLE pairing at the OS level
  5. Performs Noise protocol handshake for app-layer key exchange
  6. Verifies device security through hardware attestation
  7. Saves pairing information for future connections

The pairing establishes a secure channel using the Noise XX protocol pattern,
which provides mutual authentication and forward secrecy.

Examples:
  # Scan and interactively select a device to pair
  xkey device pair

  # Pair with a specific device by name
  xkey device pair --device "John's Pixel"

  # Pair with extended scan timeout
  xkey device pair --timeout 60s

  # Force re-pairing if already paired
  xkey device pair --device "John's Pixel" --force`,
	RunE: runDevicePair,
}

func init() {
	deviceCmd.AddCommand(devicePairCmd)

	// Pairing flags
	devicePairCmd.Flags().String("device", "", "Specific device name or address to pair")
	devicePairCmd.Flags().Duration("timeout", defaultDeviceScanTimeout, "Scan timeout duration")
	devicePairCmd.Flags().Bool("force", false, "Force re-pairing even if already paired")

	// Bind flags to viper
	_ = viper.BindPFlag("device.pair.device", devicePairCmd.Flags().Lookup("device"))
	_ = viper.BindPFlag("device.pair.timeout", devicePairCmd.Flags().Lookup("timeout"))
	_ = viper.BindPFlag("device.pair.force", devicePairCmd.Flags().Lookup("force"))
}

// runDevicePair executes the phone pairing command.
func runDevicePair(cmd *cobra.Command, args []string) error {
	logger := slog.Default()

	deviceFilter, _ := cmd.Flags().GetString("device")
	scanTimeout, _ := cmd.Flags().GetDuration("timeout")
	force, _ := cmd.Flags().GetBool("force")

	// Load existing configuration
	cfg, err := loadDevicesConfig()
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("%w: %v", ErrDeviceConfigLoadFailed, err)
	}
	if cfg == nil {
		cfg = &DevicesConfig{
			Devices: []PairedDevice{},
		}
	}

	// Create BLE transport for scanning
	transport, err := phone.NewBLETransport(&phone.BLETransportConfig{
		ScanTimeout: scanTimeout,
		Logger:      logger,
	})
	if err != nil {
		if errors.Is(err, phone.ErrBLEUnavailable) {
			return ErrDeviceBLEUnavailable
		}
		return fmt.Errorf("failed to initialize Bluetooth: %w", err)
	}
	defer transport.Close()

	ctx, cancel := context.WithTimeout(context.Background(), scanTimeout)
	defer cancel()

	var selectedDevice *phone.ScanResult

	// If a specific device was requested, scan all and filter
	if deviceFilter != "" {
		fmt.Printf("Searching for device \"%s\"...\n", deviceFilter)
		devices, err := transport.ScanAll(ctx)
		if err != nil {
			return fmt.Errorf("scan failed: %w", err)
		}

		for i := range devices {
			if devices[i].LocalName == deviceFilter || devices[i].Address == deviceFilter {
				selectedDevice = &devices[i]
				break
			}
		}
		if selectedDevice == nil {
			fmt.Printf("Device \"%s\" not found.\n", deviceFilter)
			if len(devices) > 0 {
				fmt.Println("Available xKey devices:")
				for _, d := range devices {
					fmt.Printf("  - %s (%s)\n", d.DisplayName(), d.Address)
				}
			}
			return ErrDeviceNotFound
		}
	} else {
		// Auto-discover: scan until first xKey device is found
		fmt.Println("Scanning for xKey devices...")
		logger.Debug("starting scan...")
		devices, err := transport.Scan(ctx) // Stops on first device found
		logger.Debug("scan returned", "deviceCount", len(devices), "error", err)
		if err != nil {
			return fmt.Errorf("scan failed: %w", err)
		}

		if len(devices) == 0 {
			fmt.Println("No xKey devices found.")
			fmt.Println("\nMake sure:")
			fmt.Println("  1. The xKey app is running on your phone")
			fmt.Println("  2. You've tapped 'Start xKey' to begin advertising")
			fmt.Println("  3. Bluetooth is enabled on both devices")
			fmt.Println("\nUse 'xkey device list' to see all nearby xKey devices.")
			return ErrDeviceNoDevicesFound
		}

		if len(devices) == 1 {
			// Auto-select the only device
			selectedDevice = &devices[0]
			fmt.Printf("Found: %s (%s)\n", selectedDevice.DisplayName(), selectedDevice.Address)
		} else {
			// Multiple devices found - prompt for selection
			fmt.Printf("Found %d xKey devices:\n\n", len(devices))
			for i, d := range devices {
				fmt.Printf("  [%d] %s (%s)\n", i+1, d.DisplayName(), d.Address)
			}
			fmt.Println()
			fmt.Print("Select device [1]: ")

			var selection int
			var input string
			if _, err := fmt.Scanln(&input); err != nil || input == "" {
				selection = 1 // Default to first device
			} else {
				if _, err := fmt.Sscanf(input, "%d", &selection); err != nil || selection < 1 || selection > len(devices) {
					return fmt.Errorf("invalid selection: %s", input)
				}
			}
			selectedDevice = &devices[selection-1]
			fmt.Printf("\nSelected: %s (%s)\n", selectedDevice.DisplayName(), selectedDevice.Address)
		}
	}

	// Check if already paired
	existingDevice := findDeviceByAddress(cfg, selectedDevice.Address)
	if existingDevice != nil && !force {
		fmt.Printf("Device \"%s\" is already paired.\n", existingDevice.Name)
		fmt.Print("Re-pair? [y/N]: ")
		var response string
		if _, err := fmt.Scanln(&response); err != nil || (response != "y" && response != "Y") {
			return ErrDeviceAlreadyPaired
		}
	}

	// Determine device name for storage and display
	deviceName := selectedDevice.DisplayName()

	fmt.Printf("\nPairing with \"%s\" (%s)...\n", deviceName, selectedDevice.Address)

	// Generate local Noise static key
	localKey, err := phone.GenerateStaticKey()
	if err != nil {
		return fmt.Errorf("failed to generate local key: %w", err)
	}

	// Create Noise session for handshake
	session, err := phone.NewNoiseSession(&phone.NoiseSessionConfig{
		LocalStaticKey: localKey,
		IsInitiator:    true,
	})
	if err != nil {
		return fmt.Errorf("failed to create noise session: %w", err)
	}

	// Connect to the device - use longer timeout to allow for user PIN confirmation
	// BLE pairing may require user to confirm a PIN on their phone
	pairingTimeout := 60 * time.Second
	connectCtx, connectCancel := context.WithTimeout(context.Background(), pairingTimeout)
	defer connectCancel()

	fmt.Println("Connecting...")
	fmt.Println("(Check your phone for a pairing confirmation prompt)")
	if err := transport.Connect(connectCtx, selectedDevice.Address); err != nil {
		return fmt.Errorf("connection failed: %w", err)
	}

	// Perform Noise XX handshake using the centralized implementation
	fmt.Println("Performing secure key exchange...")
	handshakeCfg := &phone.HandshakeConfig{
		Transport:           transport,
		Session:             session,
		Logger:              logger,
		StripEnvelopeHeader: false, // Android sends raw Noise messages, no envelope
		EnvelopeHeaderSize:  0,
	}
	if err := phone.PerformHandshake(connectCtx, handshakeCfg); err != nil {
		transport.Disconnect()
		return fmt.Errorf("key exchange failed: %w", err)
	}

	// Send pairing confirmation request to phone
	fmt.Println("Waiting for confirmation on phone...")
	pairingReq := phone.NewRequest(phone.MethodPairingConfirm, &phone.PairingConfirmParams{
		DeviceName:   hostname(),
		PublicKeyHex: hex.EncodeToString(session.LocalStaticPublicKey()),
	})
	pairingPlaintext, err := phone.EncodeRequest(pairingReq)
	if err != nil {
		transport.Disconnect()
		return fmt.Errorf("failed to encode pairing request: %w", err)
	}
	pairingCiphertext, err := session.Encrypt(pairingPlaintext)
	if err != nil {
		transport.Disconnect()
		return fmt.Errorf("failed to encrypt pairing request: %w", err)
	}
	pairingResponseCiphertext, err := transport.SendAndReceive(connectCtx, pairingCiphertext)
	if err != nil {
		transport.Disconnect()
		return fmt.Errorf("pairing confirmation failed: %w", err)
	}
	pairingResponsePlaintext, err := session.Decrypt(pairingResponseCiphertext)
	if err != nil {
		transport.Disconnect()
		return fmt.Errorf("failed to decrypt pairing response: %w", err)
	}
	pairingResp, err := phone.DecodeResponse(pairingResponsePlaintext)
	if err != nil {
		transport.Disconnect()
		return fmt.Errorf("failed to decode pairing response: %w", err)
	}
	if pairingResp.Error != nil {
		transport.Disconnect()
		return phone.MapRPCError(pairingResp.Error)
	}
	pairingResult, err := phone.DecodeResult[phone.PairingConfirmResult](pairingResp)
	if err != nil {
		transport.Disconnect()
		return fmt.Errorf("failed to decode pairing result: %w", err)
	}
	if !pairingResult.Confirmed {
		transport.Disconnect()
		return phone.ErrPairingRejected
	}
	fmt.Printf("Phone confirmed pairing as \"%s\"\n", pairingResult.DeviceName)

	// Get the phone's public key
	remotePublicKey := session.RemoteStaticPublicKey()
	if len(remotePublicKey) == 0 {
		transport.Disconnect()
		return fmt.Errorf("failed to obtain phone's public key")
	}

	// Perform device attestation to verify device security
	attestResult := performPairingAttestation(connectCtx, transport, session, logger)

	// Disconnect after pairing (will reconnect when needed)
	transport.Disconnect()

	// Create or update device record
	pairedDevice := PairedDevice{
		Name:                 deviceName,
		Address:              selectedDevice.Address,
		NoisePublicKey:       base64.StdEncoding.EncodeToString(remotePublicKey),
		LocalNoisePrivateKey: base64.StdEncoding.EncodeToString(localKey.Private),
		PairedAt:             time.Now().UTC(),
	}

	// Apply attestation results if available
	if attestResult != nil {
		recordDeviceAttestation(&pairedDevice, attestResult)
	}

	// Update or add to configuration.
	// When force re-pairing, remove all old entries for the same device name
	// since Android RPA rotation means the address changes across reinstalls.
	if existingDevice != nil {
		// Update existing device matched by address
		for i := range cfg.Devices {
			if cfg.Devices[i].Address == selectedDevice.Address {
				cfg.Devices[i] = pairedDevice
				break
			}
		}
	} else if force {
		// Force mode: remove stale entries by name, then add fresh entry.
		// This handles the case where the phone's BLE address changed
		// (Android RPA rotation or app reinstall) but the name is the same.
		filtered := make([]PairedDevice, 0, len(cfg.Devices))
		for _, d := range cfg.Devices {
			if d.Name != deviceName {
				filtered = append(filtered, d)
			}
		}
		cfg.Devices = append(filtered, pairedDevice)
	} else {
		// Add new device
		cfg.Devices = append(cfg.Devices, pairedDevice)
	}

	// Set as default if first device
	if cfg.DefaultDevice == "" {
		cfg.DefaultDevice = deviceName
	}

	// Save configuration
	if err := saveDevicesConfig(cfg); err != nil {
		return fmt.Errorf("%w: %v", ErrDeviceConfigSaveFailed, err)
	}

	fmt.Println()
	fmt.Printf("Successfully paired with \"%s\"!\n", deviceName)
	fmt.Printf("Phone public key: %s...\n", truncateKey(pairedDevice.NoisePublicKey))
	fmt.Println()
	fmt.Println("The phone is now available as a key backend.")
	fmt.Println("Use '--backend phone' with xKey commands to use phone-backed keys.")

	return nil
}

// performPairingAttestation performs device attestation during pairing.
// Returns nil if attestation fails (non-fatal during pairing).
func performPairingAttestation(
	ctx context.Context,
	transport phone.Transport,
	session *phone.NoiseSession,
	logger *slog.Logger,
) *DeviceAttestationResult {
	fmt.Println("Verifying device security...")

	// Generate 32-byte random nonce
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		logger.Warn("device attestation skipped: nonce generation failed", "error", err)
		fmt.Println("  Warning: Device attestation skipped (nonce generation failed)")
		return nil
	}

	// Create and send local.attestDevice request
	attestReq := phone.NewRequest(phone.MethodLocalAttestDevice, &phone.LocalAttestDeviceParams{
		Nonce: nonce,
	})

	attestPlaintext, err := phone.EncodeRequest(attestReq)
	if err != nil {
		logger.Warn("device attestation skipped: encode failed", "error", err)
		fmt.Println("  Warning: Device attestation skipped (request encoding failed)")
		return nil
	}

	attestCiphertext, err := session.Encrypt(attestPlaintext)
	if err != nil {
		logger.Warn("device attestation skipped: encrypt failed", "error", err)
		fmt.Println("  Warning: Device attestation skipped (encryption failed)")
		return nil
	}

	attestResponseCiphertext, err := transport.SendAndReceive(ctx, attestCiphertext)
	if err != nil {
		logger.Warn("device attestation skipped: transport error", "error", err)
		fmt.Println("  Warning: Device attestation skipped (communication error)")
		return nil
	}

	attestResponsePlaintext, err := session.Decrypt(attestResponseCiphertext)
	if err != nil {
		logger.Warn("device attestation skipped: decrypt failed", "error", err)
		fmt.Println("  Warning: Device attestation skipped (decryption failed)")
		return nil
	}

	attestResp, err := phone.DecodeResponse(attestResponsePlaintext)
	if err != nil {
		logger.Warn("device attestation skipped: decode failed", "error", err)
		fmt.Println("  Warning: Device attestation skipped (response decode failed)")
		return nil
	}

	if attestResp.Error != nil {
		logger.Warn("device attestation skipped: RPC error", "code", attestResp.Error.Code, "message", attestResp.Error.Message)
		fmt.Printf("  Warning: Device attestation skipped (%s)\n", attestResp.Error.Message)
		return nil
	}

	attestResult, err := phone.DecodeResult[phone.LocalAttestDeviceResult](attestResp)
	if err != nil {
		logger.Warn("device attestation skipped: result decode failed", "error", err)
		fmt.Println("  Warning: Device attestation skipped (result decode failed)")
		return nil
	}

	// Extract attestation information
	securityLevel := attestResult.SecurityLevel
	bootState := attestResult.BootState
	verifiedBootHash := attestResult.VerifiedBootHash

	// Calculate device fingerprint from root certificate
	var deviceFingerprint string
	if len(attestResult.CertificateChain) > 0 {
		rootIdx := len(attestResult.CertificateChain) - 1
		deviceFingerprint = calculateDeviceFingerprint(attestResult.CertificateChain[rootIdx])
	}

	// Display attestation results
	fmt.Printf("  Boot State:     %s\n", formatBootState(bootState))
	fmt.Printf("  Security Level: %s\n", securityLevel)
	if len(verifiedBootHash) > 0 {
		bootHashHex := hex.EncodeToString(verifiedBootHash)
		fmt.Printf("  Boot Hash:      %s\n", truncateBootHash(bootHashHex))
	}

	// Return attestation result for storage
	return &DeviceAttestationResult{
		AttestationTime:   time.Now().UTC(),
		SecurityLevel:     securityLevel,
		BootStateVerified: bootState == 0, // 0 = VERIFIED
		BootHashHex:       hex.EncodeToString(verifiedBootHash),
		DeviceFingerprint: deviceFingerprint,
	}
}

// hostname returns the local hostname, or "unknown" if it cannot be determined.
func hostname() string {
	name, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return name
}
