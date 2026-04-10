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
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/jeremyhahn/go-xkms/pkg/attestation/android"
	xkeyAttestation "github.com/jeremyhahn/go-xkms/xkey/pkg/attestation"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/phone"
	xkeyTruststore "github.com/jeremyhahn/go-xkms/xkey/pkg/truststore"
)

// Device attestation errors.
var (
	// ErrAttestDeviceNonceGenFailed indicates nonce generation failed.
	ErrAttestDeviceNonceGenFailed = errors.New("device: failed to generate attestation nonce")

	// ErrAttestDeviceCertParseFailed indicates certificate parsing failed.
	ErrAttestDeviceCertParseFailed = errors.New("device: failed to parse attestation certificate")

	// ErrAttestDeviceVerifyFailed indicates attestation verification failed.
	ErrAttestDeviceVerifyFailed = errors.New("device: device attestation verification failed")
)

// Attestation constants.
const (
	attestationNonceSize        = 32
	deviceConnectTimeoutSeconds = 60
)

// deviceAttestDeviceCmd handles device attestation.
var deviceAttestDeviceCmd = &cobra.Command{
	Use:   "attest-device",
	Short: "Verify phone device attestation",
	Long: `Perform device attestation on a paired phone to verify its security state.

Device attestation cryptographically proves:
  1. The phone has genuine Android hardware (TEE or StrongBox)
  2. The device boot state is verified (not unlocked/rooted)
  3. The device identity has not changed since last attestation

The attestation certificate chain is verified against Google's Hardware
Attestation Root CA to ensure authenticity.

If a boot hash was recorded from a previous attestation, this command
validates that the hash has not changed, which would indicate the device
may have been compromised.

Examples:
  # Attest the default device
  xkey device attest-device

  # Attest a specific device
  xkey device attest-device --device "Pixel 9 Pro Fold"

  # Force re-attestation (ignore grace period)
  xkey device attest-device --force

  # Set a custom grace period for this device
  xkey device attest-device --set-grace-period 30m`,
	RunE: runDeviceAttestDevice,
}

func init() {
	deviceCmd.AddCommand(deviceAttestDeviceCmd)

	// Attestation flags
	deviceAttestDeviceCmd.Flags().String("device", "", "Device name to attest (uses default if not specified)")
	deviceAttestDeviceCmd.Flags().Bool("force", false, "Ignore grace period and re-attest anyway")
	deviceAttestDeviceCmd.Flags().Duration("set-grace-period", 0, "Set the attestation grace period for this device (e.g., 5m, 30m)")

	// Bind flags to viper
	_ = viper.BindPFlag("device.attest.device", deviceAttestDeviceCmd.Flags().Lookup("device"))
	_ = viper.BindPFlag("device.attest.force", deviceAttestDeviceCmd.Flags().Lookup("force"))
	_ = viper.BindPFlag("device.attest.grace_period", deviceAttestDeviceCmd.Flags().Lookup("set-grace-period"))
}

// runDeviceAttestDevice executes the phone device attestation command.
func runDeviceAttestDevice(cmd *cobra.Command, args []string) error {
	logger := slog.Default()

	deviceFilter, _ := cmd.Flags().GetString("device")
	force, _ := cmd.Flags().GetBool("force")
	setGracePeriod, _ := cmd.Flags().GetDuration("set-grace-period")

	// Load phone configuration
	cfg, err := loadDevicesConfig()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			fmt.Println("No paired devices. Use 'xkey device pair' first.")
			return ErrDeviceNotPaired
		}
		return fmt.Errorf("%w: %v", ErrDeviceConfigLoadFailed, err)
	}

	if len(cfg.Devices) == 0 {
		fmt.Println("No paired devices. Use 'xkey device pair' first.")
		return ErrDeviceNotPaired
	}

	// Find the target device
	var device *PairedDevice
	if deviceFilter != "" {
		device = findDeviceByName(cfg, deviceFilter)
		if device == nil {
			return fmt.Errorf("%w: %s", ErrDeviceNotFound, deviceFilter)
		}
	} else if cfg.DefaultDevice != "" {
		device = findDeviceByName(cfg, cfg.DefaultDevice)
		if device == nil {
			return fmt.Errorf("%w: default device %s not found", ErrDeviceNotFound, cfg.DefaultDevice)
		}
	} else if len(cfg.Devices) > 0 {
		device = &cfg.Devices[0]
	}

	if device == nil {
		return ErrDeviceNotFound
	}

	// Check grace period unless force is set
	if !force && !isDeviceAttestationRequired(device, cfg.AttestationPolicy) {
		remaining := timeRemaining(device, cfg.AttestationPolicy)
		timeSinceLastAttestation := time.Since(device.LastDeviceAttestationTime)
		fmt.Printf("Device \"%s\" was attested %s ago.\n", device.Name, formatAttestationDuration(timeSinceLastAttestation))

		gracePeriod := time.Duration(device.AttestationGracePeriod)
		if gracePeriod == 0 && cfg.AttestationPolicy != nil {
			gracePeriod = time.Duration(cfg.AttestationPolicy.DefaultGracePeriod)
		}
		if gracePeriod == 0 {
			gracePeriod = defaultAttestationGracePeriod
		}
		fmt.Printf("Grace period: %s (remaining: %s)\n", gracePeriod, formatAttestationDuration(remaining))
		fmt.Println("\nUse --force to re-attest anyway.")
		return nil
	}

	fmt.Printf("Attesting device \"%s\"...\n", device.Name)

	// Load session keys from pairing
	localPrivateKey, err := base64.StdEncoding.DecodeString(device.LocalNoisePrivateKey)
	if err != nil {
		return fmt.Errorf("failed to decode local noise key: %w", err)
	}

	localKey, err := phone.LoadStaticKey(localPrivateKey)
	if err != nil {
		return fmt.Errorf("failed to load local noise key: %w", err)
	}

	remotePublicKey, err := base64.StdEncoding.DecodeString(device.NoisePublicKey)
	if err != nil {
		return fmt.Errorf("failed to decode remote noise key: %w", err)
	}

	// Create BLE transport
	transport, err := phone.NewBLETransport(&phone.BLETransportConfig{
		ScanTimeout: defaultDeviceScanTimeout,
		Logger:      logger,
	})
	if err != nil {
		if errors.Is(err, phone.ErrBLEUnavailable) {
			return ErrDeviceBLEUnavailable
		}
		return fmt.Errorf("failed to initialize Bluetooth: %w", err)
	}
	defer transport.Close()

	// Connect to the device
	fmt.Println("Connecting...")
	connectTimeout := deviceConnectTimeoutSeconds * time.Second
	connectCtx, connectCancel := context.WithTimeout(context.Background(), connectTimeout)
	defer connectCancel()

	if err := transport.Connect(connectCtx, device.Address); err != nil {
		return fmt.Errorf("connection failed: %w", err)
	}
	defer transport.Disconnect()

	// Create Noise session with existing keys
	session, err := phone.NewNoiseSession(&phone.NoiseSessionConfig{
		LocalStaticKey:       localKey,
		ExpectedRemoteStatic: remotePublicKey,
		IsInitiator:          true,
	})
	if err != nil {
		return fmt.Errorf("failed to create noise session: %w", err)
	}

	// Perform Noise handshake
	fmt.Println("Establishing secure channel...")
	handshakeCfg := &phone.HandshakeConfig{
		Transport:           transport,
		Session:             session,
		Logger:              logger,
		StripEnvelopeHeader: false,
		EnvelopeHeaderSize:  0,
	}
	if err := phone.PerformHandshake(connectCtx, handshakeCfg); err != nil {
		return fmt.Errorf("handshake failed: %w", err)
	}

	// Generate attestation nonce
	nonce := make([]byte, attestationNonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("%w: %v", ErrAttestDeviceNonceGenFailed, err)
	}

	// Send local.attestDevice request
	fmt.Println("Requesting device attestation...")
	attestReq := phone.NewRequest(phone.MethodLocalAttestDevice, &phone.LocalAttestDeviceParams{
		Nonce: nonce,
	})

	attestPlaintext, err := phone.EncodeRequest(attestReq)
	if err != nil {
		return fmt.Errorf("failed to encode attestation request: %w", err)
	}

	attestCiphertext, err := session.Encrypt(attestPlaintext)
	if err != nil {
		return fmt.Errorf("failed to encrypt attestation request: %w", err)
	}

	attestResponseCiphertext, err := transport.SendAndReceive(connectCtx, attestCiphertext)
	if err != nil {
		return fmt.Errorf("attestation request failed: %w", err)
	}

	attestResponsePlaintext, err := session.Decrypt(attestResponseCiphertext)
	if err != nil {
		return fmt.Errorf("failed to decrypt attestation response: %w", err)
	}

	attestResp, err := phone.DecodeResponse(attestResponsePlaintext)
	if err != nil {
		return fmt.Errorf("failed to decode attestation response: %w", err)
	}

	if attestResp.Error != nil {
		return phone.MapRPCError(attestResp.Error)
	}

	attestResult, err := phone.DecodeResult[phone.LocalAttestDeviceResult](attestResp)
	if err != nil {
		return fmt.Errorf("failed to decode attestation result: %w", err)
	}

	// Parse certificate chain
	certChain := make([]*x509.Certificate, 0, len(attestResult.CertificateChain))
	for i, certDER := range attestResult.CertificateChain {
		cert, err := x509.ParseCertificate(certDER)
		if err != nil {
			return fmt.Errorf("%w: certificate %d: %v", ErrAttestDeviceCertParseFailed, i, err)
		}
		certChain = append(certChain, cert)
	}

	if len(certChain) == 0 {
		return fmt.Errorf("%w: empty certificate chain", ErrAttestDeviceVerifyFailed)
	}

	// Build trust pool using the auto-selecting attestation verifier
	fmt.Println("Verifying attestation chain...")

	xkeyStore, xkeyErr := openTrustStore()
	if xkeyErr != nil {
		return fmt.Errorf("failed to open trust store: %w", xkeyErr)
	}
	defer func() { _ = xkeyStore.Close() }()

	verifier, verifierErr := xkeyAttestation.NewVerifier(xkeyStore, xkeyTruststore.LoadEmbeddedRoots)
	if verifierErr != nil {
		return fmt.Errorf("failed to create attestation verifier: %w", verifierErr)
	}

	rootPool, poolErr := verifier.BuildTrustPool(xkeyTruststore.PurposeAndroidHardware)
	if poolErr != nil {
		return fmt.Errorf("failed to build trust pool: %w", poolErr)
	}

	// Verify attestation using the Android extension parser
	verifyOpts := &android.VerifyOptions{
		TrustedRoots:     rootPool,
		ExpectedNonce:    nonce,
		MinSecurityLevel: android.SecurityLevelTrustedEnvironment, // TEE minimum
		VerifyBootState:  true,
	}

	keyDesc, err := android.VerifyKeyAttestation(certChain, verifyOpts)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrAttestDeviceVerifyFailed, err)
	}

	// Extract boot hash from RootOfTrust
	var bootHashHex string
	var bootVerified bool
	if keyDesc.TeeEnforced.RootOfTrust != nil {
		rot := keyDesc.TeeEnforced.RootOfTrust
		bootHashHex = hex.EncodeToString(rot.VerifiedBootHash)
		bootVerified = rot.VerifiedBootState == android.VerifiedBootVerified

		// Validate boot hash hasn't changed if we have a previous value
		if err := validateBootHashMatch(device, bootHashHex); err != nil {
			fmt.Println()
			fmt.Println("WARNING: Device boot hash has changed!")
			fmt.Printf("  Previous: %s\n", truncateBootHash(device.DeviceBootHashHex))
			fmt.Printf("  Current:  %s\n", truncateBootHash(bootHashHex))
			fmt.Println()
			fmt.Println("This may indicate:")
			fmt.Println("  - Device was updated (OS/firmware)")
			fmt.Println("  - Device was factory reset")
			fmt.Println("  - Device may be compromised")
			fmt.Println()
			return err
		}
	}

	// Determine security level string
	securityLevel := keyDesc.AttestationSecurityLevel.String()

	// Validate security level meets policy requirements
	if cfg.AttestationPolicy != nil {
		if err := validateSecurityLevel(securityLevel, cfg.AttestationPolicy); err != nil {
			return err
		}
	}

	// Calculate device fingerprint from root cert
	var deviceFingerprint string
	if len(attestResult.CertificateChain) > 0 {
		rootIdx := len(attestResult.CertificateChain) - 1
		deviceFingerprint = calculateDeviceFingerprint(attestResult.CertificateChain[rootIdx])
	}

	// Record attestation result
	attestationResult := &DeviceAttestationResult{
		AttestationTime:   time.Now().UTC(),
		SecurityLevel:     securityLevel,
		BootStateVerified: bootVerified,
		BootHashHex:       bootHashHex,
		DeviceFingerprint: deviceFingerprint,
	}
	recordDeviceAttestation(device, attestationResult)

	// Update grace period if specified
	if setGracePeriod > 0 {
		device.AttestationGracePeriod = Duration(setGracePeriod)
	}

	// Find and update the device in the config
	for i := range cfg.Devices {
		if cfg.Devices[i].Address == device.Address {
			cfg.Devices[i] = *device
			break
		}
	}

	// Save updated configuration
	if err := saveDevicesConfig(cfg); err != nil {
		return fmt.Errorf("%w: %v", ErrDeviceConfigSaveFailed, err)
	}

	// Display results
	fmt.Println()
	fmt.Printf("Device \"%s\" attestation VERIFIED\n", device.Name)
	fmt.Println("============================================================")
	fmt.Printf("  Security Level:   %s\n", securityLevel)
	fmt.Printf("  Boot Verified:    %v\n", bootVerified)
	if bootHashHex != "" {
		fmt.Printf("  Boot Hash:        %s\n", truncateBootHash(bootHashHex))
	}
	fmt.Printf("  Attested At:      %s\n", device.LastDeviceAttestationTime.Format(time.RFC3339))

	gracePeriod := time.Duration(device.AttestationGracePeriod)
	if gracePeriod == 0 {
		gracePeriod = defaultAttestationGracePeriod
	}
	fmt.Printf("  Grace Period:     %s\n", gracePeriod)

	return nil
}

// truncateBootHash truncates a hex hash for display, showing first and last parts.
func truncateBootHash(hash string) string {
	if len(hash) <= 20 {
		return hash
	}
	return hash[:8] + "..." + hash[len(hash)-8:]
}
