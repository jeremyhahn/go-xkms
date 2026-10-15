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
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/jeremyhahn/go-xkms/sdk/go/bootstrap"
	"github.com/jeremyhahn/go-xkms/sdk/go/pairingproto"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/attestation"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/pairing"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/phone"
)

// Device attestation errors.
//
// ErrAttestDeviceNonceGenFailed and ErrAttestDeviceCertParseFailed are gone
// with the code that raised them: this command no longer draws its own nonce
// or parses its own chain, both of which now happen once in attestOverSession
// and report through the pairing path's sentinels (#129).
var (
	// ErrAttestDeviceVerifyFailed indicates attestation verification failed.
	ErrAttestDeviceVerifyFailed = errors.New("device: device attestation verification failed")
)

// Attestation constants.
const (
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
	addDeviceBarrierFlags(deviceAttestDeviceCmd)

	// Bind flags to viper
	_ = viper.BindPFlag("device.attest.device", deviceAttestDeviceCmd.Flags().Lookup("device"))
	_ = viper.BindPFlag("device.attest.force", deviceAttestDeviceCmd.Flags().Lookup("force"))
	_ = viper.BindPFlag("device.attest.grace_period", deviceAttestDeviceCmd.Flags().Lookup("set-grace-period"))
}

// runDeviceAttestDevice executes the phone device attestation command.
func runDeviceAttestDevice(cmd *cobra.Command, args []string) (err error) {
	logger := slog.Default()

	deviceFilter, _ := cmd.Flags().GetString("device")
	force, _ := cmd.Flags().GetBool("force")
	setGracePeriod, _ := cmd.Flags().GetDuration("set-grace-period")

	// The barrier is opened, if one is initialized, before the devices file:
	// this command reads the local Noise static private key to reconnect
	// and, on success, rewrites the record with a fresh attestation
	// timestamp, migrating a legacy plaintext record to the sealed form when
	// it can. A host with no barrier initialized at all is not refused here
	// (#42 owner ruling) -- see openDeviceBarrier.
	barrier, closeBarrier, err := openDeviceBarrier(cmd)
	if err != nil {
		return err
	}
	defer closeBarrier()

	// Load phone configuration
	cfg, err := loadDevicesConfig()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			fmt.Println("No paired devices. Use 'xkey device pair' first.")
			return ErrDeviceNotPaired
		}
		return &SentinelCauseError{Sentinel: ErrDeviceConfigLoadFailed, Cause: err}
	}

	if len(cfg.Devices) == 0 {
		fmt.Println("No paired devices. Use 'xkey device pair' first.")
		return ErrDeviceNotPaired
	}

	// Find the target device
	var device *PairedDevice
	switch {
	case deviceFilter != "":
		device, err = findDeviceByName(cfg, deviceFilter)
		if err != nil {
			return err
		}
		if device == nil {
			return &DetailError{Err: ErrDeviceNotFound, Detail: fmt.Sprintf(": %s", deviceFilter)}
		}
	case cfg.DefaultDevice != "":
		device, err = findDeviceByName(cfg, cfg.DefaultDevice)
		if err != nil {
			return err
		}
		if device == nil {
			return &DetailError{Err: ErrDeviceNotFound, Detail: fmt.Sprintf(": default device %s not found", cfg.DefaultDevice)}
		}
	case len(cfg.Devices) > 0:
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

	// Unseal the local Noise private key (#42). barrier is nil here only
	// because openDeviceBarrier found none initialized (any other
	// resolution failure already returned above); a nil barrier means this
	// record is expected to be the legacy plaintext form, logged once per
	// operation. pairing.UnsealLocalNoiseKey requires the stored form to
	// match the barrier's presence and returns
	// pairing.ErrNoiseKeyFormMismatch (telling the operator to re-pair)
	// when it does not -- there is no migration between the two forms.
	if barrier == nil && !pairing.IsSealedNoiseKey(device.LocalNoisePrivateKey) {
		logger.Warn(noBarrierConfiguredWarning, "device", device.Name)
	}
	localPrivateKey, err := pairing.UnsealLocalNoiseKey(barrier, device.LocalNoisePrivateKey)
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrAttestDeviceVerifyFailed, Cause: err}
	}
	// Destroyed here, at the unseal, not at the LoadStaticKey below: a
	// decode failure on any other field returns in between, and the raw
	// scalar would be left sitting in protected memory nothing releases.
	defer localPrivateKey.Destroy()

	localKey, err := bootstrap.LoadNoiseStaticKeyFromBuffer(localPrivateKey)
	if err != nil {
		return &WrappedError{Msg: "failed to load local noise key", Err: err}
	}
	// Registered before the transport's own defer, so LIFO releases the
	// protected pages only after the transport that reads them is closed.
	defer localKey.Destroy()

	remotePublicKey, err := base64.StdEncoding.DecodeString(device.NoisePublicKey)
	if err != nil {
		return &WrappedError{Msg: "failed to decode remote noise key", Err: err}
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
		return &WrappedError{Msg: "failed to initialize Bluetooth", Err: err}
	}
	defer func() {
		if closeErr := transport.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()

	// Connect to the device
	fmt.Println("Connecting...")
	connectTimeout := deviceConnectTimeoutSeconds * time.Second
	connectCtx, connectCancel := context.WithTimeout(context.Background(), connectTimeout)
	defer connectCancel()

	if err := transport.Connect(connectCtx, device.Address); err != nil {
		return &WrappedError{Msg: "connection failed", Err: err}
	}
	defer func() {
		if closeErr := transport.Disconnect(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()

	// Create Noise session with existing keys
	session, err := bootstrap.NewNoiseSession(&bootstrap.NoiseSessionConfig{
		LocalStaticKey:       localKey,
		ExpectedRemoteStatic: remotePublicKey,
		IsInitiator:          true,
	})
	if err != nil {
		return &WrappedError{Msg: "failed to create noise session", Err: err}
	}

	// The stored identity, decoded the way every other connecting path decodes
	// it. Fail-closed: a corrupt record yields an error and no bytes, never the
	// "no fingerprint configured" signal, which would silently drop the check.
	expectedFingerprint, fpErr := phone.DecodeDeviceFingerprint(device.DeviceFingerprint)
	if fpErr != nil {
		return &SentinelCauseError{Sentinel: ErrAttestDeviceVerifyFailed, Cause: fpErr}
	}

	// Perform Noise handshake.
	//
	// LocalStaticPublicKey and ExpectedDeviceFingerprint are what make the
	// pre-handshake identity exchange run, and this command used to set
	// neither — so it connected with an EMPTY prologue and no fingerprint
	// comparison, while the reconnect path bound both. That mattered less when
	// this command only refreshed a timestamp; since #129 it can also record
	// the attestation PROTOCOL VERSION, so re-attesting over a session weaker
	// than the one the binding is meant to be revalidated on would let the
	// stronger claim be established from the weaker context. (Codex, #124.)
	//
	// An empty stored fingerprint decodes to nil, which is the legitimate
	// never-attested case: the exchange still runs and the device may answer
	// "unknown". A device that HAS a fingerprint cannot return to that state,
	// and performIdentityExchange refuses if it claims to.
	fmt.Println("Establishing secure channel...")
	handshakeCfg := &pairingproto.HandshakeConfig{
		Transport:                 transport,
		Session:                   session,
		Logger:                    logger,
		StripEnvelopeHeader:       false,
		EnvelopeHeaderSize:        0,
		LocalStaticPublicKey:      session.LocalStaticPublicKey(),
		ExpectedDeviceFingerprint: expectedFingerprint,
	}
	if err := pairingproto.PerformHandshake(connectCtx, handshakeCfg); err != nil {
		return &WrappedError{Msg: "handshake failed", Err: err}
	}

	// The whole attestation exchange, shared with the pairing path (#129).
	//
	// This command used to re-implement the sequence — request, chain
	// verification, boot state, fingerprint, signature — beside the one in
	// device_pair.go. Both of Codex's blocking findings on #124 were instances
	// of the same root cause: two copies of a security decision drift, and the
	// weaker copy is the one that ends up establishing the binding. That is the
	// shape of #95, one command later. There is now one implementation, so
	// "attest-device applies a weaker policy than pairing" is not a state this
	// code can reach.
	//
	// The trust material is loaded the same way too: loadPairingAttestationTrust
	// builds its pool from the same store, verifier and PurposeAndroidHardware
	// this command built inline.
	fmt.Println("Requesting device attestation...")

	trust, trustErr := loadPairingAttestationTrust()
	if trustErr != nil {
		return trustErr
	}

	fmt.Println("Verifying attestation chain...")

	verified, err := attestation.AttestOverSession(
		connectCtx, transport, session, trust, pairingproto.AttestPurposeReattest, logger)
	if err != nil {
		return err
	}

	securityLevel := verified.Result.SecurityLevel
	bootHashHex := verified.Result.BootHashHex
	deviceFingerprint := verified.Result.DeviceFingerprint

	// Validate security level meets policy requirements. This is the one check
	// that is genuinely this command's own: pairing enforces the portfolio
	// minimum, and an operator may set a higher bar for re-attestation.
	if cfg.AttestationPolicy != nil {
		if err := validateSecurityLevel(securityLevel, cfg.AttestationPolicy); err != nil {
			return err
		}
	}

	// Validate boot hash hasn't changed if we have a previous value.
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

	// Fail-closed identity continuity (#93). This command REVALIDATES an
	// existing binding, so a changed attested key is refused here — never
	// silently rewritten — mirroring validateBootHashMatch above. Otherwise a
	// peer holding the paired Noise key plus a separately valid hardware
	// attestation of its own device could turn the operator's revalidation
	// into a rebind onto that device. Legitimate rotation is an explicit
	// re-pair, which establishes a fresh binding on purpose.
	if err := attestation.DeviceBindingFor(*device).ValidateAttestedKeyMatch(deviceFingerprint); err != nil {
		fmt.Println()
		fmt.Println("WARNING: the device's attested key has changed since pairing!")
		fmt.Printf("  Previous: %s\n", truncateDeviceInfoHash(device.DeviceFingerprint))
		fmt.Printf("  Current:  %s\n", truncateDeviceInfoHash(deviceFingerprint))
		fmt.Println()
		fmt.Println("This attestation is NOT applied and the existing binding is unchanged.")
		fmt.Println("If you deliberately rotated the device's key (factory reset, key")
		fmt.Println("regeneration), re-pair with `xkey device pair --force` to bind the")
		fmt.Println("new key. If you did NOT, treat this as suspicious.")
		fmt.Println()
		return err
	}

	recordDeviceAttestation(device, verified.Result)

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
		return &SentinelCauseError{Sentinel: ErrDeviceConfigSaveFailed, Cause: err}
	}

	// Display results
	fmt.Println()
	fmt.Printf("Device \"%s\" attestation VERIFIED\n", device.Name)
	fmt.Println("============================================================")
	fmt.Printf("  Trust Anchor:     %s\n", verified.TrustAnchor)
	fmt.Printf("  Attested Key:     %s\n", truncateDeviceInfoHash(deviceFingerprint))
	fmt.Printf("  Security Level:   %s\n", securityLevel)
	fmt.Printf("  Boot State:       %s\n", verified.BootState)
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
