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
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/attestation"
	xkeyconfig "github.com/jeremyhahn/go-xkms/xkey/pkg/config"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/pairing"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/phone"
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
  xkey device pair --device "John's Pixel" --force

  # Honour a sealed enterprise policy that allows unattestable devices
  echo -n "$SO_PIN" | xkey device pair --so-pin-stdin

` + soPINUsage,
	RunE: runDevicePair,
}

func init() {
	deviceCmd.AddCommand(devicePairCmd)

	// Pairing flags
	devicePairCmd.Flags().String("device", "", "Specific device name or address to pair")
	devicePairCmd.Flags().Duration("timeout", defaultDeviceScanTimeout, "Scan timeout duration")
	devicePairCmd.Flags().Bool("force", false, "Force re-pairing even if already paired")
	addSOPINFlags(devicePairCmd)

	// Bind flags to viper
	_ = viper.BindPFlag("device.pair.device", devicePairCmd.Flags().Lookup("device"))
	_ = viper.BindPFlag("device.pair.timeout", devicePairCmd.Flags().Lookup("timeout"))
	_ = viper.BindPFlag("device.pair.force", devicePairCmd.Flags().Lookup("force"))
}

// pairingTransport is what runDevicePair needs from a transport: discovery,
// a connection to the selected device, and the encrypted channel. The BLE
// transport is the production implementation; a test supplies one backed
// by an in-memory pair so the command can be driven without a phone.
type pairingTransport interface {
	phone.Transport
	Scan(ctx context.Context) ([]phone.ScanResult, error)
	ScanAll(ctx context.Context) ([]phone.ScanResult, error)
	Connect(ctx context.Context, address string) error
	Disconnect() error
	Close() error
}

// pairingSeams are runDevicePair's injection points: how it opens its
// transport, reads and writes the devices file, and loads this machine's
// attestation trust. Production wires the real implementations; a test
// replaces them so the abort/allow/save wiring itself can be exercised, not
// only the helpers it calls.
type pairingSeams struct {
	newTransport func(cfg *phone.BLETransportConfig) (pairingTransport, error)
	loadDevices  func() (*DevicesConfig, error)
	saveDevices  func(cfg *DevicesConfig) error
	loadTrust    func() (*attestation.Trust, error)
}

// newBLEPairingTransport opens the real BLE transport. It returns an
// untyped nil on failure so the interface value is nil, not a typed nil.
func newBLEPairingTransport(cfg *phone.BLETransportConfig) (pairingTransport, error) {
	transport, err := phone.NewBLETransport(cfg)
	if err != nil {
		return nil, err
	}
	return transport, nil
}

// pairSeams is the production wiring. Tests swap it for the duration of a
// test and restore it.
var pairSeams = pairingSeams{
	newTransport: newBLEPairingTransport,
	loadDevices:  loadDevicesConfig,
	saveDevices:  saveDevicesConfig,
	loadTrust:    loadPairingAttestationTrust,
}

// runDevicePair executes the phone pairing command.
func runDevicePair(cmd *cobra.Command, args []string) error {
	logger := slog.Default()

	deviceFilter, _ := cmd.Flags().GetString("device")
	scanTimeout, _ := cmd.Flags().GetDuration("timeout")
	force, _ := cmd.Flags().GetBool("force")

	// Load existing configuration
	cfg, err := pairSeams.loadDevices()
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return &SentinelCauseError{Sentinel: ErrDeviceConfigLoadFailed, Cause: err}
	}
	if cfg == nil {
		cfg = &DevicesConfig{
			Devices: []PairedDevice{},
		}
	}

	// Resolve the enterprise plane before anything is scanned, so an
	// operator who supplied an SO PIN learns about a policy that does not
	// verify now rather than after the phone has confirmed.
	enterprisePolicy, err := resolvePairingPolicy(cmd, GetConfig(), logger)
	if err != nil {
		return err
	}

	// Create BLE transport for scanning
	transport, err := pairSeams.newTransport(&phone.BLETransportConfig{
		ScanTimeout: scanTimeout,
		Logger:      logger,
	})
	if err != nil {
		if errors.Is(err, phone.ErrBLEUnavailable) {
			return ErrDeviceBLEUnavailable
		}
		return &WrappedError{Msg: "failed to initialize Bluetooth", Err: err}
	}
	defer func() { _ = transport.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), scanTimeout)
	defer cancel()

	var selectedDevice *phone.ScanResult

	// If a specific device was requested, scan all and filter
	if deviceFilter != "" {
		fmt.Printf("Searching for device \"%s\"...\n", deviceFilter)
		devices, err := transport.ScanAll(ctx)
		if err != nil {
			return &WrappedError{Msg: "scan failed", Err: err}
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
			return &WrappedError{Msg: "scan failed", Err: err}
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
					return &MessageError{Msg: fmt.Sprintf("invalid selection: %s", input)}
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
		return &WrappedError{Msg: "failed to generate local key", Err: err}
	}
	// The private half is base64ed into the stored device record before this
	// returns, so the protected copy does not outlive the command.
	defer localKey.Destroy()

	// Create Noise session for handshake
	session, err := phone.NewNoiseSession(&phone.NoiseSessionConfig{
		LocalStaticKey: localKey,
		IsInitiator:    true,
	})
	if err != nil {
		return &WrappedError{Msg: "failed to create noise session", Err: err}
	}

	// Connect to the device - use longer timeout to allow for user PIN confirmation
	// BLE pairing may require user to confirm a PIN on their phone
	pairingTimeout := 60 * time.Second
	connectCtx, connectCancel := context.WithTimeout(context.Background(), pairingTimeout)
	defer connectCancel()

	fmt.Println("Connecting...")
	fmt.Println("(Check your phone for a pairing confirmation prompt)")
	if err := transport.Connect(connectCtx, selectedDevice.Address); err != nil {
		return &WrappedError{Msg: "connection failed", Err: err}
	}

	// Perform Noise XX handshake using the centralized implementation.
	// The identity exchange runs on every connection, pairing included: the
	// phone answers an unknown key with "new device" and both sides fall back
	// to an empty prologue, so pairing and reconnecting negotiate the same way.
	fmt.Println("Performing secure key exchange...")
	handshakeCfg := &phone.HandshakeConfig{
		Transport:            transport,
		Session:              session,
		Logger:               logger,
		StripEnvelopeHeader:  false, // Android sends raw Noise messages, no envelope
		EnvelopeHeaderSize:   0,
		LocalStaticPublicKey: session.LocalStaticPublicKey(),
	}
	if err := phone.PerformHandshake(connectCtx, handshakeCfg); err != nil {
		_ = transport.Disconnect()
		return &WrappedError{Msg: "key exchange failed", Err: err}
	}

	// Send pairing confirmation request to phone
	fmt.Println("Waiting for confirmation on phone...")
	pairingReq := phone.NewRequest(phone.MethodPairingConfirm, &phone.PairingConfirmParams{
		DeviceName:   hostname(),
		PublicKeyHex: hex.EncodeToString(session.LocalStaticPublicKey()),
	})
	pairingPlaintext, err := phone.EncodeRequest(pairingReq)
	if err != nil {
		_ = transport.Disconnect()
		return &WrappedError{Msg: "failed to encode pairing request", Err: err}
	}
	pairingCiphertext, err := session.Encrypt(pairingPlaintext)
	if err != nil {
		_ = transport.Disconnect()
		return &WrappedError{Msg: "failed to encrypt pairing request", Err: err}
	}
	pairingResponseCiphertext, err := transport.SendAndReceive(connectCtx, pairingCiphertext)
	if err != nil {
		_ = transport.Disconnect()
		return &WrappedError{Msg: "pairing confirmation failed", Err: err}
	}
	pairingResponsePlaintext, err := session.Decrypt(pairingResponseCiphertext)
	if err != nil {
		_ = transport.Disconnect()
		return &WrappedError{Msg: "failed to decrypt pairing response", Err: err}
	}
	pairingResp, err := phone.DecodeResponse(pairingResponsePlaintext)
	if err != nil {
		_ = transport.Disconnect()
		return &WrappedError{Msg: "failed to decode pairing response", Err: err}
	}
	if pairingResp.Error != nil {
		_ = transport.Disconnect()
		return phone.MapRPCError(pairingResp.Error)
	}
	pairingResult, err := phone.DecodeResult[phone.PairingConfirmResult](pairingResp)
	if err != nil {
		_ = transport.Disconnect()
		return &WrappedError{Msg: "failed to decode pairing result", Err: err}
	}
	if !pairingResult.Confirmed {
		_ = transport.Disconnect()
		return phone.ErrPairingRejected
	}
	fmt.Printf("Phone confirmed pairing as \"%s\"\n", pairingResult.DeviceName)

	// Get the phone's public key
	remotePublicKey := session.RemoteStaticPublicKey()
	if len(remotePublicKey) == 0 {
		_ = transport.Disconnect()
		return &MessageError{Msg: "failed to obtain phone's public key"}
	}

	// Attest the device before anything is written down. Whether an
	// UNATTESTABLE device may still be paired is policy (see
	// allowUnattestablePairing); what is not policy is that no unverified
	// claim is ever written down. The pairing record is what every later
	// connection is judged against, so a record whose attestation half was
	// never checked is worse than no record at all (#95).
	allowUnattestable := allowUnattestablePairing(cfg, enterprisePolicy)
	attestResult, attestErr := performPairingAttestation(connectCtx, transport, session, logger)
	if attestErr != nil {
		if !allowUnattestable {
			_ = transport.Disconnect()
			if enterprisePolicy == nil {
				logger.Warn("unattestable device refused: the config directory is sealed and the enterprise policy was not verified",
					"hint", "supply the SO PIN (--so-pin-stdin, XKEY_SO_PIN or --so-pin) to honour a sealed policy that allows it")
			}
			return attestErr
		}
		logger.Warn("pairing continued without a verified attestation",
			"device", deviceName,
			"reason", attestErr,
			"policy", "allow_unattestable_devices")
		printUnattestablePairingWarning()
	}

	// Disconnect after pairing (will reconnect when needed)
	_ = transport.Disconnect()

	// Create or update device record
	pairedDevice := newPairedDeviceRecord(
		deviceName, selectedDevice.Address, remotePublicKey, localKey.Private, attestResult)

	// Update or add to configuration.
	// When force re-pairing, remove all old entries for the same device name
	// since Android RPA rotation means the address changes across reinstalls.
	switch {
	case existingDevice != nil:
		// Update existing device matched by address
		for i := range cfg.Devices {
			if cfg.Devices[i].Address == selectedDevice.Address {
				cfg.Devices[i] = pairedDevice
				break
			}
		}
	case force:
		// Force mode: remove stale entries by name, then add fresh entry.
		// This handles the case where the phone's BLE address changed
		// (Android RPA rotation or app reinstall) but the name is the same.
		filtered := make([]PairedDevice, 0, len(cfg.Devices))
		for _, d := range cfg.Devices {
			if d.Name != deviceName {
				filtered = append(filtered, d)
			}
		}
		filtered = append(filtered, pairedDevice)
		cfg.Devices = filtered
	default:
		// Add new device
		cfg.Devices = append(cfg.Devices, pairedDevice)
	}

	// Set as default if first device
	if cfg.DefaultDevice == "" {
		cfg.DefaultDevice = deviceName
	}

	// Save configuration
	if err := pairSeams.saveDevices(cfg); err != nil {
		return &SentinelCauseError{Sentinel: ErrDeviceConfigSaveFailed, Cause: err}
	}

	fmt.Println()
	fmt.Printf("Successfully paired with \"%s\"!\n", deviceName)
	fmt.Printf("Phone public key: %s...\n", truncateKey(pairedDevice.NoisePublicKey))
	fmt.Println()
	fmt.Println("The phone is now available as a key backend.")
	fmt.Println("Use '--backend phone' with xKey commands to use phone-backed keys.")

	return nil
}

// performPairingAttestation attests the device during pairing and returns what
// was VERIFIED about it.
//
// It fails closed: every step — loading the trust material, the RPC round trip,
// chain verification, the live challenge signature, identifying the anchor —
// returns an error that aborts pairing, and no attestation claim is persisted
// unless it came out of evidence that verified.
//
// The decision itself is attestation.AttestOverSession, shared with
// `device attest-device`, the reconnect path and the GUI. What stays here is
// what is genuinely this command's: loading THIS machine's trust store, and
// what the operator sees.
func performPairingAttestation(
	ctx context.Context,
	transport phone.Transport,
	session *phone.NoiseSession,
	logger *slog.Logger,
) (*attestation.Result, error) {
	fmt.Println("Verifying device security...")

	trust, err := pairSeams.loadTrust()
	if err != nil {
		logger.Error("pairing refused: attestation trust material unavailable", "error", err)
		return nil, err
	}

	verified, err := attestation.AttestOverSession(
		ctx, transport, session, trust, pairing.AttestPurposePair, logger)
	if err != nil {
		logger.Error("pairing refused: attestation verification failed", "error", err)
		fmt.Println("  Chain Status:   FAILED")
		fmt.Println()
		fmt.Println("The device's attestation could not be verified. Either its chain")
		fmt.Println("does not lead to a trusted Android hardware attestation root, or it")
		fmt.Println("did not sign this pairing's challenge with the attested key, or it")
		fmt.Println("is running an app too old to prove liveness. Pairing has been refused.")
		return nil, err
	}

	fmt.Println("  Chain Status:   VERIFIED")
	fmt.Printf("  Trust Anchor:   %s\n", verified.TrustAnchor)
	fmt.Printf("  Security Level: %s\n", verified.Result.SecurityLevel)
	fmt.Printf("  Boot State:     %s\n", verified.BootState)
	if verified.Result.BootHashHex != "" {
		fmt.Printf("  Boot Hash:      %s\n", truncateBootHash(verified.Result.BootHashHex))
	}

	return verified.Result, nil
}

// loadPairingAttestationTrust builds this machine's Android hardware
// attestation trust material.
//
// It is the CLI's half of a decision whose other half is shared: WHICH store
// to open is per-surface, what to do with the pool is not.
func loadPairingAttestationTrust() (*attestation.Trust, error) {
	store, err := openTrustStore()
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: attestation.ErrDeviceAttestVerifyFailed, Cause: err}
	}
	defer func() { _ = store.Close() }()

	return attestation.LoadTrust(store)
}
func newPairedDeviceRecord(
	name, address string,
	remotePublicKey, localPrivateKey []byte,
	attest *DeviceAttestationResult,
) PairedDevice {
	device := PairedDevice{
		Name:                 name,
		Address:              address,
		NoisePublicKey:       base64.StdEncoding.EncodeToString(remotePublicKey),
		LocalNoisePrivateKey: base64.StdEncoding.EncodeToString(localPrivateKey),
		PairedAt:             time.Now().UTC(),
	}
	if attest != nil {
		recordDeviceAttestation(&device, attest)
	}
	return device
}

// ErrPairingPolicyRefused indicates the config directory is sealed, an SO
// PIN was supplied, and the policy section did not verify under it. The
// pairing is refused outright rather than continued under a policy that may
// have been edited: the cause (config.ErrPolicyUnverifiable joined with
// ErrPolicyHMACMismatch or ErrPolicyHMACLoadFailed) is reachable with
// errors.Is.
var ErrPairingPolicyRefused = errors.New("device pair: sealed enterprise policy could not be verified")

// resolvePairingPolicy resolves the enterprise plane for one pairing.
//
// It returns the policy with its verification state when the plane can be
// trusted: unsealed (personal mode, the section is the user's own file) or
// sealed and verified under the SO PIN the operator supplied. It returns
// (nil, nil) when the directory is sealed and no SO PIN was supplied — the
// plane exists but is unknown, and allowUnattestablePairing fails closed on
// it. It returns ErrPairingPolicyRefused when an SO PIN was supplied and the
// section did not verify, because a sealed section that does not verify is a
// value anyone may have written and must not be consulted at all (#118).
//
// Where the SO PIN comes from is the same three sources as the user PIN
// (soPINUsage). It is never demanded: an ordinary pairing has no SO at the
// keyboard, and the price of not supplying it is the fail-closed answer.
func resolvePairingPolicy(cmd *cobra.Command, unified *xkeyconfig.Config, logger *slog.Logger) (*xkeyconfig.VerifiedPolicy, error) {
	soPIN, err := resolveSOPINInput(cmd)
	if err != nil {
		return nil, err
	}

	configDir := xkeyconfig.ConfigDir()
	if soPIN == "" && xkeyconfig.IsEnterpriseMode(configDir) {
		logger.Info("sealed enterprise policy not consulted: no SO PIN supplied",
			"config_dir", configDir)
		return nil, nil
	}

	policy, err := xkeyconfig.LoadVerifiedPolicy(unified, configDir, soPIN)
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrPairingPolicyRefused, Cause: err}
	}
	if policy.State == xkeyconfig.PolicySealedVerified {
		logger.Info("enterprise policy verified", "state", policy.State.String())
	}
	return policy, nil
}

// allowUnattestablePairing projects this command's two policy planes onto the
// shared decision, attestation.AllowUnattestablePairing.
//
// What is genuinely this command's is WHERE each plane comes from: the user
// plane is devices.yaml as this package reads it, the enterprise plane is the
// config.VerifiedPolicy resolvePairingPolicy produced, nil when the directory
// is sealed and no SO PIN was supplied. What is not this command's is how they
// combine -- the GUI pairs phones too, and a resolution that lived here alone
// was the #95 defect one level up (#115).
func allowUnattestablePairing(devices *DevicesConfig, policy *xkeyconfig.VerifiedPolicy) bool {
	userAllows := devices != nil && devices.AttestationPolicy != nil &&
		devices.AttestationPolicy.AllowUnattestableDevices
	return attestation.AllowUnattestablePairing(userAllows, policy)
}

// printUnattestablePairingWarning tells the operator what they now have, in the
// terms the record actually supports.
//
// It is deliberately not softened. The default is to refuse; reaching this
// point means someone chose to pair a device whose hardware claims could not be
// checked, and the one thing they must not take away is that the pairing
// carries a verified device identity. It does not carry any device identity.
func printUnattestablePairingWarning() {
	fmt.Println()
	fmt.Println("  WARNING: paired WITHOUT a verified attestation.")
	fmt.Println()
	fmt.Println("  Policy allows pairing an unattestable device, so this pairing")
	fmt.Println("  completed. Nothing about the device's hardware was verified, so")
	fmt.Println("  the record stores no security level, no boot state and no device")
	fmt.Println("  fingerprint -- there is nothing trustworthy to store.")
	fmt.Println()
	fmt.Println("  This device is NOT known to be a hardware-backed security key.")
	fmt.Println("  Run `xkey device attest-device` to attempt attestation again.")
	fmt.Println()
}

// hostname returns the local hostname, or "unknown" if it cannot be determined.
func hostname() string {
	name, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return name
}
