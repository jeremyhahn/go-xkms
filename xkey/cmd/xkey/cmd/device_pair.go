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

	registerDevicePairFlags(devicePairCmd)
}

// Device pair command errors (#1307).
var (
	// ErrDeviceNameInvalid indicates the advertised device name failed
	// validation: empty, too long, or containing a non-printable character.
	// See pairing.ValidateDeviceName.
	ErrDeviceNameInvalid = errors.New("device pair: invalid device name")

	// ErrDeviceNameCollision indicates the advertised device name is
	// already used by a different paired device -- one pinned to a
	// different Noise static key, not the device being (re-)paired. See
	// pairing.ConflictingPairedDevice.
	ErrDeviceNameCollision = errors.New("device pair: device name is already used by a different paired device")
)

// pairingTransport is what runDevicePair needs from a transport: discovery,
// a connection to the selected device, and the encrypted channel. The BLE
// transport is the production implementation; a test supplies one backed
// by an in-memory pair so the command can be driven without a phone.
type pairingTransport interface {
	pairing.Transport
	Scan(ctx context.Context) ([]phone.ScanResult, error)
	ScanAll(ctx context.Context) ([]phone.ScanResult, error)
	Connect(ctx context.Context, address string) error
	Disconnect() error
	Close() error
}

// abortPairing disconnects transport and returns baseErr joined with any
// disconnect failure. Used on runDevicePair's many early-return failure
// paths so a failed disconnect from an already-failed pairing attempt is
// never silently dropped.
func abortPairing(transport pairingTransport, baseErr error) error {
	if cerr := transport.Disconnect(); cerr != nil {
		return errors.Join(baseErr, cerr)
	}
	return baseErr
}

// pairingSeams are runDevicePair's injection points: how it opens its
// transport, reads and writes the devices file, opens the barrier the new
// Noise private key is sealed under (#42), and loads this machine's
// attestation trust. Production wires the real implementations; a test
// replaces them so the abort/allow/save wiring itself can be exercised, not
// only the helpers it calls.
type pairingSeams struct {
	newTransport func(cfg *phone.BLETransportConfig) (pairingTransport, error)
	loadDevices  func() (*DevicesConfig, error)
	saveDevices  func(cfg *DevicesConfig) error
	loadTrust    func() (*attestation.Trust, error)
	openBarrier  func(cmd *cobra.Command) (pairing.NoiseKeyBarrier, func(), error)
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
	openBarrier:  openDeviceBarrier,
}

// runDevicePair executes the phone pairing command.
func runDevicePair(cmd *cobra.Command, args []string) (err error) {
	logger := slog.Default()

	deviceFilter, err := cmd.Flags().GetString("device")
	if err != nil {
		return &DetailError{Err: ErrCommandFlagInvalid, Detail: ": device: " + err.Error()}
	}
	scanTimeout, err := resolveDeviceScanTimeout(cmd)
	if err != nil {
		return err
	}
	force, err := cmd.Flags().GetBool("force")
	if err != nil {
		return &DetailError{Err: ErrCommandFlagInvalid, Detail: ": force: " + err.Error()}
	}

	// The barrier is opened, if one is initialized, before anything else
	// including the scan: pairing generates a new Noise static private key
	// that gets sealed under it when there is one (#42). A host with no
	// barrier initialized at all is not refused here -- barrier comes back
	// nil with a nil error, and sealOrWarnLocalNoiseKey below falls back to
	// the legacy plaintext form with a warning, same as xkey always did
	// before #42. A barrier that exists but could not be opened IS refused,
	// and there is nothing to gain from running a full BLE handshake and
	// attestation exchange only to hit that refusal at the very end.
	barrier, closeBarrier, err := pairSeams.openBarrier(cmd)
	if err != nil {
		return err
	}
	defer closeBarrier()

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
	defer func() {
		if closeErr := transport.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()

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

	// Determine device name for storage and display. This is the BLE
	// advertised local name -- untrusted input from the device being paired
	// -- and it becomes the record's lookup key below, so it is validated
	// before anything else uses it (#1307).
	deviceName := selectedDevice.DisplayName()
	if err := pairing.ValidateDeviceName(deviceName); err != nil {
		return &SentinelCauseError{Sentinel: ErrDeviceNameInvalid, Cause: err}
	}

	fmt.Printf("\nPairing with \"%s\" (%s)...\n", deviceName, selectedDevice.Address)

	// Generate local Noise static key
	localKey, err := pairing.GenerateStaticKey()
	if err != nil {
		return &WrappedError{Msg: "failed to generate local key", Err: err}
	}
	// The private half is base64ed into the stored device record before this
	// returns, so the protected copy does not outlive the command.
	defer localKey.Destroy()

	// Create Noise session for handshake
	session, err := pairing.NewNoiseSession(&pairing.NoiseSessionConfig{
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
	handshakeCfg := &pairing.HandshakeConfig{
		Transport:            transport,
		Session:              session,
		Logger:               logger,
		StripEnvelopeHeader:  false, // Android sends raw Noise messages, no envelope
		EnvelopeHeaderSize:   0,
		LocalStaticPublicKey: session.LocalStaticPublicKey(),
	}
	if err := pairing.PerformHandshake(connectCtx, handshakeCfg); err != nil {
		return abortPairing(transport, &WrappedError{Msg: "key exchange failed", Err: err})
	}

	// Send pairing confirmation request to phone
	fmt.Println("Waiting for confirmation on phone...")
	pairingReq := pairing.NewRequest(pairing.MethodPairingConfirm, &pairing.PairingConfirmParams{
		DeviceName:   hostname(),
		PublicKeyHex: hex.EncodeToString(session.LocalStaticPublicKey()),
	})
	pairingPlaintext, err := pairing.EncodeRequest(pairingReq)
	if err != nil {
		return abortPairing(transport, &WrappedError{Msg: "failed to encode pairing request", Err: err})
	}
	pairingCiphertext, err := session.Encrypt(pairingPlaintext)
	if err != nil {
		return abortPairing(transport, &WrappedError{Msg: "failed to encrypt pairing request", Err: err})
	}
	pairingResponseCiphertext, err := transport.SendAndReceive(connectCtx, pairingCiphertext)
	if err != nil {
		return abortPairing(transport, &WrappedError{Msg: "pairing confirmation failed", Err: err})
	}
	pairingResponsePlaintext, err := session.Decrypt(pairingResponseCiphertext)
	if err != nil {
		return abortPairing(transport, &WrappedError{Msg: "failed to decrypt pairing response", Err: err})
	}
	pairingResp, err := pairing.DecodeResponse(pairingResponsePlaintext)
	if err != nil {
		return abortPairing(transport, &WrappedError{Msg: "failed to decode pairing response", Err: err})
	}
	if pairingResp.Error != nil {
		return abortPairing(transport, pairing.MapRPCError(pairingResp.Error))
	}
	pairingResult, err := pairing.DecodeResult[pairing.PairingConfirmResult](pairingResp)
	if err != nil {
		return abortPairing(transport, &WrappedError{Msg: "failed to decode pairing result", Err: err})
	}
	if !pairingResult.Confirmed {
		return abortPairing(transport, phone.ErrPairingRejected)
	}
	fmt.Printf("Phone confirmed pairing as \"%s\"\n", pairingResult.DeviceName)

	// Get the phone's public key
	remotePublicKey := session.RemoteStaticPublicKey()
	if len(remotePublicKey) == 0 {
		return abortPairing(transport, &MessageError{Msg: "failed to obtain phone's public key"})
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
			if enterprisePolicy == nil {
				logger.Warn("unattestable device refused: the config directory is sealed and the enterprise policy was not verified",
					"hint", "supply the SO PIN (--so-pin-stdin or XKEY_SO_PIN) to honour a sealed policy that allows it")
			}
			return abortPairing(transport, attestErr)
		}
		logger.Warn("pairing continued without a verified attestation",
			"device", deviceName,
			"reason", attestErr,
			"policy", "allow_unattestable_devices")
		printUnattestablePairingWarning()
	}

	// Disconnect after pairing (will reconnect when needed). Pairing has
	// already succeeded at this point, so a failed disconnect doesn't
	// change the outcome below, but it is logged since transport.Close
	// deferred above will otherwise be the only chance to notice the
	// device connection did not tear down cleanly.
	if err := transport.Disconnect(); err != nil {
		logger.Warn("failed to disconnect after pairing", "error", err)
	}

	// Seal the local Noise static private key before it is written anywhere,
	// or fall back to the legacy plaintext form with a warning if no barrier
	// is initialized on this host at all (#42). localKey.Private is still
	// valid here: it is destroyed by the deferred localKey.Destroy() above,
	// which has not run yet.
	noiseKeyField, err := sealOrWarnLocalNoiseKey(logger, deviceName, barrier, localKey.Private)
	if err != nil {
		return err
	}

	// Create or update device record
	pairedDevice := newPairedDeviceRecord(
		deviceName, selectedDevice.Address, remotePublicKey, noiseKeyField, attestResult)

	// Update or add to configuration; see resolvePairedDevices for the
	// name-collision refusal and identity-based replacement (#1307).
	updatedDevices, err := resolvePairedDevices(cfg.Devices, pairedDevice)
	if err != nil {
		return err
	}
	cfg.Devices = updatedDevices

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
	transport pairing.Transport,
	session *pairing.NoiseSession,
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

// resolveEnterpriseApplicationPolicy resolves the enterprise plane of the
// attested-application allow-list (#1305) for loadPairingAttestationTrust,
// which is called both from a command's own RunE and from deep re-attestation
// call graphs that thread no *cobra.Command through (see
// resolveSOPINFromEnv). Only XKEY_SO_PIN can supply the SO PIN here, never
// --so-pin-stdin, since an unattended reconnect has no operator to answer a
// stdin prompt. unified is the CLI's own loaded config (GetConfig()) rather
// than read again here, so a test can supply a fixture the same way
// resolvePairingPolicy's own unified parameter does.
//
// Unlike resolvePairingPolicy's own resolution -- used for the
// unattestable-pairing WIDEN decision, whose safe fallback is simply the
// ordinary strict pairing path, still fully functional -- an unverified
// sealed section has NO safe fallback here: which allow-list a locked
// deployment intends is unknown until the section verifies, and there is no
// "ordinary strict path" to degrade to when the question is which
// application to trust at all. So a genuinely SEALED config directory that
// does not verify -- no XKEY_SO_PIN, or a PIN that does not match --
// REFUSES outright with attestation.ErrApplicationPolicyUnverifiable, never
// silently falling back to devices.yaml. A user (or attacker) able to write
// devices.yaml but not produce the SO PIN must never be able to bypass a
// deployment that locks the allow-list merely by leaving the PIN unsupplied.
//
// Only a genuinely UNSEALED (personal-mode) config directory falls through
// to the user's own devices.yaml -- there, the policy section IS the user's
// own file, so there is nothing to verify and nothing to bypass.
func resolveEnterpriseApplicationPolicy(unified *xkeyconfig.Config) (*xkeyconfig.PolicySection, error) {
	configDir := xkeyconfig.ConfigDir()
	sealed := xkeyconfig.IsEnterpriseMode(configDir)

	if !sealed {
		// Personal mode: no enterprise plane exists to verify in the first
		// place. unified may even be nil here -- loadPairingAttestationTrust
		// runs from contexts that never went through RootCmd's initConfig (a
		// direct unit test of the trust loader, chiefly) -- and an absent
		// config in an unsealed directory is still no plane to refuse
		// against; devices.yaml governs.
		return nil, nil
	}

	// Sealed from here on: every exit below either verifies or refuses, and
	// none of them falls back to devices.yaml.
	if unified == nil {
		return nil, &SentinelCauseError{
			Sentinel: attestation.ErrApplicationPolicyUnverifiable, Cause: xkeyconfig.ErrConfigInvalid}
	}

	soPIN, err := resolveSOPINFromEnv()
	if err != nil {
		return nil, err
	}

	policy, err := xkeyconfig.LoadVerifiedPolicy(unified, configDir, soPIN)
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: attestation.ErrApplicationPolicyUnverifiable, Cause: err}
	}
	return &policy.Policy, nil
}

// loadPairingAttestationTrust builds this machine's Android hardware
// attestation trust material: the trust store's roots and the
// attested-application allow-list, resolved across the user's devices.yaml
// and, in a sealed (enterprise) deployment, the SO's allow-list instead once
// XKEY_SO_PIN verifies it (#1305). A sealed deployment whose section does NOT
// verify refuses outright -- see resolveEnterpriseApplicationPolicy -- so
// pairing and re-attestation never run on an application allow-list this
// machine could not confirm the SO's intent for.
//
// It is the CLI's half of a decision whose other half is shared: WHICH store
// and file to read is per-surface, what to do with them is not. A missing
// devices.yaml allow-lists nothing, so LoadTrust refuses with
// pairing.ErrApplicationPolicyUnconfigured; one that cannot be read refuses
// outright rather than being mistaken for an absent policy.
func loadPairingAttestationTrust() (_ *attestation.Trust, err error) {
	devices, err := loadDevicesConfig()
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, &SentinelCauseError{Sentinel: ErrDeviceConfigLoadFailed, Cause: err}
	}

	enterprise, err := resolveEnterpriseApplicationPolicy(GetConfig())
	if err != nil {
		return nil, err
	}
	apps := attestation.ResolveApplicationPolicy(devices.applicationPolicy(), enterprise)

	store, err := openTrustStore()
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: attestation.ErrDeviceAttestVerifyFailed, Cause: err}
	}
	defer func() {
		if closeErr := store.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()

	return attestation.LoadTrust(store, apps)
}

// newPairedDeviceRecord builds the persisted record for a freshly paired
// device. localNoisePrivateKey is the value to store verbatim in
// LocalNoisePrivateKey -- the caller seals it (pairing.SealLocalNoiseKey)
// before calling this, so this function never sees the raw private scalar
// and cannot accidentally persist it unsealed (#42).
func newPairedDeviceRecord(
	name, address string,
	remotePublicKey []byte,
	localNoisePrivateKey string,
	attest *DeviceAttestationResult,
) PairedDevice {
	device := PairedDevice{
		Name:                 name,
		Address:              address,
		NoisePublicKey:       base64.StdEncoding.EncodeToString(remotePublicKey),
		LocalNoisePrivateKey: localNoisePrivateKey,
		PairedAt:             time.Now().UTC(),
	}
	if attest != nil {
		recordDeviceAttestation(&device, attest)
	}
	return device
}

// resolvePairedDevices returns devices with pairedDevice inserted (#1307).
//
// It refuses a name collision with a different, still-paired device
// (ErrDeviceNameCollision): re-pairing the SAME device is allowed, but
// persisting a second device under a name already in use would make every
// later name lookup ambiguous between them. Otherwise every existing record
// that identifies the SAME device -- matched by address or by its pinned
// Noise key, which survives Android's RPA address rotation across
// reinstalls -- is replaced by pairedDevice, unconditionally rather than
// only under --force: a same-address or same-key match already confirmed
// itself as this device by completing the handshake, so there is nothing
// left for --force to gate. A device matching neither is appended.
//
// This replaces `--force` deleting every record sharing the advertised
// name, which could remove an unrelated device's pairing merely because an
// operator reused its display name; that collision is refused outright
// above; see pairing.ConflictingPairedDevice, pairing.SamePairedDeviceIndices
// and pairing.ReplacePairedDevices, which do the matching this sequences.
func resolvePairedDevices(devices []PairedDevice, pairedDevice PairedDevice) ([]PairedDevice, error) {
	if conflict := pairing.ConflictingPairedDevice(devices, pairedDevice.Name, pairedDevice.Address, pairedDevice.NoisePublicKey); conflict != nil {
		return nil, &DetailError{
			Err: ErrDeviceNameCollision,
			Detail: fmt.Sprintf(": %q is already paired at address %s; choose a different name or unpair it first",
				pairedDevice.Name, conflict.Address),
		}
	}

	sameDevice := pairing.SamePairedDeviceIndices(devices, pairedDevice.Address, pairedDevice.NoisePublicKey)
	if len(sameDevice) > 0 {
		return pairing.ReplacePairedDevices(devices, sameDevice, pairedDevice), nil
	}
	return append(devices, pairedDevice), nil
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
