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

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	xkeyAttestation "github.com/jeremyhahn/go-xkms/xkey/pkg/attestation"
	xkeyconfig "github.com/jeremyhahn/go-xkms/xkey/pkg/config"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/phone"
	xkeyTruststore "github.com/jeremyhahn/go-xkms/xkey/pkg/truststore"
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
		return &SentinelCauseError{Sentinel: ErrDeviceConfigLoadFailed, Cause: err}
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
	allowUnattestable := allowUnattestablePairing(cfg, GetConfig())
	attestResult, attestErr := performPairingAttestation(connectCtx, transport, session, logger)
	if attestErr != nil {
		if !allowUnattestable {
			_ = transport.Disconnect()
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
	if err := saveDevicesConfig(cfg); err != nil {
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

// pairingAttestationTrust is the trust material pairing verifies against.
//
// It is ONE pool and deliberately nothing else. An earlier version carried a
// parallel flat list of roots so the matching anchor could be looked up by
// fingerprint afterwards, and that list was built from the trust store's
// certificates for EVERY purpose while the pool was built from the
// Android-hardware ones alone. A peer could then append the public DER of a
// certificate stored under an unrelated purpose: verification still succeeded
// through the genuine Android root, and the lookup selected the appended
// certificate as "the anchor". Two sets that must agree are two sets that can
// disagree, so there is now only one, and the anchor is read back out of the
// verification instead of being inferred — see verifiedTrustAnchor.
type pairingAttestationTrust struct {
	pool *x509.CertPool
}

// loadPairingAttestationTrust builds the Android hardware-attestation trust
// material from the local trust store merged with the embedded roots — the
// same construction device attest and the GUI's buildAttestationTrustPool use.
//
// It is loaded BEFORE the phone is asked for an attestation, and its failure
// is fatal. Discovering that no anchor is available only after the challenge
// has gone out leaves the caller holding evidence it has no way to judge, and
// the only safe thing to do with unjudgeable evidence is refuse it — so refuse
// earlier, where the message is about this machine's trust store rather than
// about the phone.
func loadPairingAttestationTrust() (*pairingAttestationTrust, error) {
	store, err := openTrustStore()
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrDeviceAttestVerifyFailed, Cause: err}
	}
	defer func() { _ = store.Close() }()

	verifier, err := xkeyAttestation.NewVerifier(store, xkeyTruststore.LoadEmbeddedRoots)
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrDeviceAttestVerifyFailed, Cause: err}
	}

	pool, err := verifier.BuildTrustPool(xkeyTruststore.PurposeAndroidHardware)
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrDeviceAttestVerifyFailed, Cause: err}
	}

	return &pairingAttestationTrust{pool: pool}, nil
}

// verifiedTrustAnchor returns the trust anchor x509 ACTUALLY used to verify
// the chain, read out of the chain it built, rather than inferred from the
// last certificate the peer sent.
//
// The distinction is the whole point. x509 verification proves the leaf chains
// to some certificate in the pool; it constrains nothing about what follows
// that anchor in the presented slice, so a valid chain with anything appended
// still verifies. Asking the verifier which anchor it used cannot be fooled by
// an appended certificate and cannot drift from the pool, because there is no
// second list to keep in step with it.
//
// The options MUST mirror the ones android.VerifyKeyAttestation verifies with
// — same roots, same intermediates, ExtKeyUsageAny — or this would report the
// anchor of a different verification than the one that was accepted.
func verifiedTrustAnchor(chain []*x509.Certificate, pool *x509.CertPool) (*x509.Certificate, error) {
	if len(chain) == 0 {
		return nil, &DetailError{Err: ErrDeviceAttestVerifyFailed, Detail: ": empty certificate chain"}
	}

	intermediates := x509.NewCertPool()
	for _, cert := range chain[1:] {
		intermediates.AddCert(cert)
	}

	built, err := chain[0].Verify(x509.VerifyOptions{
		Roots:         pool,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrDeviceAttestVerifyFailed, Cause: err}
	}
	if len(built) == 0 || len(built[0]) == 0 {
		return nil, &DetailError{Err: ErrDeviceAttestVerifyFailed, Detail: ": verification returned no chain"}
	}

	verified := built[0]
	return verified[len(verified)-1], nil
}

// performPairingAttestation attests the device during pairing and returns what
// was VERIFIED about it.
//
// It fails closed. Every step — building the trust material, the RPC round
// trip, chain verification, the freshness challenge, identifying the anchor —
// returns an error that aborts pairing, and no attestation claim is persisted
// unless it came out of a chain that verified.
//
// The previous version requested an attestation and stored the answer without
// checking any of it (#95): the nonce was generated, sent, and never looked at
// again, so a replay of any earlier session's attestation was accepted; the
// chain was never verified against any anchor; the fingerprint was the hash of
// whatever certificate the peer put last; and SecurityLevel, BootState and
// VerifiedBootHash were copied out of the peer's own JSON into a record that
// downstream code reads as verified fact. Every failure was a warning that
// let pairing complete, which made attestation advisory on this path.
//
// The claims now come from desc — the attestation extension parsed out of the
// leaf of the verified chain — and not from the sibling JSON fields, which are
// peer assertions that nothing binds to the certificates.
func performPairingAttestation(
	ctx context.Context,
	transport phone.Transport,
	session *phone.NoiseSession,
	logger *slog.Logger,
) (*DeviceAttestationResult, error) {
	fmt.Println("Verifying device security...")

	trust, err := loadPairingAttestationTrust()
	if err != nil {
		logger.Error("pairing refused: attestation trust material unavailable", "error", err)
		return nil, err
	}

	// Generate 32-byte random nonce
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		logger.Error("pairing refused: nonce generation failed", "error", err)
		return nil, &SentinelCauseError{Sentinel: ErrDeviceAttestNonceFailed, Cause: err}
	}

	// Create and send local.attestDevice request
	attestReq := phone.NewRequest(phone.MethodLocalAttestDevice, &phone.LocalAttestDeviceParams{
		Nonce: nonce,
	})

	attestPlaintext, err := phone.EncodeRequest(attestReq)
	if err != nil {
		logger.Error("pairing refused: attestation request encoding failed", "error", err)
		return nil, &SentinelCauseError{Sentinel: ErrDeviceAttestFailed, Cause: err}
	}

	attestCiphertext, err := session.Encrypt(attestPlaintext)
	if err != nil {
		logger.Error("pairing refused: attestation request encryption failed", "error", err)
		return nil, &SentinelCauseError{Sentinel: ErrDeviceAttestFailed, Cause: err}
	}

	attestResponseCiphertext, err := transport.SendAndReceive(ctx, attestCiphertext)
	if err != nil {
		logger.Error("pairing refused: attestation transport error", "error", err)
		return nil, &SentinelCauseError{Sentinel: ErrDeviceAttestFailed, Cause: err}
	}

	attestResponsePlaintext, err := session.Decrypt(attestResponseCiphertext)
	if err != nil {
		logger.Error("pairing refused: attestation response decryption failed", "error", err)
		return nil, &SentinelCauseError{Sentinel: ErrDeviceAttestFailed, Cause: err}
	}

	attestResp, err := phone.DecodeResponse(attestResponsePlaintext)
	if err != nil {
		logger.Error("pairing refused: attestation response decode failed", "error", err)
		return nil, &SentinelCauseError{Sentinel: ErrDeviceAttestFailed, Cause: err}
	}

	if attestResp.Error != nil {
		logger.Error("pairing refused: attestation RPC error",
			"code", attestResp.Error.Code, "message", attestResp.Error.Message)
		return nil, &DetailError{
			Err:    ErrDeviceAttestFailed,
			Detail: fmt.Sprintf(": %s", attestResp.Error.Message),
		}
	}

	attestResult, err := phone.DecodeResult[phone.LocalAttestDeviceResult](attestResp)
	if err != nil {
		logger.Error("pairing refused: attestation result decode failed", "error", err)
		return nil, &SentinelCauseError{Sentinel: ErrDeviceAttestFailed, Cause: err}
	}

	verified, err := verifyPairingAttestation(attestResult.CertificateChain, nonce, trust)
	if err != nil {
		logger.Error("pairing refused: attestation verification failed", "error", err)
		fmt.Println("  Chain Status:   FAILED")
		fmt.Println()
		fmt.Println("The device's attestation chain could not be verified against the")
		fmt.Println("trusted Android hardware attestation roots, or the attestation was")
		fmt.Println("not freshly generated for this pairing. Pairing has been refused.")
		return nil, err
	}

	fmt.Println("  Chain Status:   VERIFIED")
	fmt.Printf("  Trust Anchor:   %s\n", verified.trustAnchor)
	fmt.Printf("  Security Level: %s\n", verified.result.SecurityLevel)
	fmt.Printf("  Boot State:     %s\n", verified.bootState)
	if verified.result.BootHashHex != "" {
		fmt.Printf("  Boot Hash:      %s\n", truncateBootHash(verified.result.BootHashHex))
	}

	return verified.result, nil
}

// newPairedDeviceRecord builds the record written to devices.yaml.
//
// attest is nil exactly when the attestation failed AND policy allowed pairing
// to continue anyway. The record then carries no attestation fields at all --
// not a zeroed security level beside a fingerprint copied from the peer, which
// is what #95 found, but nothing. A later `device attest-device` fills them in,
// and until it does the device reads as never attested, because it has not
// been.
//
// It is a function rather than a literal inside runDevicePair so that invariant
// can be asserted without a BLE transport and a phone on the other end of it.
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

// allowUnattestablePairing resolves what `xkey device pair` does when the
// phone's attestation cannot be verified, across the two planes the owner
// ruling of 2026-08-23 on #95 defines:
//
//   - the USER's setting, devices.yaml `attestation_policy.allow_unattestable_devices`;
//   - the ENTERPRISE/SO setting, the HMAC-sealed config.PolicySection.
//
// The enterprise plane wins only while it says it does. LockPairingAttestationPolicy
// is what "enterprise config may lock the setting" means concretely: unset, the
// user's answer is used; set, PairingAllowUnattestableDevices is used and the
// user's answer is ignored. Nothing else in the resolution consults the user
// plane, so a locked deployment cannot be widened by editing devices.yaml.
//
// Every absent value resolves to false -- refuse. That is the default the
// ruling names, and it is reached by the zero value rather than by a defaults
// table, deliberately: this package cannot rely on config.DefaultPolicy(),
// because a config file carrying a partial `policy:` block resolves the keys it
// omits to false rather than to their defaults (measured; #114). A design whose
// secure state came from that table would be insecure for exactly the
// deployments that write a minimal policy file.
func allowUnattestablePairing(devices *DevicesConfig, unified *xkeyconfig.Config) bool {
	allowed := devices != nil && devices.AttestationPolicy != nil &&
		devices.AttestationPolicy.AllowUnattestableDevices

	// The enterprise plane may only ever make the answer STRICTER.
	//
	// This is narrower than "the sealed section decides", and the narrowing is
	// forced rather than chosen. GetConfig() returns whatever was loaded from
	// xkey.yaml; nothing on the CLI path calls config.VerifyPolicyHMAC, and
	// nothing on this path CAN -- verification needs the SO PIN, which a
	// pairing command does not have and must not start demanding. Treating
	// those fields as authoritative in both directions therefore meant any
	// user who can edit xkey.yaml could write
	//
	//     policy:
	//       lock_pairing_attestation_policy: true
	//       pairing_allow_unattestable_devices: true
	//
	// and pair an unattestable device, over the top of a devices.yaml that
	// refuses. That is a fail-open reached by editing an UNAUTHENTICATED file,
	// and it is worse than having no enterprise plane at all, because it looks
	// like enforcement.
	//
	// Monotone consumption removes it without needing the SO PIN: an
	// unverified section can only ever REFUSE, which is the direction no
	// attacker wants, and refusing is already what an absent section gets you.
	// Locking the setting OPEN needs authenticated policy and is filed as
	// go-xkms#118; until then this function cannot honour it, and silently
	// honouring it anyway was the defect.
	if unified != nil && unified.Policy.LockPairingAttestationPolicy &&
		!unified.Policy.PairingAllowUnattestableDevices {
		return false
	}
	return allowed
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

// pairingVerifyOptions is the policy every pairing attestation is verified
// under, in one place so it can be asserted directly.
//
// It exists as a function because two of these four fields are enforced inside
// the SDK against material this package's fixtures cannot construct — no
// exported builder produces an attestation extension carrying a RootOfTrust —
// so a test here can pin WHICH policy is requested even where it cannot
// exercise the refusal. The refusals themselves are covered by
// pkg/attestation/android's own suite (ErrInsufficientSecurityLevel,
// ErrUnverifiedBoot). Splitting it that way is the honest division: this
// package proves the call site asks for the bar, that package proves the bar
// is enforced.
func pairingVerifyOptions(pool *x509.CertPool, nonce []byte) *xkms.AndroidVerifyOptions {
	return &xkms.AndroidVerifyOptions{
		TrustedRoots:  pool,
		ExpectedNonce: nonce,

		// The same bar `device attest-device` already enforces, and that
		// alignment is the point rather than a new policy: without it pairing
		// ADMITTED a device that its own first re-attestation would refuse, so
		// the weaker gate was the one establishing the binding. A
		// software-protected key is not a phone acting as an HSM, and
		// reporting "Chain Status: VERIFIED" over one is the overstatement #94
		// already had to correct once.
		MinSecurityLevel: xkms.AndroidSecurityLevelTrustedEnvironment,

		// Refuses an explicitly unverified boot state. Note what it does NOT
		// do: a chain whose extension carries no RootOfTrust at all passes it,
		// because the SDK's check is "if present, it must be verified". That
		// is the SDK's documented contract and attest-device inherits it too,
		// so it is not changed here — the requirement that the claim be
		// PRESENT is enforced at the point of consumption instead, in
		// requireAttestedBootState below.
		VerifyBootState: true,
	}
}

// verifiedPairingAttestation is what a verified attestation yields: the record
// that may be persisted, plus the two display strings derived from the same
// verified material so nothing printed comes from an unverified source.
type verifiedPairingAttestation struct {
	result      *DeviceAttestationResult
	trustAnchor string
	bootState   string
}

// verifyPairingAttestation is the security decision, separated from the RPC
// that fetches the evidence so it can be exercised directly.
//
// It returns an error unless the chain verifies to a known Android hardware
// attestation root AND carries this pairing's challenge. Everything in the
// returned record is derived from that verified chain.
func verifyPairingAttestation(
	derChain [][]byte,
	nonce []byte,
	trust *pairingAttestationTrust,
) (*verifiedPairingAttestation, error) {
	if trust == nil || trust.pool == nil {
		return nil, &DetailError{
			Err:    ErrDeviceAttestVerifyFailed,
			Detail: ": no attestation trust material",
		}
	}
	if len(nonce) == 0 {
		return nil, &DetailError{
			Err:    ErrDeviceAttestVerifyFailed,
			Detail: ": no challenge to verify freshness against",
		}
	}

	chain, err := parseDERChain(derChain)
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrDeviceAttestVerifyFailed, Cause: err}
	}

	// Both options are non-nil, and that is load-bearing: VerifyKeyAttestation
	// SKIPS chain verification when TrustedRoots is nil and SKIPS the challenge
	// comparison when ExpectedNonce is nil, so a nil reaching here would
	// restore exactly the defect this is fixing while still reporting success.
	// The guards above are what stop that.
	//
	// ExpectedNonce is what establishes freshness: it is compared, in constant
	// time, against the attestationChallenge inside the leaf certificate's
	// SIGNED extension. The Nonce echoed back in the RPC result is not checked
	// and must not be — it is an unsigned field the peer controls, so matching
	// it proves only that the peer can copy.
	desc, err := xkms.VerifyAndroidKeyAttestation(chain, pairingVerifyOptions(trust.pool, nonce))
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrDeviceAttestVerifyFailed, Cause: err}
	}

	// Which anchor the chain verified UNDER, taken from the verification
	// itself. Never chain[len-1] — that is the value #95 found being
	// persisted, and it is chosen by the peer.
	matchedRoot, err := verifiedTrustAnchor(chain, trust.pool)
	if err != nil {
		return nil, err
	}

	rot, err := requireAttestedBootState(desc)
	if err != nil {
		return nil, err
	}

	// Claims taken from the verified extension, not from the peer's JSON.
	verified := &verifiedPairingAttestation{
		trustAnchor: formatTrustAnchor(matchedRoot),
		bootState:   rot.VerifiedBootState.String(),
		result: &DeviceAttestationResult{
			AttestationTime:   time.Now().UTC(),
			SecurityLevel:     desc.AttestationSecurityLevel.String(),
			DeviceFingerprint: certFingerprint(matchedRoot),
			BootStateVerified: true,
			BootHashHex:       hex.EncodeToString(rot.VerifiedBootHash),
		},
	}

	return verified, nil
}

// requireAttestedBootState refuses an attestation that does not actually make a
// boot-state claim, or makes an unacceptable one.
//
// AndroidVerifyOptions.VerifyBootState is "if a RootOfTrust is present, it must
// say verified". Absence therefore PASSES it, and the previous version of this
// function turned that into a successful pairing: the CLI printed "Chain
// Status: VERIFIED", the record stored a security level and an attestation
// timestamp, and the device was admitted having claimed nothing whatsoever
// about its boot chain. A phone-as-HSM pairing is exactly the case where that
// claim is the product.
//
// The check lives HERE rather than in pkg/attestation/android because absence
// versus refusal is the CONSUMER's policy: the SDK's contract is deliberately
// "verify what is claimed", other callers depend on it, and widening it would
// change every one of them. This is the point of consumption for pairing.
//
// DeviceLocked is required for the same reason. An unlocked bootloader can run
// an arbitrary image, so "verified boot" from one is a statement about a chain
// the owner can replace at will.
//
// A device that fails any of these is UNATTESTABLE, which is a policy question
// with a policy answer -- see allowUnattestablePairing. It is not silently
// admitted here.
func requireAttestedBootState(desc *xkms.AndroidKeyDescription) (*xkms.AndroidRootOfTrust, error) {
	rot := desc.TeeEnforced.RootOfTrust
	if rot == nil {
		return nil, &DetailError{
			Err:    ErrDeviceAttestVerifyFailed,
			Detail: ": the attestation carries no root of trust, so it makes no claim about the device's boot chain",
		}
	}
	if !rot.DeviceLocked {
		return nil, &DetailError{
			Err:    ErrDeviceAttestVerifyFailed,
			Detail: ": the device bootloader is unlocked, so a verified boot chain can be replaced at will",
		}
	}
	if rot.VerifiedBootState != xkms.AndroidVerifiedBootVerified {
		return nil, &DetailError{
			Err:    ErrDeviceAttestVerifyFailed,
			Detail: ": device boot state is " + rot.VerifiedBootState.String() + ", not verified",
		}
	}
	return rot, nil
}

// hostname returns the local hostname, or "unknown" if it cannot be determined.
func hostname() string {
	name, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return name
}
