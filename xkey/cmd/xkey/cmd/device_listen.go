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
	"os/signal"
	"syscall"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/pairing"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/phone"
	"github.com/spf13/cobra"
)

// deviceListenCmd starts the BLE peripheral to accept phone-initiated connections.
var deviceListenCmd = &cobra.Command{
	Use:   "listen",
	Short: "Listen for phone-initiated connections",
	Long: `Start the BLE peripheral to accept connections from paired phones.

This command starts the laptop as a BLE peripheral (GATT server), allowing
the phone to initiate connections when it needs to perform operations like
re-attestation or key management.

The peripheral advertises the xKey service UUID and waits for the paired
phone to connect. Once connected, the phone can send requests through the
established Noise-encrypted channel.

When the phone sends a remote.attestDevice request, this laptop will generate
its attestation (using TPM2 if available, otherwise software attestation) and
return it to the phone for verification.

Attestation Modes:
  - auto (default): Use TPM2 if available, otherwise fall back to software
  - tpm2: Require TPM2 attestation, fail if TPM2 is not available
  - software: Always use software attestation, even if TPM2 is available

TCG Device Enrollment:
  --tpm-enrollment additionally offers this laptop's TPM to the phone acting
  as a Certificate Authority, so the phone can run the TCG-CSR-IDEVID
  enrollment ceremony against it. It is off by default: enrollment hands the
  phone the EK certificate and lets it drive TPM2_ActivateCredential, so it is
  an explicit decision. A host with no TPM still listens, pairs and serves
  every other method; it simply reports enrollment as unavailable.

This is useful when:
  - The phone needs to verify the laptop's integrity
  - Re-attestation is triggered from the phone
  - The phone wants to use keys on the laptop's xkms

Examples:
  # Start listening for the default paired device
  xkey device listen

  # Listen for a specific device
  xkey device listen --device "John's Pixel"

  # Listen with custom device name
  xkey device listen --name "My Laptop"

  # Listen with timeout (default: no timeout, runs until interrupted)
  xkey device listen --timeout 5m

  # Force TPM2 attestation (fail if TPM2 not available)
  xkey device listen --attestation-mode tpm2

  # Use software attestation only
  xkey device listen --attestation-mode software

  # Also let the phone enroll this laptop's TPM as a TCG device identity
  xkey device listen --tpm-enrollment`,
	RunE: runDeviceListen,
}

func init() {
	deviceCmd.AddCommand(deviceListenCmd)

	registerDeviceListenFlags(deviceListenCmd)
}

// runDeviceListen executes the phone listen command.
func runDeviceListen(cmd *cobra.Command, args []string) (runErr error) {
	logger := slog.Default()

	deviceFilter, _ := cmd.Flags().GetString("device")
	deviceName, _ := cmd.Flags().GetString("name")
	timeout, _ := cmd.Flags().GetDuration("timeout")
	attestModeStr, _ := cmd.Flags().GetString("attestation-mode")
	tpmDevice, _ := cmd.Flags().GetString("tpm-device")
	tpmPCRBank, _ := cmd.Flags().GetString("tpm-pcr-bank")
	tpmEnrollment, _ := cmd.Flags().GetBool("tpm-enrollment")
	allowSyncFlag, _ := cmd.Flags().GetBool("allow-sync")

	// Parse attestation mode
	attestMode := pairing.ParseAttestationMode(attestModeStr)

	// Resolved before anything else touches the network: an SO PIN that
	// fails to verify a sealed policy must refuse the whole session, not
	// just the sync methods it happens to govern (go-xkms#1306).
	syncPolicy, err := resolvePairingPolicy(cmd, unifiedConfigOrDefault(), logger)
	if err != nil {
		return err
	}
	syncAllowed := allowPhoneSyncExport(allowSyncFlag, syncPolicy)

	// The barrier is opened, if one is initialized, before the devices file:
	// this command reads the local Noise static private key to advertise as
	// this host's identity. A host with no barrier initialized at all is not
	// refused here (#42 owner ruling) -- see openDeviceBarrier.
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

	// Resolve which paired device this session pins to, decode its remote
	// static key, and unseal our local one -- shared with "xkey device
	// relay" (go-xkms#1306); see resolveListenTargetDevice.
	targetDevice, expectedRemoteStatic, localPrivateKey, err := resolveListenTargetDevice(cfg, deviceFilter, barrier, logger)
	if err != nil {
		return err
	}
	// Destroyed here, at the unseal, not at the LoadStaticKey below: a
	// decode failure on any other field returns in between, and the raw
	// scalar would be left sitting in protected memory nothing releases.
	defer localPrivateKey.Destroy()

	// Reconstruct the Noise static key from stored private key
	localStaticKey, err := pairing.LoadStaticKey(localPrivateKey.Bytes())
	if err != nil {
		return &WrappedError{Msg: "failed to reconstruct local key", Err: err}
	}
	// Ownership transfers to the peripheral below. It is the only thing that
	// knows whether a reader is still live at shutdown: on an incomplete
	// shutdown it retains the key for the process lifetime, where a
	// caller-side destroy would free pages that reader is still using.
	//
	// Until that transfer the key is still ours, and there is real work in
	// between — TPM init, bridge and handler setup — every failure of which
	// used to be covered by the defer this replaced.
	transferred := false
	defer func() {
		if !transferred {
			localStaticKey.Destroy()
		}
	}()

	// Use hostname as default device name
	if deviceName == "" {
		deviceName = hostname()
	}

	// Initialize TPM2 if mode is not software-only
	var tpmModule xkms.TrustedPlatformModule
	if attestMode != pairing.AttestationModeSoftware {
		tpmModule, err = initTPMForAttestation(tpmDevice, logger)
		if err != nil {
			if attestMode == pairing.AttestationModeTPM2 {
				return &SentinelCauseError{Sentinel: ErrTPM2InitFailed, Cause: err}
			}
			logger.Warn("TPM2 not available, using software attestation",
				slog.String("error", err.Error()))
		}
	}

	// Close TPM when done
	if tpmModule != nil {
		defer func() {
			if closeErr := tpmModule.Close(); closeErr != nil {
				logger.Error("failed to close TPM", slog.String("error", closeErr.Error()))
			}
		}()
	}

	// Resolve the TPM the bridge answers TCG enrollment from. When the
	// attestor already holds this host's TPM open, that same handle is used —
	// the device is opened once per process, not once per feature.
	enroller, ownedEnroller, enrollerErr := resolveListenEnroller(tpmEnrollment, tpmModule, tpmDevice, tpmPCRBank, logger)
	if ownedEnroller != nil {
		defer func() {
			if closeErr := ownedEnroller.Close(); closeErr != nil {
				logger.Error("failed to close enrollment TPM", slog.String("error", closeErr.Error()))
			}
		}()
	}

	// Wire the xkmsd bridge so the phone's full remote.* method set is served,
	// not just ping and attestation. syncApproval gates the secret-exporting
	// remote.sync* methods (go-xkms#1306): allowed once, at session start,
	// not per request -- see newSessionSyncApproval.
	syncApproval := newSessionSyncApproval(targetDevice.Name, syncAllowed, logger)
	bridgeClient, bridge, collaborators, err := connectListenBridge(cmd, logger, targetDevice, enroller, enrollerErr, syncApproval)
	if err != nil {
		return err
	}
	if bridgeClient != nil {
		defer func() {
			if closeErr := bridgeClient.Close(); closeErr != nil {
				logger.Warn("failed to close xkmsd client", slog.String("error", closeErr.Error()))
			}
		}()
	}
	// Closes the OATH store and sync data sources connectListenBridge opened
	// for the life of this daemon. A nil receiver (no bridge, or a
	// collaborator that failed to open) is a safe no-op.
	defer collaborators.Close()

	// Create the request handler that processes phone requests
	handler, err := newListenRequestHandler(logger, tpmModule, attestMode, bridge)
	if err != nil {
		return &WrappedError{Msg: "failed to create request handler", Err: err}
	}

	// Create the BLE peripheral
	peripheral, err := phone.NewBLEPeripheral(&phone.BLEPeripheralConfig{
		LocalStaticKey:       localStaticKey,
		OwnsStaticKey:        true,
		ExpectedRemoteStatic: expectedRemoteStatic,
		DeviceName:           deviceName,
		Logger:               logger,
		RequestHandler:       handler,
		// The #129 live attestation gate: the peripheral sends
		// local.attestDevice to the phone and requires a verified answer
		// before serving any request (go-xkms#1306). newLiveAttestor is the
		// exact verifier PhoneKeyBackend.Connect uses on the initiator side.
		LiveAttest: newLiveAttestor(targetDevice, logger),
	})
	if err == nil {
		// The constructor consumed the key; the peripheral releases it now.
		transferred = true
	}
	if err != nil {
		if errors.Is(err, phone.ErrBLEUnavailable) {
			return ErrDeviceBLEUnavailable
		}
		return &SentinelCauseError{Sentinel: ErrDeviceListenFailed, Cause: err}
	}

	// Set up context with optional timeout
	ctx := context.Background()
	var cancel context.CancelFunc
	if timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	} else {
		ctx, cancel = context.WithCancel(ctx)
		defer cancel()
	}

	// Handle interrupt signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println("\nStopping...")
		cancel()
		// Surfaced, not discarded: an incomplete stop means the peripheral
		// could not confirm it finished — a handler still running, or an
		// advertisement that would not come down. Only the first retains the
		// static key; either is a shutdown this command must not report as
		// clean.
		if err := peripheral.Stop(); err != nil {
			logger.Warn("peripheral stop did not complete cleanly", "error", err)
		}
	}()

	// Registered BEFORE Start, not after: a Start that fails still leaves the
	// peripheral holding the key whose ownership it just took, and returning
	// past an uninstalled defer stranded those protected pages for the life
	// of the process.
	// The result is kept, not dropped. A command that exits 0 after a
	// handler-drain timeout tells the operator the key was released when in
	// fact it was retained, so the stop result becomes the command's result
	// when nothing else already failed.
	defer func() {
		if err := peripheral.Stop(); err != nil {
			logger.Warn("peripheral stop did not complete cleanly", "error", err)
			if runErr == nil {
				runErr = err
			}
		}
	}()

	// Start the peripheral
	if err := peripheral.Start(ctx); err != nil {
		return &SentinelCauseError{Sentinel: ErrDeviceListenFailed, Cause: err}
	}

	fmt.Printf("Listening for connections from \"%s\"...\n", targetDevice.Name)
	fmt.Printf("Advertising as \"%s\"\n", deviceName)
	if tpmModule != nil {
		fmt.Println("Attestation mode: TPM2 (hardware)")
	} else {
		fmt.Println("Attestation mode: software")
	}
	if bridge != nil {
		fmt.Println("xkmsd bridge: enabled (full remote.* method set)")
	} else {
		fmt.Println("xkmsd bridge: disabled (only ping and attestation are served)")
	}
	switch {
	case !tpmEnrollment:
		fmt.Println("TCG device enrollment: disabled (pass --tpm-enrollment to offer it)")
	case enroller != nil:
		fmt.Println("TCG device enrollment: enabled")
	default:
		fmt.Println("TCG device enrollment: requested but no TPM is reachable (see log)")
	}
	fmt.Println("Press Ctrl+C to stop")
	fmt.Println()

	// Accept connections in a loop
	for {
		select {
		case <-ctx.Done():
			if ctx.Err() == context.DeadlineExceeded {
				fmt.Println("Listen timeout reached")
			}
			return nil
		default:
		}

		if err := peripheral.AcceptConnection(ctx); err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return nil
			}
			logger.Error("connection error", slog.String("error", err.Error()))
			// Continue listening for new connections
		}
	}
}
