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

// Relay command errors.
var (
	// ErrDeviceRelayStartFailed indicates the relay server failed to start.
	ErrDeviceRelayStartFailed = errors.New("device: relay server start failed")

	// ErrDeviceRelayStopFailed indicates the relay server failed to stop cleanly.
	ErrDeviceRelayStopFailed = errors.New("device: relay server stop failed")
)

// deviceRelayCmd starts a TCP pairing relay server that serves an already
// paired phone's phone-initiated session over the network, as the TCP
// counterpart to `xkey device listen`'s BLE peripheral (go-xkms#1306).
var deviceRelayCmd = &cobra.Command{
	Use:   "relay",
	Short: "Serve a paired phone's session over TCP instead of BLE",
	Long: `Start a TCP relay server that serves a paired phone's phone-initiated
session over the network, as the TCP counterpart to "xkey device listen"'s
BLE peripheral -- useful when the phone and this host are not in Bluetooth
range of each other but can reach each other over a network.

The relay is NOT a pairing mechanism: it serves the SAME already-paired
device "xkey device listen" does, pinned to that device's Noise static key
exactly the way "listen" pins to it, and requires the same #129 live
attestation proof (the laptop challenges the phone with local.attestDevice)
before serving anything. Pair the phone first with "xkey device pair" (BLE),
then use "xkey device relay" for later sessions when BLE is not available.

It binds to loopback (127.0.0.1) by default. Reachable from the network is
an explicit choice: pass --listen with a non-loopback address (for example
--listen 0.0.0.0:8444) only when you intend the relay to accept connections
from other hosts.

Examples:
  xkey device relay                          Serve the default paired device on 127.0.0.1:8444
  xkey device relay --device "John's Pixel"  Serve a specific paired device
  xkey device relay --listen :9443           Serve on loopback, a custom port
  xkey device relay --listen 0.0.0.0:8444    Accept connections from the network
  xkey device relay --allow-sync             Also allow this session to export the password vault/OATH secrets`,
	RunE: runDeviceRelay,
}

func init() {
	deviceCmd.AddCommand(deviceRelayCmd)
	deviceRelayCmd.Flags().String("listen", "", "TCP listen address as host:port (default: phone.relay_listen_address, 127.0.0.1:8444)")
	registerDeviceListenFlags(deviceRelayCmd)
}

// runDeviceRelay executes the device relay command.
func runDeviceRelay(cmd *cobra.Command, args []string) (runErr error) {
	out := cmd.OutOrStdout()
	logger := slog.Default()

	// The listen address is configuration: --listen over
	// phone.relay_listen_address over the built-in default (loopback).
	listenAddr := relayListenAddress(cmd)

	deviceFilter, _ := cmd.Flags().GetString("device")
	timeout, _ := cmd.Flags().GetDuration("timeout")
	attestModeStr, _ := cmd.Flags().GetString("attestation-mode")
	tpmDevice, _ := cmd.Flags().GetString("tpm-device")
	tpmPCRBank, _ := cmd.Flags().GetString("tpm-pcr-bank")
	tpmEnrollment, _ := cmd.Flags().GetBool("tpm-enrollment")
	allowSyncFlag, _ := cmd.Flags().GetBool("allow-sync")

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
	// this command reads the local Noise static private key to identify
	// itself to the phone. A host with no barrier initialized at all is not
	// refused here (#42 owner ruling) -- see openDeviceBarrier.
	barrier, closeBarrier, err := openDeviceBarrier(cmd)
	if err != nil {
		return err
	}
	defer closeBarrier()

	cfg, err := loadDevicesConfig()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			_, _ = fmt.Fprintln(out, "No paired devices. Use 'xkey device pair' first.")
			return ErrDeviceNotPaired
		}
		return &SentinelCauseError{Sentinel: ErrDeviceConfigLoadFailed, Cause: err}
	}
	if len(cfg.Devices) == 0 {
		_, _ = fmt.Fprintln(out, "No paired devices. Use 'xkey device pair' first.")
		return ErrDeviceNotPaired
	}

	// Resolve which paired device this session pins to, decode its remote
	// static key, and unseal our local one -- shared with "xkey device
	// listen"; see resolveListenTargetDevice.
	targetDevice, expectedRemoteStatic, localPrivateKey, err := resolveListenTargetDevice(cfg, deviceFilter, barrier, logger)
	if err != nil {
		return err
	}
	// Destroyed here, at the unseal, not at the LoadStaticKey below: a
	// decode failure on any other field returns in between, and the raw
	// scalar would be left sitting in protected memory nothing releases.
	defer localPrivateKey.Destroy()

	// Reconstruct the Noise static key from stored private key. This is
	// THIS host's persistent relay identity -- the same key "xkey device
	// listen" advertises for this paired device, not a fresh one generated
	// per invocation: a relay that generated a new key every run could
	// never be pinned to by anything, and never proved it was the same
	// laptop the phone paired with.
	localStaticKey, err := pairing.LoadStaticKeyFromBuffer(localPrivateKey)
	if err != nil {
		return &WrappedError{Msg: "failed to reconstruct local key", Err: err}
	}
	// Ownership transfers to the server below. It is the only thing that
	// knows whether a reader is still live at shutdown: on an incomplete
	// shutdown it retains the key for the process lifetime, where a
	// caller-side destroy would free pages that reader is still using.
	//
	// Until that transfer the key is still ours, and there is real work in
	// between -- TPM init, bridge and handler setup.
	transferred := false
	defer func() {
		if !transferred {
			localStaticKey.Destroy()
		}
	}()

	// Initialize TPM2 if mode is not software-only.
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
	if tpmModule != nil {
		defer func() {
			if closeErr := tpmModule.Close(); closeErr != nil {
				logger.Error("failed to close TPM", slog.String("error", closeErr.Error()))
			}
		}()
	}

	enroller, ownedEnroller, enrollerErr := resolveListenEnroller(tpmEnrollment, tpmModule, tpmDevice, tpmPCRBank, logger)
	if ownedEnroller != nil {
		defer func() {
			if closeErr := ownedEnroller.Close(); closeErr != nil {
				logger.Error("failed to close enrollment TPM", slog.String("error", closeErr.Error()))
			}
		}()
	}

	// Wire the xkmsd bridge so the phone's full remote.* method set is
	// served, not just ping and attestation -- the same bridge "xkey device
	// listen" wires. syncApproval gates the secret-exporting remote.sync*
	// methods (go-xkms#1306): allowed once, at session start, not per
	// request -- see newSessionSyncApproval.
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
	defer collaborators.Close()

	handler, err := newListenRequestHandler(logger, tpmModule, attestMode, bridge)
	if err != nil {
		return &WrappedError{Msg: "failed to create request handler", Err: err}
	}

	// Create the TCP pairing server, pinned to the paired device's key and
	// gated on live attestation exactly like the BLE peripheral is.
	server, err := phone.NewTCPPairingServer(&phone.TCPPairingConfig{
		ListenAddr:     listenAddr,
		LocalStaticKey: localStaticKey,
		OwnsStaticKey:  true,
		// Pinned to the paired device: only a phone holding this exact
		// Noise static key can complete the handshake. Closes the gap the
		// issue found -- the relay used to accept a handshake from any
		// initiator (go-xkms#1306).
		ExpectedRemoteStatic: expectedRemoteStatic,
		RequestHandler:       handler,
		Logger:               logger,
		// The #129 live attestation gate: the server sends local.attestDevice
		// to the phone and requires a verified answer before serving any
		// request (go-xkms#1306). newLiveAttestor is the exact verifier
		// PhoneKeyBackend.Connect uses on the initiator side.
		LiveAttest: newLiveAttestor(targetDevice, logger),
	})
	if err == nil {
		transferred = true
	}
	if err != nil {
		logger.Error("failed to create TCP pairing server", slog.String("error", err.Error()))
		return &SentinelCauseError{Sentinel: ErrDeviceRelayStartFailed, Cause: err}
	}

	if err := server.Start(); err != nil {
		logger.Error("failed to start TCP pairing server", slog.String("error", err.Error()))
		// The server took ownership of the key at construction, so a failed
		// bind still has to go through Stop -- it is the only thing that
		// releases those protected pages now.
		return &SentinelCauseError{Sentinel: ErrDeviceRelayStartFailed, Cause: errors.Join(err, server.Stop())}
	}

	_, _ = fmt.Fprintf(out, "TCP pairing relay listening on %s\n", server.Addr())
	_, _ = fmt.Fprintf(out, "Serving paired device %q\n", targetDevice.Name)
	if tpmModule != nil {
		_, _ = fmt.Fprintln(out, "Attestation mode: TPM2 (hardware)")
	} else {
		_, _ = fmt.Fprintln(out, "Attestation mode: software")
	}
	if bridge != nil {
		_, _ = fmt.Fprintln(out, "xkmsd bridge: enabled (full remote.* method set)")
	} else {
		_, _ = fmt.Fprintln(out, "xkmsd bridge: disabled (only ping and attestation are served)")
	}
	if syncAllowed {
		_, _ = fmt.Fprintln(out, "Phone sync: allowed for this session (--allow-sync)")
	} else {
		_, _ = fmt.Fprintln(out, "Phone sync: refused (pass --allow-sync to export the password vault/OATH secrets to the phone)")
	}
	_, _ = fmt.Fprintln(out, "Press Ctrl+C to stop")

	ctx := context.Background()
	var cancel context.CancelFunc
	if timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, timeout)
	} else {
		ctx, cancel = context.WithCancel(ctx)
	}
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	select {
	case <-sigChan:
	case <-ctx.Done():
		_, _ = fmt.Fprintln(out, "Relay timeout reached")
	}
	signal.Stop(sigChan)

	_, _ = fmt.Fprintln(out, "\nStopping relay server...")
	if stopErr := server.Stop(); stopErr != nil {
		logger.Error("relay server stop error", slog.String("error", stopErr.Error()))
		return &SentinelCauseError{Sentinel: ErrDeviceRelayStopFailed, Cause: stopErr}
	}

	return nil
}
