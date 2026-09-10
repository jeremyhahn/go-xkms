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
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/phone"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/qrgen"
)

// Relay command errors.
var (
	// ErrDeviceRelayStartFailed indicates the relay server failed to start.
	ErrDeviceRelayStartFailed = errors.New("device: relay server start failed")

	// ErrDeviceRelayStopFailed indicates the relay server failed to stop cleanly.
	ErrDeviceRelayStopFailed = errors.New("device: relay server stop failed")
)

// deviceRelayCmd starts a TCP pairing relay server that accepts incoming
// connections from remote devices.
var deviceRelayCmd = &cobra.Command{
	Use:   "relay",
	Short: "Start TCP pairing relay server",
	Long: `Start a TCP relay server that accepts connections from remote devices.
This enables network-based pairing as an alternative to Bluetooth.

The relay server listens for incoming TCP connections, performs Noise XX
handshake for mutual authentication, and proxies JSON-RPC requests to
local xKey services.

Examples:
  xkey device relay                          Start relay on default port (:8444)
  xkey device relay --listen :9443           Start relay on custom port
  xkey device relay --qr                     Start relay and show QR code for pairing`,
	RunE: runDeviceRelay,
}

func init() {
	deviceCmd.AddCommand(deviceRelayCmd)
	deviceRelayCmd.Flags().String("listen", "", "TCP listen address as host:port (default: phone.relay_listen_address, :8444)")
	deviceRelayCmd.Flags().Bool("qr", false, "Show QR code for pairing")
}

// runDeviceRelay executes the device relay command.
func runDeviceRelay(cmd *cobra.Command, args []string) error {
	out := cmd.OutOrStdout()
	logger := slog.Default()

	// The listen address is configuration: --listen over
	// phone.relay_listen_address over the built-in default.
	listenAddr := relayListenAddress(cmd)
	showQR, _ := cmd.Flags().GetBool("qr")

	// Generate or load local Noise static key.
	localKey, err := phone.GenerateStaticKey()
	if err != nil {
		logger.Error("failed to generate noise static key", slog.String("error", err.Error()))
		return &SentinelCauseError{Sentinel: ErrDeviceRelayStartFailed, Cause: err}
	}
	// Ownership transfers to the component below. It is the only thing that
	// knows whether a reader is still live at shutdown: on an incomplete
	// shutdown it retains the key for the process lifetime, where a
	// caller-side destroy would free pages that reader is still using.

	// Create the TCP pairing server.
	server, err := phone.NewTCPPairingServer(&phone.TCPPairingConfig{
		ListenAddr:     listenAddr,
		LocalStaticKey: localKey,
		OwnsStaticKey:  true,
		Logger:         logger,
	})
	if err != nil {
		logger.Error("failed to create TCP pairing server", slog.String("error", err.Error()))
		return &SentinelCauseError{Sentinel: ErrDeviceRelayStartFailed, Cause: err}
	}

	// Start the server (begins accepting connections in the background).
	if err := server.Start(); err != nil {
		logger.Error("failed to start TCP pairing server", slog.String("error", err.Error()))
		// The server took ownership of the key at construction, so a failed
		// bind still has to go through Stop — it is the only thing that
		// releases those protected pages now.
		_ = server.Stop()
		return &SentinelCauseError{Sentinel: ErrDeviceRelayStartFailed, Cause: err}
	}

	actualAddr := server.Addr()
	pubKeyB64 := base64.RawURLEncoding.EncodeToString(server.LocalStaticPublicKey())

	_, _ = fmt.Fprintf(out, "TCP pairing relay listening on %s\n", actualAddr)
	_, _ = fmt.Fprintf(out, "Public key: %s\n", pubKeyB64)

	// Show QR code if requested.
	if showQR {
		payload := &qrgen.PairingPayload{
			Version:   1,
			Type:      "xkey-pair",
			NoisePub:  pubKeyB64,
			Addr:      actualAddr,
			Transport: "tcp",
			Name:      relayHostname(),
		}

		qrStr, qrErr := qrgen.GenerateTerminalQR(payload)
		if qrErr != nil {
			logger.Warn("failed to generate QR code", slog.String("error", qrErr.Error()))
		} else {
			_, _ = fmt.Fprintln(out, qrStr)
		}

		uri, uriErr := qrgen.ToURI(payload)
		if uriErr != nil {
			logger.Warn("failed to generate pairing URI", slog.String("error", uriErr.Error()))
		} else {
			_, _ = fmt.Fprintf(out, "Pairing URI: %s\n", uri)
		}
	}

	_, _ = fmt.Fprintln(out, "Press Ctrl+C to stop")

	// Block until interrupt signal.
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan
	signal.Stop(sigChan)

	_, _ = fmt.Fprintln(out, "\nStopping relay server...")
	if stopErr := server.Stop(); stopErr != nil {
		logger.Error("relay server stop error", slog.String("error", stopErr.Error()))
		return &SentinelCauseError{Sentinel: ErrDeviceRelayStopFailed, Cause: stopErr}
	}

	return nil
}

// relayHostname returns a sanitized local hostname for use in pairing payloads.
// Truncates to 64 characters and falls back to "xKey" if unavailable.
func relayHostname() string {
	name, err := os.Hostname()
	if err != nil {
		return "xKey"
	}
	if len(name) > 64 {
		name = name[:64]
	}
	return name
}
