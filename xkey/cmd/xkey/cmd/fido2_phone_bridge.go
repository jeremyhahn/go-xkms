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
	"errors"
	"io"
	"log/slog"

	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/authenticator/keybackend"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/pairing"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/phone"
	"github.com/spf13/cobra"
)

// ErrXKMSdBridgeCreationFailed indicates the Bridge could not be created.
var ErrXKMSdBridgeCreationFailed = errors.New("xkmsd: bridge creation failed")

// phoneBackendWithBridge wraps a PhoneKeyBackend and adds xkmsd client
// lifecycle management. It implements keybackend.FIDO2KeyBackend through
// embedding and overrides Close() to clean up the xkmsd SDK client.
type phoneBackendWithBridge struct {
	*phone.PhoneKeyBackend
	xkmsdClient transport.Client
	bridge      *pairing.Bridge
	// enrollerCloser owns the TPM handle opened for device enrollment, when
	// this bridge opened one of its own rather than borrowing a shared TPM.
	enrollerCloser io.Closer
	// collaborators holds the long-lived OATH store and sync data sources
	// buildListenBridgeConfig opened for this bridge (go-xkms#1041), the same
	// collaborators "xkey device listen" wires and closes at shutdown. A phone
	// paired through this bridge reaches the identical on-disk stores those
	// commands read and write, not a second wiring that leaves them nil.
	collaborators *listenBridgeCollaborators
	logger        *slog.Logger
}

// Close closes the phone backend, stops the message router, releases the
// OATH store and sync data sources the bridge opened, and closes the xkmsd
// SDK client connection.
func (b *phoneBackendWithBridge) Close() error {
	// Close the phone backend first (stops router, disconnects transport).
	backendErr := b.PhoneKeyBackend.Close()

	// Release the OATH store and sync sources before the client and TPM go
	// away, matching the order "xkey device listen" tears down the same
	// collaborators in. b.collaborators.Close() is a safe no-op when nil (no
	// bridge was built, or a collaborator failed to open).
	b.collaborators.Close()

	// Close the xkmsd SDK client.
	var clientErr error
	if b.xkmsdClient != nil {
		clientErr = b.xkmsdClient.Close()
		if clientErr != nil {
			b.logger.Warn("failed to close xkmsd client", "error", clientErr)
		}
	}

	// Release the TPM handle last: the router must be stopped before the
	// device the enrollment handlers read from goes away.
	var enrollerErr error
	if b.enrollerCloser != nil {
		enrollerErr = b.enrollerCloser.Close()
		if enrollerErr != nil {
			b.logger.Warn("failed to close TPM enroller", "error", enrollerErr)
		}
	}

	return errors.Join(backendErr, clientErr, enrollerErr)
}

// Ensure phoneBackendWithBridge implements FIDO2KeyBackend.
var _ keybackend.FIDO2KeyBackend = (*phoneBackendWithBridge)(nil)

// connectXKMSdBridge creates a xkmsd SDK client, creates a Bridge,
// and enables bidirectional message routing on the phone backend.
//
// Returns nil if xkmsd is not enabled. Returns an error if xkmsd
// is enabled but the connection or bridge creation fails.
//
// cmd is the "xkey fido2" command invocation: it is handed to
// buildListenBridgeConfig unchanged, exactly as "xkey device listen" hands
// its own command to the same function, so the OATH store and sync service
// this bridge serves are opened from the same --barrier-password /
// --barrier-password-file flags (go-xkms#1041). fido2Cmd registers those
// flags itself (fido2.go), so a phone paired through "xkey fido2" reaches the
// identical barrier the operator already unlocked for FIDO2 credential
// storage, not a second, differently-configured one. device is the paired
// phone the bridge serves; bridge calls are audited against it (see
// buildListenBridgeConfig).
func connectXKMSdBridge(backend *phone.PhoneKeyBackend, cmd *cobra.Command, device *PairedDevice, logger *slog.Logger) (*phoneBackendWithBridge, error) {
	cfg := loadXKMSdBridgeConfig()
	if !cfg.Enabled {
		return nil, nil
	}

	client, err := dialXKMSd(cfg, logger)
	if err != nil {
		return nil, err
	}

	// Resolve the TPM the remote.* enrollment methods answer from. This is
	// the same resolution device_listen uses; an open failure is not fatal to
	// the bridge, it is carried through so the phone is told the difference
	// between "no TPM here" and "a TPM I could not open".
	enroller, enrollerCloser, enrollerErr := resolveListenEnroller(
		cfg.TPMEnrollment, nil, cfg.TPMDevice, cfg.TPMPCRBank, logger)

	// Build the Bridge configuration through the exact same collaborator
	// wiring "xkey device listen" uses (buildListenBridgeConfig,
	// device_listen.go): the OATH store, PIV certificate storage, and sync
	// service a phone reaches through this bridge are the same ones a paired
	// laptop's "xkey device listen" serves, not a parallel implementation
	// that only forwards ping/attestation/TPM enrollment (go-xkms#1041).
	bridgeCfg, collaborators := buildListenBridgeConfig(cmd, logger, cfg, device, enroller, enrollerErr)

	bridge, err := pairing.NewBridge(client, bridgeCfg)
	if err != nil {
		collaborators.Close()
		if enrollerCloser != nil {
			err = errors.Join(err, enrollerCloser.Close())
		}
		return nil, errors.Join(ErrXKMSdBridgeCreationFailed, err, client.Close())
	}

	// Enable bidirectional message routing on the phone backend.
	// This starts the MessageRouter background goroutine which:
	// - Routes outbound local.* requests from laptop to phone
	// - Dispatches inbound remote.* requests from phone to Bridge
	//
	// EnableBidirectional gained an error return when it stopped silently
	// starting a second router, which gave this function a failure path it
	// never had — and the resources acquired above have no other owner until
	// phoneBackendWithBridge is built below. Same cleanup as the NewBridge
	// failure directly above.
	if err := backend.EnableBidirectional(bridge); err != nil {
		collaborators.Close()
		if enrollerCloser != nil {
			err = errors.Join(err, enrollerCloser.Close())
		}
		return nil, errors.Join(ErrXKMSdBridgeCreationFailed, err, client.Close())
	}

	logger.Info("xkmsd bridge enabled",
		slog.Int("allowed_backends", len(cfg.AllowedBackends)),
		slog.Int("denied_backends", len(cfg.DeniedBackends)),
	)

	return &phoneBackendWithBridge{
		PhoneKeyBackend: backend,
		xkmsdClient:     client,
		bridge:          bridge,
		enrollerCloser:  enrollerCloser,
		collaborators:   collaborators,
		logger:          logger,
	}, nil
}
