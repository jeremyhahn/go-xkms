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
	"io"
	"log/slog"
	"time"

	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
	unixtransport "github.com/jeremyhahn/go-xkms/sdk/go/transport/unix"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/authenticator/keybackend"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/pairing"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/phone"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// XKMSd bridge errors.
var (
	// ErrXKMSdConnectionFailed indicates the connection to xkmsd failed.
	ErrXKMSdConnectionFailed = errors.New("xkmsd: connection failed")

	// ErrXKMSdBridgeCreationFailed indicates the Bridge could not be created.
	ErrXKMSdBridgeCreationFailed = errors.New("xkmsd: bridge creation failed")

	// ErrXKMSdUnsupportedProtocol indicates the configured protocol is not supported.
	ErrXKMSdUnsupportedProtocol = errors.New("xkmsd: unsupported protocol")
)

// Default xkmsd configuration values.
const (
	defaultXKMSdProtocol       = "unix"
	defaultXKMSdAddress        = "xkms-data/xkms.sock"
	defaultXKMSdConnectTimeout = 10 * time.Second
	defaultXKMSdRequestTimeout = 30 * time.Second
)

// XKMSdBridgeConfig holds the configuration for the xkmsd bridge.
type XKMSdBridgeConfig struct {
	// Enabled controls whether the xkmsd bridge is active.
	Enabled bool

	// Protocol is the transport protocol to use ("unix", "grpc").
	Protocol string

	// Address is the xkmsd server address (socket path or host:port).
	Address string

	// ConnectTimeout is the timeout for connecting to xkmsd.
	ConnectTimeout time.Duration

	// RequestTimeout is the timeout for individual requests to xkmsd.
	RequestTimeout time.Duration

	// TLSEnabled enables TLS for the connection.
	TLSEnabled bool

	// TLSCAFile is the CA cert file for server verification.
	TLSCAFile string

	// AllowedBackends restricts which xkmsd backends the phone can access.
	AllowedBackends []string

	// DeniedBackends explicitly denies access to specific backends.
	DeniedBackends []string

	// TPMEnrollment offers this host's TPM to the phone acting as the
	// enterprise CA, serving the remote.* TCG/IDevID enrollment methods.
	TPMEnrollment bool

	// TPMDevice is the TPM2 device path (default: /dev/tpmrm0).
	TPMDevice string

	// TPMPCRBank overrides the PCR bank the platform policy digest is
	// computed over. Empty uses the pkg/tpm2 default (SHA-256).
	TPMPCRBank string
}

// loadXKMSdBridgeConfig reads the xkmsd bridge configuration from viper.
func loadXKMSdBridgeConfig() *XKMSdBridgeConfig {
	return &XKMSdBridgeConfig{
		Enabled:         viper.GetBool("xkmsd.enabled"),
		Protocol:        viper.GetString("xkmsd.protocol"),
		Address:         viper.GetString("xkmsd.address"),
		ConnectTimeout:  viper.GetDuration("xkmsd.connect_timeout"),
		RequestTimeout:  viper.GetDuration("xkmsd.request_timeout"),
		TLSEnabled:      viper.GetBool("xkmsd.tls.enabled"),
		TLSCAFile:       viper.GetString("xkmsd.tls.ca_file"),
		AllowedBackends: viper.GetStringSlice("xkmsd.sharing.allowed_backends"),
		DeniedBackends:  viper.GetStringSlice("xkmsd.sharing.denied_backends"),
		TPMEnrollment:   viper.GetBool("xkmsd.tpm.enrollment"),
		TPMDevice:       viper.GetString("xkmsd.tpm.device"),
		TPMPCRBank:      viper.GetString("xkmsd.tpm.pcr_bank"),
	}
}

// applyDefaults fills in zero-value fields with sensible defaults.
func (c *XKMSdBridgeConfig) applyDefaults() {
	if c.Protocol == "" {
		c.Protocol = defaultXKMSdProtocol
	}
	if c.Address == "" {
		c.Address = defaultXKMSdAddress
	}
	if c.ConnectTimeout <= 0 {
		c.ConnectTimeout = defaultXKMSdConnectTimeout
	}
	if c.RequestTimeout <= 0 {
		c.RequestTimeout = defaultXKMSdRequestTimeout
	}
}

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
// storage, not a second, differently-configured one.
func connectXKMSdBridge(backend *phone.PhoneKeyBackend, cmd *cobra.Command, logger *slog.Logger) (*phoneBackendWithBridge, error) {
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
	bridgeCfg, collaborators := buildListenBridgeConfig(cmd, logger, cfg, enroller, enrollerErr)

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

// dialXKMSd creates and connects an SDK transport client from the given
// configuration, filling in defaults first. The caller owns the returned
// client and must close it.
func dialXKMSd(cfg *XKMSdBridgeConfig, logger *slog.Logger) (transport.Client, error) {
	cfg.applyDefaults()

	logger.Info("connecting to xkmsd",
		slog.String("protocol", cfg.Protocol),
		slog.String("address", cfg.Address),
	)

	client, err := createXKMSdClient(cfg)
	if err != nil {
		return nil, errors.Join(ErrXKMSdConnectionFailed, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), cfg.ConnectTimeout)
	defer cancel()

	if err := client.Connect(ctx); err != nil {
		return nil, errors.Join(ErrXKMSdConnectionFailed, err, client.Close())
	}

	logger.Info("connected to xkmsd")
	return client, nil
}

// createXKMSdClient creates an SDK transport client for the given protocol.
func createXKMSdClient(cfg *XKMSdBridgeConfig) (transport.Client, error) {
	switch cfg.Protocol {
	case "unix":
		return unixtransport.New(
			transport.WithAddress(cfg.Address),
		)
	default:
		return nil, ErrXKMSdUnsupportedProtocol
	}
}
