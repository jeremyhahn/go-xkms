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
	"log/slog"
	"time"

	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
	unixtransport "github.com/jeremyhahn/go-xkms/sdk/go/transport/unix"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/authenticator/keybackend"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/phone"
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
	bridge      *phone.Bridge
	logger      *slog.Logger
}

// Close closes the phone backend, stops the message router, and closes the
// xkmsd SDK client connection.
func (b *phoneBackendWithBridge) Close() error {
	// Close the phone backend first (stops router, disconnects transport).
	backendErr := b.PhoneKeyBackend.Close()

	// Close the xkmsd SDK client.
	var clientErr error
	if b.xkmsdClient != nil {
		clientErr = b.xkmsdClient.Close()
		if clientErr != nil {
			b.logger.Warn("failed to close xkmsd client", "error", clientErr)
		}
	}

	return errors.Join(backendErr, clientErr)
}

// Ensure phoneBackendWithBridge implements FIDO2KeyBackend.
var _ keybackend.FIDO2KeyBackend = (*phoneBackendWithBridge)(nil)

// connectXKMSdBridge creates a xkmsd SDK client, creates a Bridge,
// and enables bidirectional message routing on the phone backend.
//
// Returns nil if xkmsd is not enabled. Returns an error if xkmsd
// is enabled but the connection or bridge creation fails.
func connectXKMSdBridge(backend *phone.PhoneKeyBackend, logger *slog.Logger) (*phoneBackendWithBridge, error) {
	cfg := loadXKMSdBridgeConfig()
	if !cfg.Enabled {
		return nil, nil
	}

	cfg.applyDefaults()

	logger.Info("connecting to xkmsd",
		slog.String("protocol", cfg.Protocol),
		slog.String("address", cfg.Address),
	)

	// Create the SDK transport client based on protocol.
	client, err := createXKMSdClient(cfg)
	if err != nil {
		return nil, errors.Join(ErrXKMSdConnectionFailed, err)
	}

	// Connect to xkmsd.
	ctx, cancel := context.WithTimeout(context.Background(), cfg.ConnectTimeout)
	defer cancel()

	if err := client.Connect(ctx); err != nil {
		_ = client.Close()
		return nil, errors.Join(ErrXKMSdConnectionFailed, err)
	}

	logger.Info("connected to xkmsd")

	// Create the Bridge for routing remote.* requests.
	bridgeCfg := &phone.BridgeConfig{
		AllowedBackends: cfg.AllowedBackends,
		DeniedBackends:  cfg.DeniedBackends,
		RequestTimeout:  cfg.RequestTimeout,
		Logger:          logger,
	}

	bridge, err := phone.NewBridge(client, bridgeCfg)
	if err != nil {
		_ = client.Close()
		return nil, errors.Join(ErrXKMSdBridgeCreationFailed, err)
	}

	// Enable bidirectional message routing on the phone backend.
	// This starts the MessageRouter background goroutine which:
	// - Routes outbound local.* requests from laptop to phone
	// - Dispatches inbound remote.* requests from phone to Bridge
	backend.EnableBidirectional(bridge)

	logger.Info("xkmsd bridge enabled",
		slog.Int("allowed_backends", len(cfg.AllowedBackends)),
		slog.Int("denied_backends", len(cfg.DeniedBackends)),
	)

	return &phoneBackendWithBridge{
		PhoneKeyBackend: backend,
		xkmsdClient:     client,
		bridge:          bridge,
		logger:          logger,
	}, nil
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
