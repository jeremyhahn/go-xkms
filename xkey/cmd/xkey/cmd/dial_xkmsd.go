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
	"log/slog"
	"time"

	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
	"github.com/spf13/viper"
)

// XKMSd bridge errors.
var (
	// ErrXKMSdConnectionFailed indicates the connection to xkmsd failed.
	ErrXKMSdConnectionFailed = errors.New("xkmsd: connection failed")

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

	// TLSCAFile is the CA cert file for server verification. Empty means
	// the system trust store.
	TLSCAFile string

	// TLSCertFile and TLSKeyFile are the PEM client certificate and key
	// that admit xkey on xkmsd's socket, the qrdb node's TLS listener.
	TLSCertFile string
	TLSKeyFile  string

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
		TLSCAFile:       viper.GetString("xkmsd.tls_ca_file"),
		TLSCertFile:     viper.GetString("xkmsd.tls_cert_file"),
		TLSKeyFile:      viper.GetString("xkmsd.tls_key_file"),
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

// dialXKMSd creates and connects an SDK transport client from the given
// configuration, filling in defaults first. The caller owns the returned
// client and must close it.
//
// dialXKMSd has no BLE dependency of its own: it only wraps the xkmsd SDK
// transport dial. It lives in this untagged file, rather than alongside the
// ble-gated phone-bridge wiring in fido2_phone_bridge.go, so ca/cert-style
// tests can exercise the "xkey dials xkmsd" path without the ble build tag
// (go-xkms#1081).
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
// xkmsd's socket is the qrdb node's TLS listener, so the client dials it
// over TLS with the configured client certificate, through the same
// endpoint dispatch the xkmsd CLI commands use.
func createXKMSdClient(cfg *XKMSdBridgeConfig) (transport.Client, error) {
	switch cfg.Protocol {
	case "unix":
		return XKMSdEndpoint{
			URL:         "unix://" + cfg.Address,
			TLSCAFile:   cfg.TLSCAFile,
			TLSCertFile: cfg.TLSCertFile,
			TLSKeyFile:  cfg.TLSKeyFile,
		}.Client()
	default:
		return nil, ErrXKMSdUnsupportedProtocol
	}
}
