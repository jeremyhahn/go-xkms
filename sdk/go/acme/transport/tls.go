// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-ca.
//
// go-trusted-ca is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package transport

import (
	"crypto/tls"
	"crypto/x509"
	"os"

	"github.com/jeremyhahn/go-xkms/sdk/go/acme/errors"
)

// TLSConfig holds configuration for mTLS authentication.
type TLSConfig struct {
	// CertFile is the path to the client certificate file.
	CertFile string

	// KeyFile is the path to the client private key file.
	KeyFile string

	// CAFile is the path to the CA certificate file for server verification.
	CAFile string

	// ServerName overrides the server name for certificate verification.
	ServerName string
}

// LoadTLSConfig loads TLS configuration from the given TLSConfig.
// This function validates and loads certificates, creating a *tls.Config
// suitable for mTLS authentication. TLS 1.3 is enforced as the minimum version.
func LoadTLSConfig(cfg TLSConfig) (*tls.Config, error) {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13,
	}

	if cfg.ServerName != "" {
		tlsConfig.ServerName = cfg.ServerName
	}

	// Load client certificate and key for mTLS
	if cfg.CertFile != "" && cfg.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return nil, errors.Wrap(err, errors.CodeConfiguration, "LoadTLSConfig",
				"failed to load client certificate")
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	// Load CA certificate for server verification
	if cfg.CAFile != "" {
		caCert, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, errors.Wrap(err, errors.CodeConfiguration, "LoadTLSConfig",
				"failed to read CA certificate")
		}

		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, errors.New(errors.CodeConfiguration, "LoadTLSConfig",
				"failed to parse CA certificate")
		}
		tlsConfig.RootCAs = caCertPool
	}

	return tlsConfig, nil
}

// LoadTLSConfigFromFiles is a convenience function that loads TLS configuration
// from certificate files with a single call.
func LoadTLSConfigFromFiles(certFile, keyFile, caFile string) (*tls.Config, error) {
	return LoadTLSConfig(TLSConfig{
		CertFile: certFile,
		KeyFile:  keyFile,
		CAFile:   caFile,
	})
}

// ValidateTLSConfig validates that the TLS configuration is complete and usable.
func ValidateTLSConfig(cfg *tls.Config) error {
	if cfg == nil {
		return errors.NewInvalidInput("ValidateTLSConfig", "TLS config is nil")
	}

	if cfg.MinVersion != 0 && cfg.MinVersion < tls.VersionTLS13 {
		return errors.NewConfiguration("ValidateTLSConfig",
			"TLS version must be 1.3 or higher")
	}

	return nil
}

// CloneTLSConfig creates a deep copy of a TLS configuration.
func CloneTLSConfig(cfg *tls.Config) *tls.Config {
	if cfg == nil {
		return nil
	}
	return cfg.Clone()
}
