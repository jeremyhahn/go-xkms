// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package config

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
)

// LoadTLSConfig loads a tls.Config from the TLSConfig struct
func (cfg *TLSConfig) LoadTLSConfig() (*tls.Config, error) {
	if !cfg.Enabled {
		return nil, nil
	}

	// Load server certificate and key
	cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load server certificate: %w", err)
	}

	// Determine minimum TLS version
	minVersion := uint16(tls.VersionTLS12) // Default to TLS 1.2
	if cfg.MinVersion != "" {
		minVersion = parseTLSVersion(cfg.MinVersion)
	}

	// #nosec G402 - MinVersion is set via variable with TLS 1.2 default, gosec cannot detect this pattern
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   minVersion,
	}

	if cfg.MaxVersion != "" {
		tlsConfig.MaxVersion = parseTLSVersion(cfg.MaxVersion)
	}

	// Set cipher suites
	if len(cfg.CipherSuites) > 0 {
		suites, err := parseCipherSuites(cfg.CipherSuites)
		if err != nil {
			return nil, fmt.Errorf("failed to parse cipher suites: %w", err)
		}
		tlsConfig.CipherSuites = suites
	}

	// Server cipher preference

	// Setup client certificate verification (mTLS)
	if cfg.ClientAuth != "" && cfg.ClientAuth != "none" {
		clientAuth, err := parseClientAuthType(cfg.ClientAuth)
		if err != nil {
			return nil, fmt.Errorf("invalid client_auth value: %w", err)
		}
		tlsConfig.ClientAuth = clientAuth

		// Load CA certificates for client verification
		if cfg.CAFile != "" || len(cfg.ClientCAs) > 0 {
			pool, err := loadCertPool(cfg.CAFile, cfg.ClientCAs)
			if err != nil {
				return nil, fmt.Errorf("failed to load client CA certificates: %w", err)
			}
			tlsConfig.ClientCAs = pool
		}
	}

	return tlsConfig, nil
}

// parseTLSVersion converts a string to a tls version constant
func parseTLSVersion(version string) uint16 {
	switch version {
	case "TLS1.0":
		return tls.VersionTLS10
	case "TLS1.1":
		return tls.VersionTLS11
	case "TLS1.2":
		return tls.VersionTLS12
	case "TLS1.3":
		return tls.VersionTLS13
	default:
		return tls.VersionTLS12 // Default
	}
}

// parseClientAuthType converts a string to a tls.ClientAuthType
func parseClientAuthType(authType string) (tls.ClientAuthType, error) {
	switch authType {
	case "none", "":
		return tls.NoClientCert, nil
	case "request":
		return tls.RequestClientCert, nil
	case "require":
		return tls.RequireAnyClientCert, nil
	case "verify":
		return tls.VerifyClientCertIfGiven, nil
	case "require_and_verify":
		return tls.RequireAndVerifyClientCert, nil
	default:
		return tls.NoClientCert, fmt.Errorf("unknown client auth type: %s", authType)
	}
}

// parseCipherSuites converts cipher suite names to IDs
func parseCipherSuites(suites []string) ([]uint16, error) {
	// Map of cipher suite names to IDs
	cipherSuiteMap := map[string]uint16{
		// TLS 1.3
		"TLS_AES_128_GCM_SHA256":       tls.TLS_AES_128_GCM_SHA256,
		"TLS_AES_256_GCM_SHA384":       tls.TLS_AES_256_GCM_SHA384,
		"TLS_CHACHA20_POLY1305_SHA256": tls.TLS_CHACHA20_POLY1305_SHA256,

		// TLS 1.2
		"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256":   tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384":   tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256": tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384": tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305":    tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305":  tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
	}

	result := make([]uint16, 0, len(suites))
	for _, name := range suites {
		id, ok := cipherSuiteMap[name]
		if !ok {
			return nil, fmt.Errorf("unknown cipher suite: %s", name)
		}
		result = append(result, id)
	}

	return result, nil
}

// loadCertPool loads CA certificates into a cert pool
func loadCertPool(caFile string, additionalCAs []string) (*x509.CertPool, error) {
	pool := x509.NewCertPool()

	// Load main CA file
	if caFile != "" {
		// #nosec G304 - CA file path from trusted config
		caCert, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA file %s: %w", caFile, err)
		}
		if !pool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA certificate from %s", caFile)
		}
	}

	// Load additional CA files
	for _, caPath := range additionalCAs {
		// #nosec G304 - CA file paths from trusted config
		caCert, err := os.ReadFile(caPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA file %s: %w", caPath, err)
		}
		if !pool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA certificate from %s", caPath)
		}
	}

	return pool, nil
}
