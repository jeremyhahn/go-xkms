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

// Package truststore manages trusted root certificate pools for attestation
// verification. It supports both embedded well-known roots (such as Google's
// Hardware Attestation Root CAs) and external PEM files loaded from disk.
package truststore

import (
	"crypto/x509"
	_ "embed"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

//go:embed google_hardware_attestation_root.pem
var googleHardwareAttestationRootPEM []byte

// WellKnownRoot identifies a well-known embedded root certificate.
type WellKnownRoot string

const (
	// GoogleHardwareAttestation is Google's Hardware Attestation Root CA,
	// used to anchor Android Key Attestation certificate chains.
	GoogleHardwareAttestation WellKnownRoot = "google-hardware-attestation"
)

// embeddedRootMapping provides O(1) constant-time lookup for embedded root certificates.
var embeddedRootMapping = map[WellKnownRoot][]byte{
	GoogleHardwareAttestation: googleHardwareAttestationRootPEM,
}

// Typed errors for the truststore package.
var (
	ErrInvalidPEM          = errors.New("truststore: invalid PEM data")
	ErrCertificateParse    = errors.New("truststore: failed to parse certificate")
	ErrFileNotFound        = errors.New("truststore: file not found")
	ErrUnknownEmbeddedRoot = errors.New("truststore: unknown embedded root")
	ErrNilConfig           = errors.New("truststore: nil configuration")
	ErrEmptyTrustStore     = errors.New("truststore: no root certificates loaded")
)

// Config holds the configuration for the trust store.
type Config struct {
	// EmbeddedRoots lists well-known embedded root certificate identifiers to include.
	EmbeddedRoots []string `yaml:"embedded_roots" json:"embedded_roots"`

	// ExternalRootPaths lists file paths to additional PEM-encoded root certificates.
	ExternalRootPaths []string `yaml:"external_root_paths" json:"external_root_paths"`
}

// TrustStore manages a set of trusted root certificates for attestation verification.
type TrustStore struct {
	roots []*x509.Certificate
}

// New creates a new TrustStore from the given configuration. It loads embedded
// roots and external root certificate files, merging both into a single pool.
func New(config *Config) (*TrustStore, error) {
	if config == nil {
		return nil, ErrNilConfig
	}

	var roots []*x509.Certificate

	// Load embedded roots
	for _, name := range config.EmbeddedRoots {
		pemData, ok := embeddedRootMapping[WellKnownRoot(name)]
		if !ok {
			return nil, fmt.Errorf("%w: %s", ErrUnknownEmbeddedRoot, name)
		}
		certs, err := parsePEMCertificates(pemData)
		if err != nil {
			return nil, fmt.Errorf("truststore: failed to parse embedded root %q: %w", name, err)
		}
		roots = append(roots, certs...)
	}

	// Load external roots
	for _, path := range config.ExternalRootPaths {
		pemData, err := os.ReadFile(path)
		if err != nil {
			if os.IsNotExist(err) {
				return nil, fmt.Errorf("%w: %s", ErrFileNotFound, path)
			}
			return nil, fmt.Errorf("truststore: failed to read %q: %w", path, err)
		}
		certs, err := parsePEMCertificates(pemData)
		if err != nil {
			return nil, fmt.Errorf("truststore: failed to parse %q: %w", path, err)
		}
		roots = append(roots, certs...)
	}

	return &TrustStore{roots: roots}, nil
}

// Roots returns all trusted root certificates. The returned slice is a copy;
// modifying it does not affect the TrustStore.
func (ts *TrustStore) Roots() []*x509.Certificate {
	result := make([]*x509.Certificate, len(ts.roots))
	copy(result, ts.roots)
	return result
}

// CertPool returns an x509.CertPool containing all trusted roots.
// This is suitable for use with x509.VerifyOptions.
func (ts *TrustStore) CertPool() *x509.CertPool {
	pool := x509.NewCertPool()
	for _, cert := range ts.roots {
		pool.AddCert(cert)
	}
	return pool
}

// Count returns the number of root certificates in the trust store.
func (ts *TrustStore) Count() int {
	return len(ts.roots)
}

// GoogleHardwareAttestationRoots parses and returns the embedded Google Hardware
// Attestation Root CA certificates. This is a convenience method for direct access
// without constructing a full TrustStore.
func GoogleHardwareAttestationRoots() ([]*x509.Certificate, error) {
	return parsePEMCertificates(googleHardwareAttestationRootPEM)
}

// parsePEMCertificates parses all PEM-encoded certificates from the given data.
func parsePEMCertificates(pemData []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := pemData

	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrCertificateParse, err)
		}
		certs = append(certs, cert)
	}

	if len(certs) == 0 {
		return nil, ErrInvalidPEM
	}

	return certs, nil
}
