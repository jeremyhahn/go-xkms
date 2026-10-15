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

package truststore

import (
	"crypto/x509"
	_ "embed"
	"errors"
	"fmt"
	"os"

	"github.com/jeremyhahn/go-xkms/pkg/errs"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// googleHardwareAttestationRootPEM contains the Google Hardware Attestation
// Root CA certificates (RSA and ECDSA).
//
//go:embed google_hardware_attestation_root.pem
var googleHardwareAttestationRootPEM []byte

// WellKnownRoot identifies an embedded well-known root certificate set.
type WellKnownRoot string

const (
	// GoogleHardwareAttestation identifies the Google Hardware Attestation
	// Root CA certificates used for Android Key Attestation.
	GoogleHardwareAttestation WellKnownRoot = "google-hardware-attestation"
)

// embeddedRoot is one embedded root set and the purpose its certificates
// are filed under.
type embeddedRoot struct {
	pem     []byte
	purpose CertPurpose
}

// embeddedRootMapping maps well-known root identifiers to their embedded
// PEM data and purpose.
var embeddedRootMapping = map[WellKnownRoot]embeddedRoot{
	GoogleHardwareAttestation: {pem: googleHardwareAttestationRootPEM, purpose: PurposeAndroidHardware},
}

// embeddedSourcePrefix marks the Source of a certificate New loaded from an
// embedded root set; the set's identifier follows it.
const embeddedSourcePrefix = "embedded:"

// Config selects the roots New loads.
type Config struct {
	// EmbeddedRoots lists well-known embedded root certificate identifiers to include.
	EmbeddedRoots []string `yaml:"embedded_roots" json:"embedded_roots"`

	// ExternalRootPaths lists file paths to additional PEM-encoded root certificates.
	ExternalRootPaths []string `yaml:"external_root_paths" json:"external_root_paths"`
}

// New builds an in-memory TrustStore holding the roots config selects.
// Embedded roots are filed under their set's purpose; certificates read from
// ExternalRootPaths are classified by ClassifyCertificate and record their
// path as the source. A certificate listed twice is loaded once.
func New(config *Config) (TrustStore, error) {
	if config == nil {
		return nil, ErrNilConfig
	}

	store, err := NewBackendStore(storage.NewMemory(), "")
	if err != nil {
		return nil, err
	}

	for _, name := range config.EmbeddedRoots {
		root, ok := embeddedRootMapping[WellKnownRoot(name)]
		if !ok {
			return nil, &errs.Detail{Err: ErrUnknownEmbeddedRoot, Detail: name}
		}
		certs, err := parsePEMCertificates(root.pem)
		if err != nil {
			return nil, &errs.Wrapped{Msg: fmt.Sprintf("truststore: failed to parse embedded root %q", name), Err: err}
		}
		opts := &AddCertificateOptions{Purpose: root.purpose, Source: embeddedSourcePrefix + name}
		if err := addRoots(store, certs, opts); err != nil {
			return nil, err
		}
	}

	for _, path := range config.ExternalRootPaths {
		pemData, err := os.ReadFile(path)
		if err != nil {
			if os.IsNotExist(err) {
				return nil, &errs.Detail{Err: ErrFileNotFound, Detail: path}
			}
			return nil, &errs.Wrapped{Msg: fmt.Sprintf("truststore: failed to read %q", path), Err: err}
		}
		certs, err := parsePEMCertificates(pemData)
		if err != nil {
			return nil, &errs.Wrapped{Msg: fmt.Sprintf("truststore: failed to parse %q", path), Err: err}
		}
		opts := &AddCertificateOptions{Source: path}
		if err := addRoots(store, certs, opts); err != nil {
			return nil, err
		}
	}

	return store, nil
}

// addRoots adds certs to store under opts, skipping certificates already
// present.
func addRoots(store TrustStore, certs []*x509.Certificate, opts *AddCertificateOptions) error {
	for _, cert := range certs {
		err := store.AddCertificateWithOptions(cert, opts)
		if err != nil && !errors.Is(err, ErrCertificateExists) {
			return err
		}
	}
	return nil
}

// GoogleHardwareAttestationRoots returns the parsed Google Hardware Attestation
// Root CA certificates. This is a convenience function for callers that need
// the roots without constructing a full TrustStore.
func GoogleHardwareAttestationRoots() ([]*x509.Certificate, error) {
	return parsePEMCertificates(googleHardwareAttestationRootPEM)
}
