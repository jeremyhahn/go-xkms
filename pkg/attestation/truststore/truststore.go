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

// Package truststore is the stack's one root store: trusted certificates
// classified by purpose (CA, TCG EK manufacturer, Android hardware, IDevID
// issuer, image signer), with synced certificates held in quarantine.
//
// TrustStore is the store contract. DAOStore persists it on a go-qrdb DAO
// (the xkmsd store), BackendStore on a storage.Backend, FileStore in a
// directory of PEM files with a JSON metadata index, and New builds an
// in-memory store from configured embedded roots and PEM files. Android,
// TCG EK and IDevID verification all take their roots from a store of this
// package.
package truststore

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
)

// TrustStore manages a persistent collection of trusted CA certificates.
type TrustStore interface {
	// AddCertificate adds a trusted certificate to the store.
	// Returns ErrCertificateExists if the certificate is already present.
	// Returns ErrInvalidCertificate if cert is nil.
	AddCertificate(cert *x509.Certificate) error

	// AddCertificateWithOptions adds a certificate with explicit metadata options.
	AddCertificateWithOptions(cert *x509.Certificate, opts *AddCertificateOptions) error

	// AddPEM parses and adds all certificates from PEM-encoded data.
	// Returns the number of certificates added and any error encountered.
	// Certificates that already exist are silently skipped.
	AddPEM(pemData []byte) (int, error)

	// ImportPEM parses and adds all certificates from PEM-encoded data,
	// filing each under opts (a nil opts auto-classifies, as AddPEM does).
	// Certificates that already exist are counted as skipped.
	ImportPEM(pemData []byte, opts *AddCertificateOptions) (ImportResult, error)

	// RemoveCertificate removes a certificate by its SHA-256 fingerprint (hex-encoded).
	// Returns ErrCertificateNotFound if no certificate matches.
	RemoveCertificate(fingerprint string) error

	// Certificates returns all trusted certificates in the store.
	Certificates() ([]*x509.Certificate, error)

	// CertificatesByPurpose returns all certificates matching the given purpose.
	CertificatesByPurpose(purpose CertPurpose) ([]*x509.Certificate, error)

	// CertPool returns an x509.CertPool containing all trusted certificates.
	// The pool is cached and invalidated on mutations.
	CertPool() (*x509.CertPool, error)

	// Contains checks if a certificate with the given fingerprint is trusted.
	Contains(fingerprint string) (bool, error)

	// Count returns the number of trusted certificates.
	Count() (int, error)

	// Metadata returns the metadata for a certificate by fingerprint.
	Metadata(fingerprint string) (*CertMetadata, error)

	// SetPurpose updates the purpose classification for a certificate.
	SetPurpose(fingerprint string, purpose CertPurpose) error

	// SetSource updates the source information for a certificate.
	SetSource(fingerprint string, source string) error

	// SetSystemInstalled marks whether the certificate is installed in the OS trust store.
	SetSystemInstalled(fingerprint string, installed bool) error

	// SetTags updates the tags for a certificate.
	SetTags(fingerprint string, tags []string) error

	// Close releases any resources held by the trust store.
	// Reload discards the in-memory cache and re-reads it from the backing
	// store, so certificates added or removed by another process become
	// visible.
	//
	// The cache is REPLACED, not merged. A certificate another process removed
	// must disappear here too: merging would leave the store trusting an anchor
	// the operator revoked, which is a worse failure than not seeing a new one.
	//
	// Returns ErrStoreClosed if the store has been closed.
	Reload() error

	Close() error
}

// Compile-time assertions that both stores satisfy TrustStore.
//
// Asserted because the interface is small enough that an implementer can drift
// out of it silently: a method added here is otherwise only caught where a
// concrete store is assigned to the interface, which may be in another package
// or in no non-test code at all.
var (
	_ TrustStore = (*BackendStore)(nil)
	_ TrustStore = (*FileStore)(nil)
)

// Fingerprint computes the SHA-256 fingerprint of a certificate, returned
// as a lowercase hex-encoded string.
func Fingerprint(cert *x509.Certificate) string {
	hash := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(hash[:])
}

// algorithmNames maps x509.PublicKeyAlgorithm values to human-readable strings.
var algorithmNames = map[x509.PublicKeyAlgorithm]string{
	x509.UnknownPublicKeyAlgorithm: "Unknown",
	x509.RSA:                       "RSA",
	x509.DSA:                       "DSA",
	x509.ECDSA:                     "ECDSA",
	x509.Ed25519:                   "Ed25519",
}

// algorithmName returns a human-readable name for the given public key algorithm.
func algorithmName(algo x509.PublicKeyAlgorithm) string {
	if name, ok := algorithmNames[algo]; ok {
		return name
	}
	return fmt.Sprintf("Unknown(%d)", int(algo))
}
