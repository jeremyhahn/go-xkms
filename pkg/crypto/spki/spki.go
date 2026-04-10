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

// Package spki provides SPKI (Subject Public Key Info) pin computation and
// verification for TLS certificate pinning. It computes SHA-256 hashes of
// the SubjectPublicKeyInfo field in X.509 certificates and provides utilities
// for pin-based TLS connection verification.
//
// SPKI pinning has two modes of operation:
//
//  1. Trust bootstrap (NewPinnedTLSConfig): Used when no CA certificate is
//     available yet. The SPKI pin, obtained out-of-band, IS the trust anchor.
//     The pin cryptographically verifies the server's public key, providing
//     security equivalent to or stronger than CA chain validation.
//
//  2. Additive verification (VerifyConnection + CA chain): When a CA cert is
//     available, SPKI pinning adds an extra verification layer on top of
//     standard CA chain validation.
package spki

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"os"
)

var (
	// ErrNilCertificate is returned when a nil certificate is provided.
	ErrNilCertificate = errors.New("certificate is nil")

	// ErrEmptyPin is returned when an empty pin string is provided.
	ErrEmptyPin = errors.New("pin is empty")

	// ErrInvalidPin is returned when the SPKI pin does not match the certificate.
	ErrInvalidPin = errors.New("SPKI pin does not match certificate")

	// ErrInvalidPEM is returned when PEM data cannot be decoded.
	ErrInvalidPEM = errors.New("no PEM data found")

	// ErrParseCertificate is returned when a certificate cannot be parsed.
	ErrParseCertificate = errors.New("failed to parse certificate")

	// ErrNoPeerCertificates is returned when the TLS connection has no peer certificates.
	ErrNoPeerCertificates = errors.New("no peer certificates in connection state")

	// ErrDialFailed is returned when the TLS connection to the server fails.
	ErrDialFailed = errors.New("failed to connect to server")

	// ErrReadCAFile is returned when the CA certificate file cannot be read.
	ErrReadCAFile = errors.New("failed to read CA certificate file")

	// ErrParseCAFile is returned when the CA certificate file cannot be parsed.
	ErrParseCAFile = errors.New("failed to parse CA certificate file")
)

// ComputePin computes the SHA-256 hash of the certificate's SubjectPublicKeyInfo
// and returns the hex-encoded result.
func ComputePin(cert *x509.Certificate) (string, error) {
	if cert == nil {
		return "", ErrNilCertificate
	}
	hash := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(hash[:]), nil
}

// ComputePinBytes computes the raw SHA-256 hash of the certificate's
// SubjectPublicKeyInfo and returns the 32-byte digest.
func ComputePinBytes(cert *x509.Certificate) ([32]byte, error) {
	if cert == nil {
		return [32]byte{}, ErrNilCertificate
	}
	return sha256.Sum256(cert.RawSubjectPublicKeyInfo), nil
}

// VerifyPin verifies that the given pin matches the certificate's SPKI hash.
func VerifyPin(cert *x509.Certificate, pin string) error {
	if cert == nil {
		return ErrNilCertificate
	}
	if pin == "" {
		return ErrEmptyPin
	}
	computed, err := ComputePin(cert)
	if err != nil {
		return err
	}
	if computed != pin {
		return ErrInvalidPin
	}
	return nil
}

// VerifyConnection creates a tls.Config VerifyConnection callback that validates
// the peer certificate's SPKI pin. This is used for SPKI-pinned TLS verification
// as an additive check on top of standard CA chain validation. The callback
// verifies the leaf certificate (first peer certificate) against the expected pin.
func VerifyConnection(pin string) func(tls.ConnectionState) error {
	return func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return ErrNoPeerCertificates
		}
		return VerifyPin(cs.PeerCertificates[0], pin)
	}
}

// NewPinnedTLSConfig creates a TLS configuration for trust bootstrap where no
// CA certificate is available. The SPKI pin (obtained out-of-band from the
// server administrator) cryptographically verifies the server's identity.
//
// Go's TLS stack requires InsecureSkipVerify to bypass CA chain validation
// (impossible without a CA cert), but the VerifyConnection callback provides
// the actual server verification via the SPKI pin hash. The connection is
// fully authenticated — it is NOT insecure.
//
// This is the standard Go pattern for custom TLS verification and is used
// during truststrap bootstrap to establish initial trust with a remote server.
func NewPinnedTLSConfig(spkiPin string) *tls.Config {
	return &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true, //nolint:gosec // CA chain skipped; VerifyConnection provides SPKI pin verification
		VerifyConnection:   VerifyConnection(spkiPin),
	}
}

// FetchServerPin connects to the given server address (host:port) using the
// system trust store for CA verification, retrieves the TLS certificate, and
// returns its SPKI pin. The server's certificate chain must be verifiable by
// the system trust store.
func FetchServerPin(address string) (string, *x509.Certificate, error) {
	return FetchServerPinWithCA(address, nil)
}

// FetchServerPinWithCA connects to the given server address (host:port),
// retrieves the TLS certificate, and returns its SPKI pin. The rootCAs
// parameter specifies the CA certificate pool for server verification.
// If rootCAs is nil, the system trust store is used.
func FetchServerPinWithCA(address string, rootCAs *x509.CertPool) (string, *x509.Certificate, error) {
	conn, err := tls.Dial("tcp", address, &tls.Config{
		RootCAs:    rootCAs,
		MinVersion: tls.VersionTLS12,
	})
	if err != nil {
		return "", nil, ErrDialFailed
	}
	defer func() { _ = conn.Close() }()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return "", nil, ErrNoPeerCertificates
	}

	leaf := certs[0]
	pin, err := ComputePin(leaf)
	if err != nil {
		return "", nil, err
	}
	return pin, leaf, nil
}

// FetchServerPinWithCAFile connects to the given server address (host:port),
// using the CA certificate at the given file path for server verification,
// retrieves the TLS certificate, and returns its SPKI pin.
func FetchServerPinWithCAFile(address, caFile string) (string, *x509.Certificate, error) {
	caCert, err := os.ReadFile(caFile)
	if err != nil {
		return "", nil, ErrReadCAFile
	}
	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return "", nil, ErrParseCAFile
	}
	return FetchServerPinWithCA(address, caCertPool)
}

// ComputePinFromPEM computes the SPKI pin from PEM-encoded certificate data.
func ComputePinFromPEM(pemData []byte) (string, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return "", ErrInvalidPEM
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", ErrParseCertificate
	}
	return ComputePin(cert)
}
