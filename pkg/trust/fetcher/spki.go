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

package fetcher

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"strings"
)

// spkiHexLength is the length of a hex-encoded SHA-256 SPKI hash.
const spkiHexLength = 64

// SPKIHash returns the lowercase hex SHA-256 digest of the certificate's
// RFC 5280 SubjectPublicKeyInfo (DER encoding).
func SPKIHash(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:])
}

// NormalizePin trims whitespace, removes optional ":" separators, lowercases,
// and validates that the result is a 64-character hex string. It returns the
// normalized pin or ErrInvalidPin.
func NormalizePin(pin string) (string, error) {
	clean := strings.ToLower(strings.TrimSpace(pin))
	clean = strings.ReplaceAll(clean, ":", "")
	clean = strings.ReplaceAll(clean, " ", "")
	if len(clean) != spkiHexLength {
		return "", fmt.Errorf("%w: expected %d hex chars, got %d",
			ErrInvalidPin, spkiHexLength, len(clean))
	}
	if _, err := hex.DecodeString(clean); err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalidPin, err)
	}
	return clean, nil
}

// PinVerifier returns a tls.Config.VerifyPeerCertificate callback that fails
// the handshake unless the leaf certificate's SPKI hash equals the supplied
// pin. The pin must already be normalized via NormalizePin.
func PinVerifier(pin string) func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return ErrNoLeafCert
		}
		leaf, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return fmt.Errorf("%w: %v", ErrPinMismatch, err)
		}
		got := SPKIHash(leaf)
		if got != pin {
			return fmt.Errorf("%w: expected %s, got %s",
				ErrPinMismatch, pin, got)
		}
		return nil
	}
}

// BuildTLSConfig returns a *tls.Config that pins the leaf certificate's SPKI
// SHA-256 hash to the supplied value. The pin is mandatory: there is no
// trust-on-first-use path and no InsecureSkipVerify path that does not also
// install PinVerifier as the sole authority on peer acceptance.
//
// Pinning disables the standard chain build (the platform CA is exactly what
// we are trying to fetch — its root is by definition not in the system trust
// store). PinVerifier becomes the sole authority on whether the peer is
// acceptable: it enforces a cryptographic match against the pre-shared SPKI
// hash, which the operator MUST obtain out-of-band (HSM-attested deployment
// manifest, signed deploy log, manually transcribed from the server console,
// or similar secure channel).
//
// This file is the only place where InsecureSkipVerify=true is allowed in
// go-xkms, and it is *only* allowed because PinVerifier is always installed
// alongside it.
func BuildTLSConfig(pin string) (*tls.Config, error) {
	if pin == "" {
		return nil, ErrPinRequired
	}
	clean, err := NormalizePin(pin)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true, //nolint:gosec // gated by PinVerifier; see file header.
		// SessionTicketsDisabled prevents TLS session resumption (tickets/PSK).
		// On a resumed session the stack does NOT invoke VerifyPeerCertificate,
		// which would silently bypass the SPKI pin below. Disabling resumption
		// forces a full handshake every time so PinVerifier is always the sole
		// authority on peer acceptance (CWE-295 / gosec G123).
		SessionTicketsDisabled: true,
		VerifyPeerCertificate:  PinVerifier(clean),
	}, nil
}
