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

package xkms

import (
	"crypto/tls"
	"crypto/x509"
	"errors"

	"github.com/jeremyhahn/go-truststrap/pkg/spkipin"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
)

// NewSPKIPinnedTLSConfig returns a *tls.Config that pins the server's Subject
// Public Key Info (SPKI) to the given pin (lowercase hex SHA-256 of the SPKI
// DER). It lets client binaries build SPKI-pinned transports (e.g.
// first-contact bootstrap) without wiring go-truststrap spkipin themselves.
// The pin replaces CA chain validation, so session tickets are disabled and
// the floor is TLS 1.3.
//
// sdk/go requires the tagged root module, so it builds on spkipin directly
// rather than on pkg/trust/bootstrap.PinTLSConfig (same behaviour).
var NewSPKIPinnedTLSConfig = func(pin string) *tls.Config {
	return &tls.Config{
		MinVersion:             tls.VersionTLS13,
		InsecureSkipVerify:     true, // #nosec G402 -- CA chain skipped; VerifyConnection is sole verifier. Allowlisted in Makefile check-insecure-tls
		SessionTicketsDisabled: true,
		VerifyConnection:       VerifySPKIPinnedConnection(pin),
	}
}

// VerifySPKIPinnedConnection returns a tls.Config VerifyConnection callback
// that checks the server's leaf certificate against an SPKI pin. Unlike
// NewSPKIPinnedTLSConfig it does not replace CA chain validation — it layers
// the pin on top of it, which is what a client that has both a root pool and a
// pin needs. Without this a caller who supplies its own *tls.Config has to
// choose between CA trust and pinning.
var VerifySPKIPinnedConnection = func(pin string) func(tls.ConnectionState) error {
	return func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return spkipin.ErrNoCertificates
		}
		return spkipin.VerifySPKIPin(cs.PeerCertificates[:1], pin)
	}
}

// errNilCertificate is returned by ComputeSPKIPin for a nil certificate.
var errNilCertificate = errors.New("xkms: nil certificate")

// ComputeSPKIPin returns the hex-encoded SHA-256 hash of a certificate's
// SubjectPublicKeyInfo — the pin format WithSPKIPin and
// VerifySPKIPinnedConnection accept.
var ComputeSPKIPin = func(cert *x509.Certificate) (string, error) {
	if cert == nil {
		return "", errNilCertificate
	}
	return spkipin.ComputeSPKIPin(cert), nil
}

// PKCS11TLSConfig configures a PKCS#11-backed mTLS client certificate (the
// private key stays in the HSM/token).
type PKCS11TLSConfig = auth.PKCS11TLSConfig

// NewPKCS11TLSConfig builds a *tls.Config whose client certificate is backed by
// a PKCS#11 token, returning a cleanup func for the session/module. It lets
// client binaries wire hardware-backed mTLS without importing pkg/auth.
var NewPKCS11TLSConfig = auth.NewPKCS11TLSConfig
