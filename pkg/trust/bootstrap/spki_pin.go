package bootstrap

import (
	"crypto/tls"

	"github.com/jeremyhahn/go-truststrap/pkg/spkipin"
)

// SPKIPinVerifyConnection returns a tls.Config.VerifyConnection callback that
// accepts the handshake only when the peer's leaf certificate matches the
// SPKI pin (lowercase hex SHA-256 of the SubjectPublicKeyInfo DER). Only the
// leaf is pinned, never an intermediate.
//
// go-truststrap spkipin v0.6.0-alpha has no standalone callback factory, so
// this thin wrapper over spkipin.VerifySPKIPin stays here until it does.
func SPKIPinVerifyConnection(pin string) func(tls.ConnectionState) error {
	return func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return spkipin.ErrNoCertificates
		}
		return spkipin.VerifySPKIPin(cs.PeerCertificates[:1], pin)
	}
}

// PinTLSConfig returns a clone of cfg (or a new config when cfg is nil) whose
// VerifyConnection enforces the SPKI pin. Client certificates, NextProtos and
// RootCAs are kept. With RootCAs set the CA chain is still validated and the
// pin is an extra check; without RootCAs the pin is the sole verifier, so
// InsecureSkipVerify and SessionTicketsDisabled are set and the floor is
// TLS 1.3. cfg itself is never mutated.
//
// go-truststrap spkipin v0.6.0-alpha lacks a "pin an existing config"
// function (its NewPinnedTLSConfig builds a fresh TLS 1.2 config), so this
// helper stays here until it does.
func PinTLSConfig(cfg *tls.Config, pin string) *tls.Config {
	pinned := &tls.Config{}
	if cfg != nil {
		pinned = cfg.Clone()
	}
	pinned.VerifyConnection = SPKIPinVerifyConnection(pin)
	if pinned.RootCAs != nil {
		return pinned
	}

	// InsecureSkipVerify bypasses CA chain validation, which is impossible
	// during trust bootstrap (the CA cert is what we are trying to fetch).
	// VerifyConnection provides the actual peer authentication via SPKI pin.
	pinned.InsecureSkipVerify = true // #nosec G402 -- CA chain skipped; VerifyConnection is sole verifier. Allowlisted in Makefile check-insecure-tls
	// SessionTicketsDisabled forces a full handshake every time so the pin
	// check is never skipped by session resumption (CWE-295).
	pinned.SessionTicketsDisabled = true
	if pinned.MinVersion < tls.VersionTLS13 {
		pinned.MinVersion = tls.VersionTLS13
	}
	return pinned
}
