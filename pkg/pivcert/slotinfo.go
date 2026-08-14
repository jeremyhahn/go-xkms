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

package pivcert

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"time"
)

// NewSlotInfo describes a certificate occupying a PIV slot.
//
// Backends that derive slot listings directly from stored certificates share
// this so every backend reports subject, validity, algorithm and fingerprint
// identically. storedAt is supplied by the caller because not every backend
// records when a certificate was written.
func NewSlotInfo(slot PIVSlot, cert *x509.Certificate, storedAt time.Time) PIVSlotInfo {
	if cert == nil {
		return PIVSlotInfo{Slot: slot, StoredAt: storedAt}
	}

	return PIVSlotInfo{
		Slot:         slot,
		Subject:      cert.Subject.String(),
		Issuer:       cert.Issuer.String(),
		SerialNumber: cert.SerialNumber.Text(16),
		NotBefore:    cert.NotBefore.Format(time.RFC3339),
		NotAfter:     cert.NotAfter.Format(time.RFC3339),
		Algorithm:    KeyAlgorithmName(cert),
		KeySize:      KeySize(cert),
		Fingerprint:  ThumbprintSHA256(cert),
		StoredAt:     storedAt,
	}
}

// KeyAlgorithmName returns the human-readable public key algorithm of a
// certificate, or "Unknown" when the algorithm is not recognized.
func KeyAlgorithmName(cert *x509.Certificate) string {
	if cert == nil {
		return "Unknown"
	}

	switch cert.PublicKeyAlgorithm {
	case x509.RSA:
		return "RSA"
	case x509.ECDSA:
		return "ECDSA"
	case x509.Ed25519:
		return "Ed25519"
	case x509.DSA:
		return "DSA"
	default:
		return "Unknown"
	}
}

// KeySize returns the size in bits of a certificate's public key, or 0 when the
// key type is not recognized.
func KeySize(cert *x509.Certificate) int {
	if cert == nil {
		return 0
	}

	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return pub.N.BitLen()
	case *ecdsa.PublicKey:
		if pub.Curve == nil || pub.Params() == nil {
			return 0
		}
		return pub.Params().BitSize
	case ed25519.PublicKey:
		return ed25519.PublicKeySize * 8
	default:
		return 0
	}
}
