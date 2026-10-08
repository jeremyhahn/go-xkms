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

// Package initialize holds the xkms-owned halves of first boot: the
// CeremonyCA that fronts the TrustedCA, the first-boot admin-mTLS seams
// (CAAdapter), the HSM threshold registry, and administrator login-factor
// enrollment over attached hardware.
//
// The initialization ceremony itself -- barrier initialization, holder
// enrolment, Shamir custody and share claims -- is go-qrdb's, served by the
// node on every transport. This package carries no copy of it.
package initialize

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
)

// SPKIPin returns the hex-encoded SHA-256 of the certificate's
// SubjectPublicKeyInfo: the pin a first-contact client verifies the CA
// against. There is exactly one encoding of this pin in the stack and this
// is it.
func SPKIPin(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:])
}
