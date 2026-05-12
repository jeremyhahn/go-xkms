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

// Package ca provides additional types that extend the core CA configuration
// and operations. These types complement the primary types in types.go by
// supporting advanced features such as wrapper-style revocation semantics
// and AIA auto-import behavior.
package ca

// RevokeOptions carries options for the extended RevokeCert operation.
//
// Unlike the minimal Revoke(serial, reason) method that only records a
// serial-number-based revocation, RevokeCert uses these options to support
// the full revocation semantics required by ACME/TCG workflows:
//
//   - Reason: the RFC 5280 CRL reason code (see Reason* constants in
//     revocation.go for valid values).
//   - DeleteKeys: when true, RevokeCert also deletes the certificate's
//     associated signing key from the keystore and removes any cached
//     certificate copies. This is the cleanup step required after key
//     compromise revocations where the private key must be destroyed.
type RevokeOptions struct {
	// Reason is the RFC 5280 CRL reason code. See the Reason* constants
	// in revocation.go (ReasonUnspecified, ReasonKeyCompromise, etc.).
	// Defaults to ReasonUnspecified (0).
	Reason int

	// DeleteKeys controls whether the certificate's private key should be
	// deleted from the keystore as part of revocation. This is the behavior
	// used by the ACME wrapper when keyAttrs was passed to Revoke.
	DeleteKeys bool
}
