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

package peer

import (
	"crypto/x509"

	evid "github.com/jeremyhahn/go-xkms/pkg/attestation/evidence"
)

// Attestation key certificate verification is the evidence primitive
// evid.VerifyAKCertificate. The OIDs below are kept here because the DevID
// checks in devid.go assert or forbid them; they are the primitive's values.

// oidTCGVerifiedTPMRestricted is tcg-cap-verifiedTPMRestricted
// (2.23.133.11.1.3), see evid.OIDTCGVerifiedTPMRestricted.
var oidTCGVerifiedTPMRestricted = evid.OIDTCGVerifiedTPMRestricted

// oidTCGVerifiedTPMRestrictedX509 is the same policy in x509.OID form.
var oidTCGVerifiedTPMRestrictedX509 = evid.OIDTCGVerifiedTPMRestrictedPolicy

// mustOID builds an x509.OID from constant arcs.
func mustOID(arc ...uint64) x509.OID {
	oid, err := x509.OIDFromInts(arc)
	if err != nil {
		panic(err)
	}
	return oid
}
