// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

// The object identifiers this package recognises credentials by, exported
// for the external test that pins them to pkg/ca. That test cannot live in
// package peer: pkg/ca reaches this package through pkg/xkms.
var (
	OIDTCGVerifiedTPMFixed          = oidTCGVerifiedTPMFixed
	OIDTCGVerifiedTPMRestricted     = oidTCGVerifiedTPMRestricted
	OIDTCGHwTypeTPM2                = oidTCGHwTypeTPM2
	OIDTCGOnEKPermIdSha256          = oidTCGOnEKPermIdSha256
	OIDHardwareModuleName           = oidHardwareModuleName
	OIDPermanentIdentifier          = oidPermanentIdentifier
	OIDTCGVerifiedTPMFixedX509      = oidTCGVerifiedTPMFixedX509
	OIDTCGVerifiedTPMRestrictedX509 = oidTCGVerifiedTPMRestrictedX509
)
