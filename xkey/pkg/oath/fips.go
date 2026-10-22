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

package oath

import "crypto/fips140"

// fipsMode reports whether crypto/hmac in this process refuses SHA-1, by
// asking the Go standard library directly. That is GODEBUG=fips140=only:
// crypto/fips140.Enforced is the flag crypto/hmac checks. Under fips140=on the
// stdlib still computes an HMAC-SHA-1, so this package does too (owner ruling
// 116: refuse exactly what the stdlib refuses, no allowlist of our own).
func fipsMode() bool {
	return fips140.Enforced()
}
