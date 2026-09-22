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

// fipsMode reports whether this process is under FIPS 140 rules, by asking
// the Go standard library directly (go-xkms #21): GODEBUG=fips140=on|only at
// runtime, or a GOFIPS140 build, both surface through crypto/fips140.Enabled.
//
// It is a variable rather than a direct call so a test can drive both sides of
// the gate: the alternative is running the suite twice under different
// environments, which no CI job here does, and an ungated branch is one nobody
// ever executes.
var fipsMode = fips140.Enabled
