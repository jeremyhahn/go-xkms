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

import xkms "github.com/jeremyhahn/go-xkms/sdk/go"

// fipsMode reports whether this process is under FIPS 140 rules, by build or
// by environment.
//
// It is a variable rather than a direct call so a test can drive both sides of
// the gate: the alternative is running the suite twice under different
// environments, which no CI job here does, and an ungated branch is one nobody
// ever executes.
//
// The detection itself is deliberately NOT re-derived here. GOFIPS140 accepts
// "off" among its spellings, so a local "is it set?" check reads the operator's
// explicit opt-OUT as an opt-in. go-xkms already got that right; this consumes
// it through sdk/go rather than keeping a second copy that can drift.
var fipsMode = xkms.FIPSMode
