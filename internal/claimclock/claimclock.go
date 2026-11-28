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

// Package claimclock holds the clock keyversion dates and expires rotation
// claims by. It is internal so that only tests inside this module can
// replace it (to model a claim holder that stalled past ClaimTTL); it is no
// configuration surface.
package claimclock

import "time"

// Now returns the current time. Tests replace it and restore it with
// t.Cleanup; they must not run in parallel with other users of it.
var Now = time.Now
