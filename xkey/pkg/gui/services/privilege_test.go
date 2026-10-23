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

package services

import "testing"

// asUnprivileged forces the effective-uid seam to report a non-root user for
// the duration of the test. This lets the unprivileged branches be exercised
// deterministically even when the test binary runs as root.
func asUnprivileged(t *testing.T) {
	t.Helper()
	origUID := geteuid
	geteuid = func() int { return 1000 }
	t.Cleanup(func() { geteuid = origUID })
}
