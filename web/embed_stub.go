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

//go:build !ui

package web

import "io/fs"

// Assets reports that no web UI is embedded in this build. Binaries built
// without the "ui" tag serve the API only; cmd/xkmsd skips the UI mount
// when ok is false.
func Assets() (fs.FS, bool) {
	return nil, false
}
