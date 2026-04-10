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

package icon

import _ "embed"

// AppIcon is the 256x256 xKey brand icon (white key on navy circle).
// Used by the system tray, Wails window, and anywhere a PNG icon is needed.
//
//go:embed appicon.png
var AppIcon []byte
