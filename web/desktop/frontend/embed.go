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

// Package frontend embeds the compiled web console SPA for the Wails desktop
// shell. The dist tree is staged by `make build-web` (which copies the same
// bundle used by the daemon embed).
package frontend

import "embed"

// Assets is the embedded SPA (index.html + assets/).
//
//go:embed all:dist
var Assets embed.FS
