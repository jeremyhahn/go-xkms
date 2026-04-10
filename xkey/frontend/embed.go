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

// Package frontend embeds the compiled Svelte/Vite frontend assets.
// The dist/ directory is produced by `npm run build` (or `make frontend-build`).
package frontend

import "embed"

//go:embed all:dist
var Assets embed.FS
