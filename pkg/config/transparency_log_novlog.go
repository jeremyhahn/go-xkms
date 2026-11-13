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

//go:build !qrdb_vlog

package config

// transparencyLogDefault turns the CA's transparency log off by default:
// without qrdb_vlog go-qrdb serves no verifiable logs, so the log cannot be
// opened and xkmsd runs without one.
const transparencyLogDefault = false
