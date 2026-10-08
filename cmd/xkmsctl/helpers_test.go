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

package main

import "testing"

// withGlobalConfig copies the supplied Config's field values into the
// package-level globalConfig struct for the duration of the test (and
// restores them via t.Cleanup). The global pointer is NEVER reassigned
// — root.go's PersistentFlags are bound to the address of the original
// struct's fields, so swapping the pointer would silently desync the
// CLI's flag layer.
func withGlobalConfig(t *testing.T, cfg *Config) {
	t.Helper()
	original := *globalConfig
	t.Cleanup(func() { *globalConfig = original })
	*globalConfig = *cfg
}
