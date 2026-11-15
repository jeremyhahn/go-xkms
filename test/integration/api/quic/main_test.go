//go:build integration

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

package quic

import (
	"testing"

	"github.com/jeremyhahn/go-xkms/test/integration/api/apiharness"
)

// TestMain brings the server past its sealed window before any test runs,
// through the harness every api test package shares, so this package run on
// its own finds the server unsealed and ready.
func TestMain(m *testing.M) {
	apiharness.Main(m)
}
