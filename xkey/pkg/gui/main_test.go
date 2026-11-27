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

package gui

import (
	"os"
	"testing"

	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
)

// TestMain opts the package's tests out of the mandatory-TLS guard: they
// connect over plain HTTP to httptest servers on loopback, the one use the
// opt-out exists for (ruling 152).
func TestMain(m *testing.M) {
	if err := os.Setenv(transport.EnvAllowInsecureTransport, "true"); err != nil {
		panic(err)
	}
	os.Exit(m.Run())
}
