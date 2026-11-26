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

package xkms

import (
	"os"
	"testing"

	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
)

// TestMain opts the package's tests out of the mandatory-TLS guard: they
// build plaintext clients against loopback and in-process servers, the one
// use the opt-out exists for (ruling 152). The guard's own tests turn it
// back on by clearing the variable with guardOn.
func TestMain(m *testing.M) {
	if err := os.Setenv(transport.EnvAllowInsecureTransport, "true"); err != nil {
		panic(err)
	}
	os.Exit(m.Run())
}
