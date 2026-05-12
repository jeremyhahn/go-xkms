// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

package ssh_test

import (
	"testing"

	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

// TestInterfaceConformance is a compile-time check that the embedded
// implementation satisfies the SDK Client interface. Any interface
// drift in either direction fails the build.
func TestInterfaceConformance(t *testing.T) {
	// Compile-time assertion — the test body itself is empty.
	var _ func(sdkssh.EmbeddedOptions) (sdkssh.Client, error) = sdkssh.NewEmbedded
}
