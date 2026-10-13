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

//go:build vault

package vault

import (
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/enclaveprovider/enclaveprovidertest"
)

// TestEnclaveProvider_Conformance runs go-enclave's provider conformance
// suite, in both modes, over Vault Transit against the in-process Transit
// double.
//
// The residue sweep is skipped: Transit returns the plaintext base64-encoded
// in a JSON response body, so the key crosses net/http, encoding/json and
// encoding/base64 buffers no provider can wipe, and the in-process Transit
// double that serves it leaves its own decrypted copy to the collector. The
// sweep still runs, and passes, for the backends whose plaintext is handed
// over as a slice.
func TestEnclaveProvider_Conformance(t *testing.T) {
	f := newVaultSealAuthFixture(t)
	enclaveprovidertest.Run(t, enclaveprovidertest.Backend{
		Sealer:           f.backend,
		KeyAttributes:    f.keyA,
		SkipResidueSweep: "Vault Transit returns the plaintext in an HTTP JSON body (net/http, encoding/json, encoding/base64 buffers) and the in-process Transit double keeps its own decrypted copy",
	})
}
