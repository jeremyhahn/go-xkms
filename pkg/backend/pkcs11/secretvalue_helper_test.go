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

//go:build pkcs11

package pkcs11

import (
	"context"

	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// secretValueString materializes sv's plaintext into a plain Go string for
// test setup that drives miekg/pkcs11 calls (NewSessionPool, Login,
// generateRSAKeyPair, ...) directly, mirroring the production
// Backend.userPIN/soPIN boundary accessors. Errors are ignored: every call
// site passes a types.NewLiteralSecretValue-constructed PIN (real material
// sealed into the enclave immediately, not a bare unresolved Raw), so the
// only failure mode (the enclave could not be opened) never happens against
// test fixtures and is not worth threading a *testing.T through every call
// site for. A nil sv (PIN not configured) yields "".
func secretValueString(sv *types.SecretValue) string {
	b, _ := types.SecretValueBytes(context.Background(), sv)
	return string(b)
}
