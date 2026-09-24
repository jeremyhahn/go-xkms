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

package software

import (
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/fips140"
	"crypto/rand"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/require"
)

// requireX25519Key generates an X25519 key for a test that needs one to
// exercise further behavior, and reports whether the caller can continue
// using it. X25519 is refused outright under GODEBUG=fips140=only
// (go-xkms deliberately supports it and disables it in FIPS mode; see
// pkg/crypto/x25519's own requireGeneratedKeyPair and docs/fips/README.md),
// so this asserts that refusal and reports ok=false instead of letting the
// caller dereference a nil key.
func requireX25519Key(t *testing.T) (*ecdh.PrivateKey, bool) {
	t.Helper()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		if fips140.Enforced() {
			require.Error(t, err, "X25519 key generation must be refused under GODEBUG=fips140=only")
			return nil, false
		}
		require.NoError(t, err)
		return nil, false
	}
	return key, true
}

// requireGeneratedX25519Key generates an X25519 key through the software
// backend's GenerateKey (attrs must carry X25519Attributes), for a test that
// needs one to exercise further backend behavior, and reports whether the
// caller can continue using it. See requireX25519Key for why the refusal is
// expected under GODEBUG=fips140=only.
func requireGeneratedX25519Key(t *testing.T, sb *SoftwareBackend, attrs *types.KeyAttributes) (crypto.PrivateKey, bool) {
	t.Helper()
	key, err := sb.GenerateKey(context.Background(), attrs)
	if err != nil {
		if fips140.Enforced() {
			require.Error(t, err, "X25519 key generation must be refused under GODEBUG=fips140=only")
			return nil, false
		}
		require.NoError(t, err)
		return nil, false
	}
	return key, true
}
