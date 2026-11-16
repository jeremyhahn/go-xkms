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

package pkcs8

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/require"
)

// TestDecodeKey_PasswordConfiguredLoadsPlaintextKey proves a backend that
// allows plaintext keys still loads a key stored as plaintext PKCS#8 when a
// password is configured (a CA given a password after its key was written,
// RequireKeyPassword=false), and a fail-closed backend still refuses it.
func TestDecodeKey_PasswordConfiguredLoadsPlaintextKey(t *testing.T) {
	t.Parallel()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	plaintext, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	pw, err := types.NewPasswordFromString("configured-later")
	require.NoError(t, err)

	got, err := (&PKCS8Backend{allowPlaintext: true}).decodeKey(plaintext, pw)
	require.NoError(t, err, "a plaintext key must load when plaintext keys are allowed")
	require.True(t, key.Equal(got), "the loaded key must be the stored key")

	_, err = (&PKCS8Backend{allowPlaintext: false}).decodeKey(plaintext, pw)
	require.ErrorIs(t, err, ErrKeyDecodingFailed, "a fail-closed backend must not fall back to a plaintext key")
}
