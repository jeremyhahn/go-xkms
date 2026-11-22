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

// copyTrackingPassword hands out a fresh copy of its value from each Bytes
// call and keeps every copy, so a test can check the caller wiped them.
type copyTrackingPassword struct {
	value  []byte
	copies *[][]byte
}

func (p copyTrackingPassword) Bytes() []byte {
	c := append([]byte(nil), p.value...)
	*p.copies = append(*p.copies, c)
	return c
}

func (p copyTrackingPassword) WithBytes(fn func([]byte) error) error { return fn(p.Bytes()) }
func (p copyTrackingPassword) String() string                        { return types.PasswordRedacted }
func (p copyTrackingPassword) Clear()                                {}

func requireAllWiped(t *testing.T, copies [][]byte, op string) {
	t.Helper()
	require.NotEmpty(t, copies, "%s must read the password", op)
	for i, c := range copies {
		for _, b := range c {
			if b != 0 {
				t.Fatalf("%s left password copy %d unwiped", op, i)
			}
		}
	}
}

// TestEncodeDecodeKey_WipePasswordCopies proves encodeKey and decodeKey wipe
// the Password.Bytes() copy they borrow before returning.
func TestEncodeDecodeKey_WipePasswordCopies(t *testing.T) {
	t.Parallel()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	b := &PKCS8Backend{}

	var encCopies [][]byte
	encoded, err := b.encodeKey(key, copyTrackingPassword{value: []byte("wipe-me"), copies: &encCopies})
	require.NoError(t, err)
	requireAllWiped(t, encCopies, "encodeKey")

	var decCopies [][]byte
	got, err := b.decodeKey(encoded, copyTrackingPassword{value: []byte("wipe-me"), copies: &decCopies})
	require.NoError(t, err)
	require.True(t, key.Equal(got))
	requireAllWiped(t, decCopies, "decodeKey")
}
