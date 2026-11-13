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

package importtoken

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func generateTestRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return key
}

// TestNewSealedRSAKey_NilPrivateKey verifies NewSealedRSAKey rejects a nil
// key rather than sealing a zero-value DER blob that would fail on every
// later Use.
func TestNewSealedRSAKey_NilPrivateKey(t *testing.T) {
	_, err := NewSealedRSAKey(t.Context(), nil)
	require.Error(t, err)
}

// TestSealedRSAKey_UseAfterDestroy verifies a destroyed key cannot be
// opened again: Use reports an error instead of panicking or returning
// stale material.
func TestSealedRSAKey_UseAfterDestroy(t *testing.T) {
	sealed, err := NewSealedRSAKey(t.Context(), generateTestRSAKey(t))
	require.NoError(t, err)

	sealed.Destroy()
	// Destroy must be idempotent.
	sealed.Destroy()

	err = sealed.Use(t.Context(), func(*rsa.PrivateKey) error { return nil })
	require.Error(t, err)
	assert.Nil(t, sealed.PublicKey())
}

// TestSealedRSAKey_NilReceiver verifies every method tolerates a nil
// *SealedRSAKey, matching the software backend's original destroy()
// contract this type replaces.
func TestSealedRSAKey_NilReceiver(t *testing.T) {
	var sealed *SealedRSAKey

	assert.Nil(t, sealed.PublicKey())
	assert.NotPanics(t, sealed.Destroy)

	err := sealed.Use(t.Context(), func(*rsa.PrivateKey) error { return nil })
	require.Error(t, err)
}
