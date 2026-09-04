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

package authenticator

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"

	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
)

// --------------------------------------------------------------------------
// #285 — key material belongs in protected memory
// --------------------------------------------------------------------------

// keyMaterialFields are the KeyManager fields holding unwrapped key material.
// Each unwraps something else in the hierarchy, so each is worth more to an
// attacker than what it protects.
var keyMaterialFields = []string{"adminKey", "cmk", "smk", "umk"}

// TestKeyManagerHoldsKeyMaterialInProtectedMemory walks KeyManager by
// reflection rather than asserting on a list of names, so a field added later
// under a different name is caught too. A hardcoded assertion would not be.
func TestKeyManagerHoldsKeyMaterialInProtectedMemory(t *testing.T) {
	km := reflect.TypeOf(KeyManager{})

	for _, name := range keyMaterialFields {
		f, ok := km.FieldByName(name)
		require.True(t, ok, "KeyManager should have a %s field", name)
		require.Equal(t, "*secure.Buffer", f.Type.String(),
			"KeyManager.%s holds key material and must live in protected memory", name)
	}
}

// TestKeyManagerHasNoRawKeyByteSlices is the structural form: any []byte field
// is a candidate for holding key material on the ordinary Go heap. umkSalt is
// exempt — a salt is not secret.
func TestKeyManagerHasNoRawKeyByteSlices(t *testing.T) {
	km := reflect.TypeOf(KeyManager{})
	exempt := map[string]bool{"umkSalt": true}

	var raw []string
	for i := 0; i < km.NumField(); i++ {
		f := km.Field(i)
		if exempt[f.Name] {
			continue
		}
		if f.Type.Kind() == reflect.Slice && f.Type.Elem().Kind() == reflect.Uint8 {
			raw = append(raw, f.Name)
		}
	}

	require.Empty(t, raw,
		"these KeyManager fields are raw []byte and may hold key material on the ordinary Go heap: %v", raw)
}

// --------------------------------------------------------------------------
// The ownership-transfer contract
// --------------------------------------------------------------------------

// TestAdoptKeyMaterialTakesOwnershipAndWipesSource pins both halves of the
// contract that adoption depends on, and that is easy to get wrong in exactly
// one direction.
//
// secure.NewBufferFromBytes WIPES its source. That is correct and desirable —
// it makes the heap copy KeyWrapper.Unwrap returns short-lived by construction
// rather than by the caller remembering. But it also means **every later use of
// the source is a bug**, and it reads as a safety feature rather than as the
// constraint it is.
//
// That mistake was made twice while writing this change: a key wrapper built
// from the source slice AFTER adopting it, which wraps with an all-zero key.
// One instance was caught by reading; the other only by the existing
// KeyManager tests failing with "key unwrap failed". This test exists so the
// constraint is stated somewhere a reader will meet it.
func TestAdoptKeyMaterialTakesOwnershipAndWipesSource(t *testing.T) {
	src := make([]byte, 32)
	for i := range src {
		src[i] = byte(i + 1)
	}
	want := append([]byte(nil), src...)

	var dst *secure.Buffer
	require.NoError(t, adoptKeyMaterial(&dst, src))
	defer dst.Destroy()

	require.NoError(t, dst.WithBytes(func(b []byte) error {
		require.Equal(t, want, b, "adoption must preserve the key it took")
		return nil
	}))

	require.Equal(t, make([]byte, len(want)), src,
		"adoption wipes its source; every later use of it is a bug, and this is what makes it one")
}

// TestAdoptKeyMaterialDestroysThePreviousBuffer proves re-adoption does not
// leak the buffer it replaces. memguard reclaims only through a process-wide
// purge, so a leaked buffer is locked pages held for the life of the process.
func TestAdoptKeyMaterialDestroysThePreviousBuffer(t *testing.T) {
	first := make([]byte, 32)
	for i := range first {
		first[i] = 0xA1
	}
	second := make([]byte, 32)
	for i := range second {
		second[i] = 0xB2
	}

	var dst *secure.Buffer
	require.NoError(t, adoptKeyMaterial(&dst, first))
	previous := dst

	require.NoError(t, adoptKeyMaterial(&dst, second))
	defer dst.Destroy()

	require.NotSame(t, previous, dst, "re-adoption must install a new buffer")
	require.Nil(t, previous.Bytes(), "the replaced buffer must be destroyed, not leaked")

	require.NoError(t, dst.WithBytes(func(b []byte) error {
		require.Equal(t, byte(0xB2), b[0], "the current buffer holds the newest key")
		return nil
	}))
}

// TestWithKeyBytesRefusesAbsentKey proves the borrow helper reports the locked
// state rather than handing fn a nil slice, which would wrap or unwrap with an
// empty key instead of failing.
func TestWithKeyBytesRefusesAbsentKey(t *testing.T) {
	called := false
	err := withKeyBytes(nil, func([]byte) error {
		called = true
		return nil
	})

	require.ErrorIs(t, err, ErrKeyManagerLocked)
	require.False(t, called, "fn must not run against an absent key")
}

// TestWithKeyBytesRefusesDestroyedKey proves the same for a buffer that was
// destroyed rather than never set — the state a Lock leaves behind.
func TestWithKeyBytesRefusesDestroyedKey(t *testing.T) {
	buf, err := secure.NewBufferFromBytes(make([]byte, 32))
	require.NoError(t, err)
	buf.Destroy()

	called := false
	err = withKeyBytes(buf, func([]byte) error {
		called = true
		return nil
	})

	require.Error(t, err, "a destroyed key must not be borrowed")
	require.False(t, called, "fn must not run against a destroyed key")
}

// --------------------------------------------------------------------------
// Refusals in the locked state
// --------------------------------------------------------------------------

// TestKeyManagerRefusesCredentialWrapWhenLocked proves a locked manager
// refuses rather than operating with absent key material.
func TestKeyManagerRefusesCredentialWrapWhenLocked(t *testing.T) {
	km := NewKeyManager(NewAuthenticatorState(), DefaultConfig())

	_, err := km.WrapCredentialKey([]byte("pkcs8-bytes"))
	require.ErrorIs(t, err, ErrKeyManagerLocked)

	_, err = km.UnwrapCredentialKey([]byte("wrapped-bytes"))
	require.ErrorIs(t, err, ErrKeyManagerLocked)

	_, err = km.GetCMK()
	require.ErrorIs(t, err, ErrKeyManagerLocked)
}

// TestKeyManagerLockDestroysProtectedKeys proves Lock leaves no key material
// behind: every protected field is released, not merely dropped.
func TestKeyManagerLockDestroysProtectedKeys(t *testing.T) {
	km := NewKeyManager(NewAuthenticatorState(), DefaultConfig())

	newKey := func() *secure.Buffer {
		buf, err := secure.NewBufferFromBytes(make([]byte, 32))
		require.NoError(t, err)
		return buf
	}

	km.mu.Lock()
	km.adminKey = newKey()
	km.cmk = newKey()
	km.smk = newKey()
	km.umk = newKey()
	km.unlockSource = unlockSourceSOPIN
	km.mu.Unlock()

	km.Lock()

	km.mu.RLock()
	defer km.mu.RUnlock()
	require.Nil(t, km.adminKey, "adminKey must be released by Lock")
	require.Nil(t, km.cmk, "cmk must be released by Lock")
	require.Nil(t, km.smk, "smk must be released by Lock")
	require.Nil(t, km.umk, "umk must be released by Lock")
	require.Equal(t, unlockSourceNone, km.unlockSource)
}
