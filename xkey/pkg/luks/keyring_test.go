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

package luks

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/jeremyhahn/go-luks2/pkg/luks2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// withKeyringCheck replaces the preflight for the test and clears the cached
// success, so each test starts from an unproven keyring.
func withKeyringCheck(t *testing.T, check func() error) *int {
	t.Helper()
	previous := checkKeyringAvailable
	calls := new(int)
	checkKeyringAvailable = func() error { *calls++; return check() }
	t.Cleanup(func() {
		checkKeyringAvailable = previous
	})
	return calls
}

// TestEnsureKeyringAvailable_RefusalIsTypedAndKeepsTheCause proves a failed
// preflight is a KeyringError: ErrKeyringUnavailable to errors.Is, go-luks2's
// classification reachable beneath it, and its message carried.
func TestEnsureKeyringAvailable_RefusalIsTypedAndKeepsTheCause(t *testing.T) {
	cause := &luks2.KeyringUnavailableError{Op: "add the volume key to the session keyring", Kind: luks2.ErrKeyringBlocked, Err: errors.New("operation not permitted")}
	withKeyringCheck(t, func() error { return cause })

	err := EnsureKeyringAvailable()
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrKeyringUnavailable))
	assert.True(t, errors.Is(err, luks2.ErrKeyringBlocked), "go-luks2's classification must stay reachable: %v", err)
	var keyring *KeyringError
	require.True(t, errors.As(err, &keyring))
	assert.Contains(t, err.Error(), "kernel keyring preflight failed")
	assert.Contains(t, err.Error(), cause.Error())
}

// TestEnsureKeyringAvailable_ProbesEveryCall verifies the probe runs on every
// call, after a success as much as after a failure: the per-user key quota can
// be exhausted between two operations of a long-lived process, and an
// operation that trusted an earlier success would fail at the key insertion,
// after the file or device it was meant to protect already existed.
func TestEnsureKeyringAvailable_ProbesEveryCall(t *testing.T) {
	failing := true
	calls := withKeyringCheck(t, func() error {
		if failing {
			return luks2.ErrKeyringBlocked
		}
		return nil
	})

	require.Error(t, EnsureKeyringAvailable())
	require.Error(t, EnsureKeyringAvailable())
	assert.Equal(t, 2, *calls, "a failure is probed again")

	failing = false
	require.NoError(t, EnsureKeyringAvailable())
	require.NoError(t, EnsureKeyringAvailable())
	assert.Equal(t, 4, *calls, "a success is probed again too")

	failing = true
	require.Error(t, EnsureKeyringAvailable(), "an exhausted quota after a success is still caught")
	assert.Equal(t, 5, *calls)
}

// TestVolume_Unlock_RefusesBeforeTouchingTheLoopDevice proves the preflight
// runs after the volume checks and before any loop device is attached: with
// the keyring unavailable, Unlock on an existing container returns the typed
// refusal, never a loop-device error.
func TestVolume_Unlock_RefusesBeforeTouchingTheLoopDevice(t *testing.T) {
	withKeyringCheck(t, func() error { return luks2.ErrKeyringBlocked })
	container := filepath.Join(t.TempDir(), "xkey.luks")
	require.NoError(t, os.WriteFile(container, make([]byte, 4096), 0600))
	vol := NewVolumeWithPaths(container, filepath.Join(t.TempDir(), "mnt"))

	err := vol.Unlock("passphrase")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrKeyringUnavailable), "%v", err)
	var volErr *VolumeError
	assert.False(t, errors.As(err, &volErr), "no loop device may have been attempted: %v", err)
}

// TestVolume_Create_RefusesBeforeCreatingTheContainer proves that with the
// keyring unavailable Create refuses before the container file exists, so
// nothing is left on disk that cannot be opened.
func TestVolume_Create_RefusesBeforeCreatingTheContainer(t *testing.T) {
	withKeyringCheck(t, func() error { return luks2.ErrKeyringUnsupported })
	container := filepath.Join(t.TempDir(), "xkey.luks")
	vol := NewVolumeWithPaths(container, filepath.Join(t.TempDir(), "mnt"))

	err := vol.Create(1024*1024, "passphrase")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrKeyringUnavailable), "%v", err)
	assert.True(t, errors.Is(err, luks2.ErrKeyringUnsupported))
	assert.NoFileExists(t, container)
}
