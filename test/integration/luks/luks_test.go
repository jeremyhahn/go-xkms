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

//go:build integration && linux

// Package luks exercises go-xkms's production LUKS Executor
// (pkg/luks.LibExecutor) against a real loop device, a real LUKS2 format and
// a real dm-crypt mapping and mount. It needs root (loop device attach,
// dm-crypt, mount) and the kernel keyring, so it runs only in the
// devcontainer via `make integration-test-luks`, never in the unit suite.
package luks

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/luks"
)

const (
	testPassphrase      = "integration-test-passphrase-123!"
	testWrongPassphrase = "wrong-passphrase-456!"
	testVolumeSize      = 64 << 20 // 64 MiB
)

// requireRoot skips the test with an explanatory message when not running
// as root: loop device attach, dm-crypt and mount all require it.
func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("integration test requires root (loop device, dm-crypt, mount); run inside the devcontainer via `make integration-test-luks`")
	}
}

// newTestConfig builds a VolumeConfig rooted in a fresh temp directory, with
// a mapper name unique to this test run so parallel suites never collide on
// /dev/mapper/<name>.
func newTestConfig(t *testing.T) *luks.VolumeConfig {
	t.Helper()
	dir := t.TempDir()
	return &luks.VolumeConfig{
		LUKSPath:   filepath.Join(dir, "vault.luks"),
		MountPoint: filepath.Join(dir, "mnt"),
		MapperName: "xkms-it-" + filepath.Base(dir),
	}
}

// TestLibExecutor_FullLifecycle drives Create -> Unlock -> Mount -> write a
// file -> Unmount -> Lock against real kernel primitives, then proves the
// container file is genuinely encrypted (its header carries the LUKS2
// magic, and the plaintext payload is not findable in the raw file).
func TestLibExecutor_FullLifecycle(t *testing.T) {
	requireRoot(t)

	cfg := newTestConfig(t)
	exec := luks.NewLibExecutor()
	ctx := context.Background()

	require.NoError(t, exec.Create(ctx, cfg, testVolumeSize, testPassphrase))
	assert.True(t, luks.IsLUKSVolume(cfg.LUKSPath), "container must carry the LUKS2 magic header")
	assert.False(t, exec.IsUnlocked(cfg), "Create must leave the volume locked")

	require.NoError(t, exec.Unlock(ctx, cfg, testPassphrase))
	assert.True(t, exec.IsUnlocked(cfg))
	t.Cleanup(func() {
		if exec.IsUnlocked(cfg) {
			_ = exec.Unmount(ctx, cfg)
			_ = exec.Lock(ctx, cfg)
		}
	})

	require.NoError(t, exec.Mount(ctx, cfg))
	mounted, err := luks.IsMounted(cfg.MountPoint)
	require.NoError(t, err)
	assert.True(t, mounted)

	secret := "the quick brown fox jumps over the lazy dog, 1234567890"
	payloadPath := filepath.Join(cfg.MountPoint, "secret.txt")
	require.NoError(t, os.WriteFile(payloadPath, []byte(secret), 0600))

	// The plaintext must not appear anywhere in the raw container file: it
	// is encrypted at rest, not merely access-controlled by the mount.
	raw, err := os.ReadFile(cfg.LUKSPath)
	require.NoError(t, err)
	assert.NotContains(t, string(raw), secret, "plaintext payload must not be recoverable from the raw container file")

	require.NoError(t, exec.Unmount(ctx, cfg))
	mounted, err = luks.IsMounted(cfg.MountPoint)
	require.NoError(t, err)
	assert.False(t, mounted)

	require.NoError(t, exec.Lock(ctx, cfg))
	assert.False(t, exec.IsUnlocked(cfg))

	// Re-unlock and mount to prove the data survived the lock cycle.
	require.NoError(t, exec.Unlock(ctx, cfg, testPassphrase))
	require.NoError(t, exec.Mount(ctx, cfg))
	got, err := os.ReadFile(payloadPath)
	require.NoError(t, err)
	assert.Equal(t, secret, string(got))
	require.NoError(t, exec.Unmount(ctx, cfg))
	require.NoError(t, exec.Lock(ctx, cfg))
}

// TestLibExecutor_WrongPassphraseRefused proves Unlock fails closed against
// a real LUKS2 header when given the wrong passphrase, and leaves no loop
// device or mapping behind.
func TestLibExecutor_WrongPassphraseRefused(t *testing.T) {
	requireRoot(t)

	cfg := newTestConfig(t)
	exec := luks.NewLibExecutor()
	ctx := context.Background()

	require.NoError(t, exec.Create(ctx, cfg, testVolumeSize, testPassphrase))

	err := exec.Unlock(ctx, cfg, testWrongPassphrase)
	require.Error(t, err)
	assert.False(t, exec.IsUnlocked(cfg), "a failed unlock must not leave a mapping behind")
}

// TestLibExecutor_CreateAlreadyExists proves Create refuses a second format
// over an existing container.
func TestLibExecutor_CreateAlreadyExists(t *testing.T) {
	requireRoot(t)

	cfg := newTestConfig(t)
	exec := luks.NewLibExecutor()
	ctx := context.Background()

	require.NoError(t, exec.Create(ctx, cfg, testVolumeSize, testPassphrase))
	err := exec.Create(ctx, cfg, testVolumeSize, testPassphrase)
	require.ErrorIs(t, err, luks.ErrVolumeAlreadyExists)
}

// TestManager_FullLifecycle drives the same real kernel primitives through
// Manager's atomic state machine, within a single long-lived instance (the
// shape Manager is designed for — see docs/luks/architecture.md
// "Manager is per-process, not per-host").
func TestManager_FullLifecycle(t *testing.T) {
	requireRoot(t)

	cfg := newTestConfig(t)
	mgr, err := luks.NewManager(cfg, luks.NewLibExecutor())
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	require.NoError(t, mgr.Create(ctx, testVolumeSize, testPassphrase))
	require.NoError(t, mgr.Unlock(ctx, testPassphrase))
	assert.True(t, mgr.IsUnlocked())
	t.Cleanup(func() {
		if mgr.IsMounted() {
			_ = mgr.Unmount(ctx)
		}
		if mgr.IsUnlocked() {
			_ = mgr.Lock(ctx)
		}
	})

	require.NoError(t, mgr.Mount(ctx))
	assert.True(t, mgr.IsMounted())

	require.ErrorIs(t, mgr.Unlock(ctx, testPassphrase), luks.ErrAlreadyUnlocked)
	require.ErrorIs(t, mgr.Mount(ctx), luks.ErrAlreadyMounted)

	require.NoError(t, mgr.Unmount(ctx))
	require.NoError(t, mgr.Lock(ctx))
	assert.False(t, mgr.IsUnlocked())
	assert.False(t, mgr.IsMounted())
}
