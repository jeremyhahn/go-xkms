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
	"context"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/crypto/fips"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockExecutor is a lightweight Executor for unit testing that records calls
// and returns pre-configured errors.
type mockExecutor struct {
	createErr  error
	unlockErr  error
	lockErr    error
	isMounted  bool
	isUnlocked bool

	createCalled  bool
	unlockCalled  bool
	lockCalled    bool
	lastSizeBytes int64
}

func (m *mockExecutor) Create(_ context.Context, _ *VolumeConfig, sizeBytes int64, _ string) error {
	m.createCalled = true
	m.lastSizeBytes = sizeBytes
	return m.createErr
}

func (m *mockExecutor) Unlock(_ context.Context, _ *VolumeConfig, _ string) error {
	m.unlockCalled = true
	return m.unlockErr
}

func (m *mockExecutor) Lock(_ context.Context, _ *VolumeConfig) error {
	m.lockCalled = true
	return m.lockErr
}

func (m *mockExecutor) IsMounted(_ *VolumeConfig) bool {
	return m.isMounted
}

func (m *mockExecutor) IsUnlocked(_ *VolumeConfig) bool {
	return m.isUnlocked
}

// validConfig returns a VolumeConfig with all required fields populated.
func validConfig() *VolumeConfig {
	return &VolumeConfig{
		LUKSPath:   "/tmp/test.luks",
		MountPoint: "/mnt/test",
		MapperName: "xkms-test",
	}
}

// --- NewManager ---

func TestNewManager_Success(t *testing.T) {
	t.Setenv(fips.EnvGOFIPS140, "")
	mgr, err := NewManager(validConfig(), &mockExecutor{})
	require.NoError(t, err)
	require.NotNil(t, mgr)
	assert.Equal(t, KDFArgon2id, mgr.Config().KDF)
	assert.Equal(t, 2000, mgr.Config().PBKDFIterTime)
}

func TestNewManager_InvalidConfig(t *testing.T) {
	cfg := &VolumeConfig{} // all fields empty
	mgr, err := NewManager(cfg, &mockExecutor{})
	require.Error(t, err)
	assert.Nil(t, mgr)
	assert.ErrorIs(t, err, ErrInvalidConfig)
}

func TestNewManager_NilExecutor(t *testing.T) {
	mgr, err := NewManager(validConfig(), nil)
	require.Error(t, err)
	assert.Nil(t, mgr)
	assert.ErrorIs(t, err, ErrNilExecutor)
}

func TestNewManager_InvalidKDFInConfig(t *testing.T) {
	cfg := validConfig()
	cfg.KDF = "bcrypt"
	mgr, err := NewManager(cfg, &mockExecutor{})
	require.Error(t, err)
	assert.Nil(t, mgr)
	assert.ErrorIs(t, err, ErrInvalidKDF)
}

// --- NewFIPSAwareManager ---

func TestNewFIPSAwareManager_Standard(t *testing.T) {
	t.Setenv(fips.EnvGOFIPS140, "")
	mgr, err := NewFIPSAwareManager("/tmp/vol.luks", "/mnt/vol", "xkms-vol", &mockExecutor{})
	require.NoError(t, err)
	require.NotNil(t, mgr)
	assert.Equal(t, KDFArgon2id, mgr.Config().KDF)
}

func TestNewFIPSAwareManager_FIPS(t *testing.T) {
	t.Setenv(fips.EnvGOFIPS140, "v1.0.0")
	mgr, err := NewFIPSAwareManager("/tmp/vol.luks", "/mnt/vol", "xkms-vol", &mockExecutor{})
	require.NoError(t, err)
	require.NotNil(t, mgr)
	assert.Equal(t, KDFPBKDF2, mgr.Config().KDF)
}

func TestNewFIPSAwareManager_NilExecutor(t *testing.T) {
	mgr, err := NewFIPSAwareManager("/tmp/vol.luks", "/mnt/vol", "xkms-vol", nil)
	require.Error(t, err)
	assert.Nil(t, mgr)
	assert.ErrorIs(t, err, ErrNilExecutor)
}

func TestNewFIPSAwareManager_EmptyPath(t *testing.T) {
	mgr, err := NewFIPSAwareManager("", "/mnt/vol", "xkms-vol", &mockExecutor{})
	require.Error(t, err)
	assert.Nil(t, mgr)
	assert.ErrorIs(t, err, ErrInvalidConfig)
}

// --- Create ---

func TestCreate_Success(t *testing.T) {
	exec := &mockExecutor{}
	mgr, err := NewManager(validConfig(), exec)
	require.NoError(t, err)

	err = mgr.Create(context.Background(), 1<<30, "strongpassphrase")
	require.NoError(t, err)
	assert.True(t, exec.createCalled)
	assert.Equal(t, int64(1<<30), exec.lastSizeBytes)
}

func TestCreate_EmptyPassphrase(t *testing.T) {
	exec := &mockExecutor{}
	mgr, err := NewManager(validConfig(), exec)
	require.NoError(t, err)

	err = mgr.Create(context.Background(), 1<<30, "")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrEmptyPassphrase)
	assert.False(t, exec.createCalled)
}

func TestCreate_InvalidSize_Zero(t *testing.T) {
	exec := &mockExecutor{}
	mgr, err := NewManager(validConfig(), exec)
	require.NoError(t, err)

	err = mgr.Create(context.Background(), 0, "passphrase")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidSize)
	assert.False(t, exec.createCalled)
}

func TestCreate_InvalidSize_Negative(t *testing.T) {
	exec := &mockExecutor{}
	mgr, err := NewManager(validConfig(), exec)
	require.NoError(t, err)

	err = mgr.Create(context.Background(), -1, "passphrase")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidSize)
	assert.False(t, exec.createCalled)
}

func TestCreate_ExecutorError(t *testing.T) {
	execErr := errors.New("disk full")
	exec := &mockExecutor{createErr: execErr}
	mgr, err := NewManager(validConfig(), exec)
	require.NoError(t, err)

	err = mgr.Create(context.Background(), 1<<30, "passphrase")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrOperationFailed)
	assert.ErrorIs(t, err, execErr)
	assert.True(t, exec.createCalled)
}

// --- Unlock ---

func TestUnlock_Success(t *testing.T) {
	exec := &mockExecutor{}
	mgr, err := NewManager(validConfig(), exec)
	require.NoError(t, err)

	err = mgr.Unlock(context.Background(), "passphrase")
	require.NoError(t, err)
	assert.True(t, exec.unlockCalled)
	assert.True(t, mgr.IsUnlocked())
}

func TestUnlock_EmptyPassphrase(t *testing.T) {
	exec := &mockExecutor{}
	mgr, err := NewManager(validConfig(), exec)
	require.NoError(t, err)

	err = mgr.Unlock(context.Background(), "")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrEmptyPassphrase)
	assert.False(t, exec.unlockCalled)
	assert.False(t, mgr.IsUnlocked())
}

func TestUnlock_ExecutorError(t *testing.T) {
	execErr := errors.New("wrong passphrase")
	exec := &mockExecutor{unlockErr: execErr}
	mgr, err := NewManager(validConfig(), exec)
	require.NoError(t, err)

	err = mgr.Unlock(context.Background(), "badpass")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrOperationFailed)
	assert.ErrorIs(t, err, execErr)
	assert.True(t, exec.unlockCalled)
	assert.False(t, mgr.IsUnlocked(),
		"state must not be set when executor fails")
}

// --- Lock ---

func TestLock_Success(t *testing.T) {
	exec := &mockExecutor{}
	mgr, err := NewManager(validConfig(), exec)
	require.NoError(t, err)

	// Unlock first, then lock.
	require.NoError(t, mgr.Unlock(context.Background(), "passphrase"))
	assert.True(t, mgr.IsUnlocked())

	err = mgr.Lock(context.Background())
	require.NoError(t, err)
	assert.True(t, exec.lockCalled)
	assert.False(t, mgr.IsUnlocked())
	assert.False(t, mgr.IsMounted())
}

func TestLock_ExecutorError(t *testing.T) {
	execErr := errors.New("device busy")
	exec := &mockExecutor{lockErr: execErr}
	mgr, err := NewManager(validConfig(), exec)
	require.NoError(t, err)

	err = mgr.Lock(context.Background())
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrOperationFailed)
	assert.ErrorIs(t, err, execErr)
	assert.True(t, exec.lockCalled)
}

// --- State accessors ---

func TestIsMounted_InitiallyFalse(t *testing.T) {
	mgr, err := NewManager(validConfig(), &mockExecutor{})
	require.NoError(t, err)
	assert.False(t, mgr.IsMounted())
}

func TestIsUnlocked_InitiallyFalse(t *testing.T) {
	mgr, err := NewManager(validConfig(), &mockExecutor{})
	require.NoError(t, err)
	assert.False(t, mgr.IsUnlocked())
}

func TestIsMounted_IsUnlocked_StateTracking(t *testing.T) {
	exec := &mockExecutor{}
	mgr, err := NewManager(validConfig(), exec)
	require.NoError(t, err)

	assert.False(t, mgr.IsMounted())
	assert.False(t, mgr.IsUnlocked())

	require.NoError(t, mgr.Unlock(context.Background(), "pass"))
	assert.True(t, mgr.IsUnlocked())

	require.NoError(t, mgr.Lock(context.Background()))
	assert.False(t, mgr.IsUnlocked())
	assert.False(t, mgr.IsMounted())
}

// --- Config ---

func TestConfig_ReturnsCopy(t *testing.T) {
	t.Setenv(fips.EnvGOFIPS140, "")
	cfg := validConfig()
	mgr, err := NewManager(cfg, &mockExecutor{})
	require.NoError(t, err)

	returned := mgr.Config()
	assert.Equal(t, cfg.LUKSPath, returned.LUKSPath)
	assert.Equal(t, cfg.MountPoint, returned.MountPoint)
	assert.Equal(t, cfg.MapperName, returned.MapperName)
	assert.Equal(t, KDFArgon2id, returned.KDF)
	assert.Equal(t, 2000, returned.PBKDFIterTime)

	// Mutating the returned copy must not affect the manager.
	returned.LUKSPath = "/changed"
	assert.NotEqual(t, returned.LUKSPath, mgr.Config().LUKSPath)
}
