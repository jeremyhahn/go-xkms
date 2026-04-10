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
)

// mockVolumeOperator is a test double for VolumeOperator that uses a temp
// directory as its mount point so the file storage delegate works without
// any real LUKS operations or root privileges.
type mockVolumeOperator struct {
	mountPoint string
	exists     bool
	isLUKS     bool
	isMounted  bool
	isOpen     bool
	created    bool
	unlocked   bool

	createErr error
	unlockErr error
	lockErr   error
}

func newMockVolumeOperator(mountPoint string) *mockVolumeOperator {
	return &mockVolumeOperator{
		mountPoint: mountPoint,
		exists:     true,
		isLUKS:     true,
	}
}

func (m *mockVolumeOperator) Exists() bool          { return m.exists }
func (m *mockVolumeOperator) IsLUKS() bool          { return m.isLUKS }
func (m *mockVolumeOperator) IsMounted() bool       { return m.isMounted }
func (m *mockVolumeOperator) IsOpen() bool          { return m.isOpen }
func (m *mockVolumeOperator) GetMountPoint() string { return m.mountPoint }

func (m *mockVolumeOperator) Create(sizeBytes int64, passphrase string) error {
	if m.createErr != nil {
		return m.createErr
	}
	m.created = true
	m.exists = true
	return nil
}

func (m *mockVolumeOperator) Unlock(passphrase string) error {
	if m.unlockErr != nil {
		return m.unlockErr
	}
	m.unlocked = true
	m.isOpen = true
	m.isMounted = true
	return nil
}

func (m *mockVolumeOperator) Lock() error {
	if m.lockErr != nil {
		return m.lockErr
	}
	m.unlocked = false
	m.isOpen = false
	m.isMounted = false
	return nil
}

func TestNewBackend(t *testing.T) {
	mock := newMockVolumeOperator(t.TempDir())
	b := NewBackend(mock)

	if b == nil {
		t.Fatal("expected non-nil backend")
	}
	if b.IsUnlocked() {
		t.Error("new backend should start in locked state")
	}
}

func TestGet_Locked_ReturnsError(t *testing.T) {
	mock := newMockVolumeOperator(t.TempDir())
	b := NewBackend(mock)

	_, err := b.Get(context.Background(), "test-key")
	if !errors.Is(err, ErrVolumeLocked) {
		t.Errorf("expected ErrVolumeLocked, got %v", err)
	}
}

func TestPut_Locked_ReturnsError(t *testing.T) {
	mock := newMockVolumeOperator(t.TempDir())
	b := NewBackend(mock)

	err := b.Put(context.Background(), "test-key", []byte("value"))
	if !errors.Is(err, ErrVolumeLocked) {
		t.Errorf("expected ErrVolumeLocked, got %v", err)
	}
}

func TestDelete_Locked_ReturnsError(t *testing.T) {
	mock := newMockVolumeOperator(t.TempDir())
	b := NewBackend(mock)

	err := b.Delete(context.Background(), "test-key")
	if !errors.Is(err, ErrVolumeLocked) {
		t.Errorf("expected ErrVolumeLocked, got %v", err)
	}
}

func TestList_Locked_ReturnsError(t *testing.T) {
	mock := newMockVolumeOperator(t.TempDir())
	b := NewBackend(mock)

	_, err := b.List(context.Background(), "")
	if !errors.Is(err, ErrVolumeLocked) {
		t.Errorf("expected ErrVolumeLocked, got %v", err)
	}
}

func TestExists_Locked_ReturnsError(t *testing.T) {
	mock := newMockVolumeOperator(t.TempDir())
	b := NewBackend(mock)

	_, err := b.Exists(context.Background(), "test-key")
	if !errors.Is(err, ErrVolumeLocked) {
		t.Errorf("expected ErrVolumeLocked, got %v", err)
	}
}

func TestInitialize_CreatesAndUnlocks(t *testing.T) {
	tmpDir := t.TempDir()
	mock := newMockVolumeOperator(tmpDir)
	mock.exists = false
	b := NewBackend(mock)

	err := b.Initialize(64*1024*1024, "test-passphrase")
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	if !mock.created {
		t.Error("expected volume Create to be called")
	}
	if !b.IsUnlocked() {
		t.Error("expected backend to be unlocked after Initialize")
	}

	// Verify storage operations work.
	err = b.Put(context.Background(), "init-key", []byte("init-value"))
	if err != nil {
		t.Fatalf("Put after Initialize failed: %v", err)
	}

	data, err := b.Get(context.Background(), "init-key")
	if err != nil {
		t.Fatalf("Get after Initialize failed: %v", err)
	}
	if string(data) != "init-value" {
		t.Errorf("expected 'init-value', got %q", string(data))
	}
}

func TestUnlock_Success(t *testing.T) {
	tmpDir := t.TempDir()
	mock := newMockVolumeOperator(tmpDir)
	b := NewBackend(mock)

	err := b.Unlock("test-passphrase")
	if err != nil {
		t.Fatalf("Unlock failed: %v", err)
	}

	if !b.IsUnlocked() {
		t.Error("expected backend to be unlocked")
	}

	// Put and Get should work.
	err = b.Put(context.Background(), "hello", []byte("world"))
	if err != nil {
		t.Fatalf("Put after Unlock failed: %v", err)
	}

	data, err := b.Get(context.Background(), "hello")
	if err != nil {
		t.Fatalf("Get after Unlock failed: %v", err)
	}
	if string(data) != "world" {
		t.Errorf("expected 'world', got %q", string(data))
	}

	// List should return the key.
	keys, err := b.List(context.Background(), "")
	if err != nil {
		t.Fatalf("List after Unlock failed: %v", err)
	}
	if len(keys) != 1 || keys[0] != "hello" {
		t.Errorf("expected [hello], got %v", keys)
	}

	// Exists should return true.
	exists, err := b.Exists(context.Background(), "hello")
	if err != nil {
		t.Fatalf("Exists after Unlock failed: %v", err)
	}
	if !exists {
		t.Error("expected key 'hello' to exist")
	}

	// Delete should work.
	err = b.Delete(context.Background(), "hello")
	if err != nil {
		t.Fatalf("Delete after Unlock failed: %v", err)
	}

	exists, err = b.Exists(context.Background(), "hello")
	if err != nil {
		t.Fatalf("Exists after Delete failed: %v", err)
	}
	if exists {
		t.Error("expected key 'hello' to not exist after Delete")
	}
}

func TestUnlock_AlreadyUnlocked(t *testing.T) {
	tmpDir := t.TempDir()
	mock := newMockVolumeOperator(tmpDir)
	b := NewBackend(mock)

	err := b.Unlock("test-passphrase")
	if err != nil {
		t.Fatalf("first Unlock failed: %v", err)
	}

	err = b.Unlock("test-passphrase")
	if !errors.Is(err, ErrVolumeAlreadyUnlocked) {
		t.Errorf("expected ErrVolumeAlreadyUnlocked, got %v", err)
	}
}

func TestUnlock_VolumeNotInitialized(t *testing.T) {
	tmpDir := t.TempDir()
	mock := newMockVolumeOperator(tmpDir)
	mock.exists = false
	b := NewBackend(mock)

	err := b.Unlock("test-passphrase")
	if !errors.Is(err, ErrVolumeNotInitialized) {
		t.Errorf("expected ErrVolumeNotInitialized, got %v", err)
	}
}

func TestUnlock_VolumeUnlockFails(t *testing.T) {
	tmpDir := t.TempDir()
	mock := newMockVolumeOperator(tmpDir)
	mock.unlockErr = errors.New("unlock failed")
	b := NewBackend(mock)

	err := b.Unlock("test-passphrase")
	if err == nil {
		t.Fatal("expected error from Unlock when volume unlock fails")
	}
	if b.IsUnlocked() {
		t.Error("backend should remain locked after failed Unlock")
	}
}

func TestLock_ClosesDelegate(t *testing.T) {
	tmpDir := t.TempDir()
	mock := newMockVolumeOperator(tmpDir)
	b := NewBackend(mock)

	err := b.Unlock("test-passphrase")
	if err != nil {
		t.Fatalf("Unlock failed: %v", err)
	}

	// Put a key while unlocked.
	err = b.Put(context.Background(), "before-lock", []byte("data"))
	if err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	// Lock.
	err = b.Lock()
	if err != nil {
		t.Fatalf("Lock failed: %v", err)
	}

	if b.IsUnlocked() {
		t.Error("expected backend to be locked after Lock")
	}

	// Storage operations should fail.
	_, err = b.Get(context.Background(), "before-lock")
	if !errors.Is(err, ErrVolumeLocked) {
		t.Errorf("expected ErrVolumeLocked after Lock, got %v", err)
	}
}

func TestLock_AlreadyLocked(t *testing.T) {
	mock := newMockVolumeOperator(t.TempDir())
	b := NewBackend(mock)

	err := b.Lock()
	if !errors.Is(err, ErrVolumeLocked) {
		t.Errorf("expected ErrVolumeLocked when locking already-locked backend, got %v", err)
	}
}

func TestLock_VolumeLockFails(t *testing.T) {
	tmpDir := t.TempDir()
	mock := newMockVolumeOperator(tmpDir)
	b := NewBackend(mock)

	err := b.Unlock("test-passphrase")
	if err != nil {
		t.Fatalf("Unlock failed: %v", err)
	}

	mock.lockErr = errors.New("lock failed")

	err = b.Lock()
	if !errors.Is(err, ErrVolumeLockFailed) {
		t.Errorf("expected ErrVolumeLockFailed, got %v", err)
	}
}

func TestClose_LocksVolume(t *testing.T) {
	tmpDir := t.TempDir()
	mock := newMockVolumeOperator(tmpDir)
	b := NewBackend(mock)

	err := b.Unlock("test-passphrase")
	if err != nil {
		t.Fatalf("Unlock failed: %v", err)
	}

	err = b.Close()
	if err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	if b.IsUnlocked() {
		t.Error("expected backend to be locked after Close")
	}

	// Operations should fail after Close.
	_, err = b.Get(context.Background(), "test-key")
	if !errors.Is(err, ErrVolumeLocked) {
		t.Errorf("expected ErrVolumeLocked after Close, got %v", err)
	}
}

func TestClose_AlreadyLocked_NoOp(t *testing.T) {
	mock := newMockVolumeOperator(t.TempDir())
	b := NewBackend(mock)

	err := b.Close()
	if err != nil {
		t.Errorf("Close on already-locked backend should be no-op, got %v", err)
	}
}

func TestInitialize_EmptyPassphrase_ReturnsError(t *testing.T) {
	mock := newMockVolumeOperator(t.TempDir())
	b := NewBackend(mock)

	err := b.Initialize(64*1024*1024, "")
	if !errors.Is(err, ErrInitializeRequiresPassphrase) {
		t.Errorf("expected ErrInitializeRequiresPassphrase, got %v", err)
	}
}

func TestInitialize_VolumeCreateFails_ReturnsError(t *testing.T) {
	mock := newMockVolumeOperator(t.TempDir())
	mock.createErr = errors.New("create failed")
	b := NewBackend(mock)

	err := b.Initialize(64*1024*1024, "test-passphrase")
	if err == nil {
		t.Fatal("expected error when volume Create fails")
	}
	if b.IsUnlocked() {
		t.Error("backend should remain locked after failed Initialize")
	}
}

func TestUnlock_DelegateCreateFails(t *testing.T) {
	// Use an invalid mount point to force filestorage.New to fail.
	mock := newMockVolumeOperator("")
	b := NewBackend(mock)

	err := b.Unlock("test-passphrase")
	if !errors.Is(err, ErrDelegateCreateFailed) {
		t.Errorf("expected ErrDelegateCreateFailed, got %v", err)
	}
	if b.IsUnlocked() {
		t.Error("backend should remain locked when delegate creation fails")
	}
}

func TestIsUnlocked_ReflectsState(t *testing.T) {
	tmpDir := t.TempDir()
	mock := newMockVolumeOperator(tmpDir)
	b := NewBackend(mock)

	if b.IsUnlocked() {
		t.Error("new backend should not be unlocked")
	}

	err := b.Unlock("test-passphrase")
	if err != nil {
		t.Fatalf("Unlock failed: %v", err)
	}

	if !b.IsUnlocked() {
		t.Error("backend should be unlocked after Unlock")
	}

	err = b.Lock()
	if err != nil {
		t.Fatalf("Lock failed: %v", err)
	}

	if b.IsUnlocked() {
		t.Error("backend should be locked after Lock")
	}
}
