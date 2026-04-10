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

package keybackend

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// mockKeyHandle is a test KeyHandle implementation.
type mockKeyHandle struct {
	credentialID []byte
	algorithm    int
	backendType  types.BackendType
}

func (h *mockKeyHandle) CredentialID() []byte       { return h.credentialID }
func (h *mockKeyHandle) Algorithm() int              { return h.algorithm }
func (h *mockKeyHandle) BackendID() types.BackendType { return h.backendType }

// mockFIDO2Backend is a configurable test backend.
type mockFIDO2Backend struct {
	id   string
	caps FIDO2KeyCapabilities

	generateErr error
	signErr     error
	loadErr     error
	deleteErr   error
	exportErr   error
	importErr   error
	closeErr    error

	// Track calls for verification.
	generateCalled atomic.Int32
	signCalled     atomic.Int32
	loadCalled     atomic.Int32
	deleteCalled   atomic.Int32
	exportCalled   atomic.Int32
	importCalled   atomic.Int32
	closeCalled    atomic.Int32

	mu   sync.RWMutex
	keys map[string]*mockKeyHandle
}

func newMockBackend(id string, caps FIDO2KeyCapabilities) *mockFIDO2Backend {
	return &mockFIDO2Backend{
		id:   id,
		caps: caps,
		keys: make(map[string]*mockKeyHandle),
	}
}

func (m *mockFIDO2Backend) Type() types.BackendType {
	return types.BackendType(m.id)
}

func (m *mockFIDO2Backend) Capabilities() FIDO2KeyCapabilities {
	return m.caps
}

func (m *mockFIDO2Backend) GenerateCredentialKey(algorithm int, credentialID []byte) (KeyHandle, []byte, error) {
	m.generateCalled.Add(1)
	if m.generateErr != nil {
		return nil, nil, m.generateErr
	}
	handle := &mockKeyHandle{
		credentialID: credentialID,
		algorithm:    algorithm,
		backendType:  types.BackendType(m.id),
	}
	m.mu.Lock()
	m.keys[string(credentialID)] = handle
	m.mu.Unlock()
	return handle, []byte("cose-public-key"), nil
}

func (m *mockFIDO2Backend) Sign(handle KeyHandle, algorithm int, data []byte) ([]byte, error) {
	m.signCalled.Add(1)
	if m.signErr != nil {
		return nil, m.signErr
	}
	return []byte("signature-from-" + m.id), nil
}

func (m *mockFIDO2Backend) LoadKey(credentialID []byte, algorithm int) (KeyHandle, error) {
	m.loadCalled.Add(1)
	if m.loadErr != nil {
		return nil, m.loadErr
	}
	m.mu.RLock()
	handle, ok := m.keys[string(credentialID)]
	m.mu.RUnlock()
	if !ok {
		return nil, ErrKeyNotFound
	}
	return handle, nil
}

func (m *mockFIDO2Backend) DeleteKey(handle KeyHandle) error {
	m.deleteCalled.Add(1)
	if m.deleteErr != nil {
		return m.deleteErr
	}
	m.mu.Lock()
	delete(m.keys, string(handle.CredentialID()))
	m.mu.Unlock()
	return nil
}

func (m *mockFIDO2Backend) ExportPrivateKey(handle KeyHandle) ([]byte, error) {
	m.exportCalled.Add(1)
	if m.exportErr != nil {
		return nil, m.exportErr
	}
	return []byte("pkcs8-key-" + m.id), nil
}

func (m *mockFIDO2Backend) ImportPrivateKey(credentialID []byte, algorithm int, pkcs8Key []byte) (KeyHandle, error) {
	m.importCalled.Add(1)
	if m.importErr != nil {
		return nil, m.importErr
	}
	handle := &mockKeyHandle{
		credentialID: credentialID,
		algorithm:    algorithm,
		backendType:  types.BackendType(m.id),
	}
	m.mu.Lock()
	m.keys[string(credentialID)] = handle
	m.mu.Unlock()
	return handle, nil
}

func (m *mockFIDO2Backend) Close() error {
	m.closeCalled.Add(1)
	return m.closeErr
}

func TestCompositeBackend_Type(t *testing.T) {
	cb := NewCompositeBackend(types.BackendTypeSoftware)
	if cb.Type() != BackendTypeComposite {
		t.Errorf("Type() = %q, want %q", cb.Type(), BackendTypeComposite)
	}
}

func TestCompositeBackend_Type_Constant(t *testing.T) {
	if BackendTypeComposite != "composite" {
		t.Errorf("BackendTypeComposite = %q, want %q", BackendTypeComposite, "composite")
	}
}

func TestCompositeBackend_Capabilities_Merged(t *testing.T) {
	cb := NewCompositeBackend(types.BackendTypeSoftware)

	sw := newMockBackend("software", FIDO2KeyCapabilities{
		SupportedAlgorithms: []int{-7, -8},
		SupportsExport:      true,
		SupportsImport:      true,
		HardwareBacked:      false,
	})
	hw := newMockBackend("tpm2", FIDO2KeyCapabilities{
		SupportedAlgorithms:     []int{-7, -35},
		SupportsExport:          false,
		SupportsAttestation:     true,
		HardwareBacked:          true,
		HandlesUserPresence:     true,
		HandlesUserVerification: true,
	})

	cb.Register(types.BackendTypeSoftware, sw)
	cb.Register(types.BackendTypeTPM2, hw)

	caps := cb.Capabilities()

	// Union of algorithms: -7, -8, -35 (no duplicates)
	if len(caps.SupportedAlgorithms) != 3 {
		t.Errorf("SupportedAlgorithms length = %d, want 3", len(caps.SupportedAlgorithms))
	}

	algSet := make(map[int]bool)
	for _, alg := range caps.SupportedAlgorithms {
		algSet[alg] = true
	}
	for _, want := range []int{-7, -8, -35} {
		if !algSet[want] {
			t.Errorf("SupportedAlgorithms missing %d", want)
		}
	}

	if !caps.HardwareBacked {
		t.Error("HardwareBacked should be true (tpm2 is hardware-backed)")
	}
	if !caps.SupportsExport {
		t.Error("SupportsExport should be true (software supports export)")
	}
	if !caps.SupportsImport {
		t.Error("SupportsImport should be true (software supports import)")
	}
	if !caps.SupportsAttestation {
		t.Error("SupportsAttestation should be true (tpm2 supports attestation)")
	}
	if !caps.HandlesUserPresence {
		t.Error("HandlesUserPresence should be true (tpm2 handles user presence)")
	}
	if !caps.HandlesUserVerification {
		t.Error("HandlesUserVerification should be true (tpm2 handles user verification)")
	}
}

func TestCompositeBackend_Capabilities_Empty(t *testing.T) {
	cb := NewCompositeBackend(types.BackendTypeSoftware)
	caps := cb.Capabilities()

	if len(caps.SupportedAlgorithms) != 0 {
		t.Errorf("SupportedAlgorithms should be empty, got %v", caps.SupportedAlgorithms)
	}
	if caps.HardwareBacked {
		t.Error("HardwareBacked should be false with no backends")
	}
}

func TestCompositeBackend_GenerateCredentialKey_RoutesToDefault(t *testing.T) {
	cb := NewCompositeBackend(types.BackendTypeSoftware)

	sw := newMockBackend("software", FIDO2KeyCapabilities{})
	hw := newMockBackend("tpm2", FIDO2KeyCapabilities{})

	cb.Register(types.BackendTypeSoftware, sw)
	cb.Register(types.BackendTypeTPM2, hw)

	credID := []byte("cred-123")
	handle, pubKey, err := cb.GenerateCredentialKey(-7, credID)
	if err != nil {
		t.Fatalf("GenerateCredentialKey() error = %v", err)
	}
	if handle == nil {
		t.Fatal("GenerateCredentialKey() returned nil handle")
	}
	if len(pubKey) == 0 {
		t.Fatal("GenerateCredentialKey() returned empty public key")
	}

	// Verify only the default backend was called.
	if sw.generateCalled.Load() != 1 {
		t.Errorf("software backend generateCalled = %d, want 1", sw.generateCalled.Load())
	}
	if hw.generateCalled.Load() != 0 {
		t.Errorf("tpm2 backend generateCalled = %d, want 0", hw.generateCalled.Load())
	}

	// Handle should report the software backend.
	if handle.BackendID() != types.BackendTypeSoftware {
		t.Errorf("handle.BackendID() = %q, want %q", handle.BackendID(), types.BackendTypeSoftware)
	}
}

func TestCompositeBackend_GenerateCredentialKey_DefaultNotFound(t *testing.T) {
	cb := NewCompositeBackend(types.BackendType("nonexistent"))

	_, _, err := cb.GenerateCredentialKey(-7, []byte("cred-123"))
	if !errors.Is(err, ErrBackendNotFound) {
		t.Errorf("GenerateCredentialKey() error = %v, want %v", err, ErrBackendNotFound)
	}
}

func TestCompositeBackend_Sign_RoutesToBackendID(t *testing.T) {
	cb := NewCompositeBackend(types.BackendTypeSoftware)

	sw := newMockBackend("software", FIDO2KeyCapabilities{})
	hw := newMockBackend("tpm2", FIDO2KeyCapabilities{})

	cb.Register(types.BackendTypeSoftware, sw)
	cb.Register(types.BackendTypeTPM2, hw)

	handle := &mockKeyHandle{
		credentialID: []byte("cred-456"),
		algorithm:    -7,
		backendType:  types.BackendTypeTPM2,
	}

	sig, err := cb.Sign(handle, -7, []byte("data-to-sign"))
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	if string(sig) != "signature-from-tpm2" {
		t.Errorf("Sign() = %q, want %q", string(sig), "signature-from-tpm2")
	}

	// Only tpm2 should have been called.
	if hw.signCalled.Load() != 1 {
		t.Errorf("tpm2 backend signCalled = %d, want 1", hw.signCalled.Load())
	}
	if sw.signCalled.Load() != 0 {
		t.Errorf("software backend signCalled = %d, want 0", sw.signCalled.Load())
	}
}

func TestCompositeBackend_Sign_EmptyBackendID_TriesAll(t *testing.T) {
	cb := NewCompositeBackend(types.BackendTypeSoftware)

	sw := newMockBackend("software", FIDO2KeyCapabilities{})
	sw.signErr = ErrInvalidKeyHandle

	hw := newMockBackend("tpm2", FIDO2KeyCapabilities{})

	cb.Register(types.BackendTypeSoftware, sw)
	cb.Register(types.BackendTypeTPM2, hw)

	handle := &mockKeyHandle{
		credentialID: []byte("cred-789"),
		algorithm:    -7,
		backendType:  "", // empty -- try all
	}

	sig, err := cb.Sign(handle, -7, []byte("data"))
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	if string(sig) != "signature-from-tpm2" {
		t.Errorf("Sign() = %q, want signature from some backend", string(sig))
	}
}

func TestCompositeBackend_Sign_NilHandle(t *testing.T) {
	cb := NewCompositeBackend(types.BackendTypeSoftware)

	_, err := cb.Sign(nil, -7, []byte("data"))
	if !errors.Is(err, ErrInvalidKeyHandle) {
		t.Errorf("Sign(nil) error = %v, want %v", err, ErrInvalidKeyHandle)
	}
}

func TestCompositeBackend_Sign_BackendNotFound(t *testing.T) {
	cb := NewCompositeBackend(types.BackendTypeSoftware)

	handle := &mockKeyHandle{
		credentialID: []byte("cred"),
		algorithm:    -7,
		backendType:  types.BackendType("nonexistent"),
	}

	_, err := cb.Sign(handle, -7, []byte("data"))
	if !errors.Is(err, ErrBackendNotFound) {
		t.Errorf("Sign() error = %v, want %v", err, ErrBackendNotFound)
	}
}

func TestCompositeBackend_LoadKey_TriesAllBackends(t *testing.T) {
	cb := NewCompositeBackend(types.BackendTypeSoftware)

	// Software backend does not have the key.
	sw := newMockBackend("software", FIDO2KeyCapabilities{})

	// TPM2 backend has the key.
	hw := newMockBackend("tpm2", FIDO2KeyCapabilities{})
	credID := []byte("tpm-cred-001")
	hw.mu.Lock()
	hw.keys[string(credID)] = &mockKeyHandle{
		credentialID: credID,
		algorithm:    -7,
		backendType:  types.BackendTypeTPM2,
	}
	hw.mu.Unlock()

	cb.Register(types.BackendTypeSoftware, sw)
	cb.Register(types.BackendTypeTPM2, hw)

	handle, err := cb.LoadKey(credID, -7)
	if err != nil {
		t.Fatalf("LoadKey() error = %v", err)
	}
	if handle.BackendID() != types.BackendTypeTPM2 {
		t.Errorf("LoadKey() handle.BackendID() = %q, want %q", handle.BackendID(), types.BackendTypeTPM2)
	}
}

func TestCompositeBackend_LoadKey_NotFound(t *testing.T) {
	cb := NewCompositeBackend(types.BackendTypeSoftware)

	sw := newMockBackend("software", FIDO2KeyCapabilities{})
	hw := newMockBackend("tpm2", FIDO2KeyCapabilities{})

	cb.Register(types.BackendTypeSoftware, sw)
	cb.Register(types.BackendTypeTPM2, hw)

	_, err := cb.LoadKey([]byte("nonexistent-cred"), -7)
	if !errors.Is(err, ErrKeyNotFound) {
		t.Errorf("LoadKey() error = %v, want %v", err, ErrKeyNotFound)
	}

	// Both backends should have been tried.
	totalCalls := sw.loadCalled.Load() + hw.loadCalled.Load()
	if totalCalls != 2 {
		t.Errorf("total LoadKey calls = %d, want 2", totalCalls)
	}
}

func TestCompositeBackend_LoadKey_PropagatesNonKeyNotFoundError(t *testing.T) {
	cb := NewCompositeBackend(types.BackendTypeSoftware)

	sw := newMockBackend("software", FIDO2KeyCapabilities{})
	sw.loadErr = ErrBackendClosed

	cb.Register(types.BackendTypeSoftware, sw)

	_, err := cb.LoadKey([]byte("cred"), -7)
	if !errors.Is(err, ErrBackendClosed) {
		t.Errorf("LoadKey() error = %v, want %v", err, ErrBackendClosed)
	}
}

func TestCompositeBackend_DeleteKey_RoutesToBackendID(t *testing.T) {
	cb := NewCompositeBackend(types.BackendTypeSoftware)

	sw := newMockBackend("software", FIDO2KeyCapabilities{})
	hw := newMockBackend("tpm2", FIDO2KeyCapabilities{})

	cb.Register(types.BackendTypeSoftware, sw)
	cb.Register(types.BackendTypeTPM2, hw)

	handle := &mockKeyHandle{
		credentialID: []byte("cred-del"),
		algorithm:    -7,
		backendType:  types.BackendTypeSoftware,
	}

	err := cb.DeleteKey(handle)
	if err != nil {
		t.Fatalf("DeleteKey() error = %v", err)
	}

	if sw.deleteCalled.Load() != 1 {
		t.Errorf("software backend deleteCalled = %d, want 1", sw.deleteCalled.Load())
	}
	if hw.deleteCalled.Load() != 0 {
		t.Errorf("tpm2 backend deleteCalled = %d, want 0", hw.deleteCalled.Load())
	}
}

func TestCompositeBackend_DeleteKey_NilHandle(t *testing.T) {
	cb := NewCompositeBackend(types.BackendTypeSoftware)

	err := cb.DeleteKey(nil)
	if !errors.Is(err, ErrInvalidKeyHandle) {
		t.Errorf("DeleteKey(nil) error = %v, want %v", err, ErrInvalidKeyHandle)
	}
}

func TestCompositeBackend_DeleteKey_BackendNotFound(t *testing.T) {
	cb := NewCompositeBackend(types.BackendTypeSoftware)

	handle := &mockKeyHandle{
		credentialID: []byte("cred"),
		algorithm:    -7,
		backendType:  types.BackendType("nonexistent"),
	}

	err := cb.DeleteKey(handle)
	if !errors.Is(err, ErrBackendNotFound) {
		t.Errorf("DeleteKey() error = %v, want %v", err, ErrBackendNotFound)
	}
}

func TestCompositeBackend_ExportPrivateKey_NotSupported(t *testing.T) {
	cb := NewCompositeBackend(types.BackendTypeTPM2)

	hw := newMockBackend("tpm2", FIDO2KeyCapabilities{
		HardwareBacked: true,
		SupportsExport: false,
	})
	hw.exportErr = ErrExportNotSupported

	cb.Register(types.BackendTypeTPM2, hw)

	handle := &mockKeyHandle{
		credentialID: []byte("cred-hw"),
		algorithm:    -7,
		backendType:  types.BackendTypeTPM2,
	}

	_, err := cb.ExportPrivateKey(handle)
	if !errors.Is(err, ErrExportNotSupported) {
		t.Errorf("ExportPrivateKey() error = %v, want %v", err, ErrExportNotSupported)
	}
	if hw.exportCalled.Load() != 1 {
		t.Errorf("tpm2 backend exportCalled = %d, want 1", hw.exportCalled.Load())
	}
}

func TestCompositeBackend_ExportPrivateKey_Success(t *testing.T) {
	cb := NewCompositeBackend(types.BackendTypeSoftware)

	sw := newMockBackend("software", FIDO2KeyCapabilities{
		SupportsExport: true,
	})
	cb.Register(types.BackendTypeSoftware, sw)

	handle := &mockKeyHandle{
		credentialID: []byte("cred-export"),
		algorithm:    -7,
		backendType:  types.BackendTypeSoftware,
	}

	data, err := cb.ExportPrivateKey(handle)
	if err != nil {
		t.Fatalf("ExportPrivateKey() error = %v", err)
	}
	if string(data) != "pkcs8-key-software" {
		t.Errorf("ExportPrivateKey() = %q, want %q", string(data), "pkcs8-key-software")
	}
}

func TestCompositeBackend_ExportPrivateKey_NilHandle(t *testing.T) {
	cb := NewCompositeBackend(types.BackendTypeSoftware)

	_, err := cb.ExportPrivateKey(nil)
	if !errors.Is(err, ErrInvalidKeyHandle) {
		t.Errorf("ExportPrivateKey(nil) error = %v, want %v", err, ErrInvalidKeyHandle)
	}
}

func TestCompositeBackend_ExportPrivateKey_BackendNotFound(t *testing.T) {
	cb := NewCompositeBackend(types.BackendTypeSoftware)

	handle := &mockKeyHandle{
		credentialID: []byte("cred"),
		algorithm:    -7,
		backendType:  types.BackendType("nonexistent"),
	}

	_, err := cb.ExportPrivateKey(handle)
	if !errors.Is(err, ErrBackendNotFound) {
		t.Errorf("ExportPrivateKey() error = %v, want %v", err, ErrBackendNotFound)
	}
}

func TestCompositeBackend_ImportPrivateKey_RoutesToDefault(t *testing.T) {
	cb := NewCompositeBackend(types.BackendTypeSoftware)

	sw := newMockBackend("software", FIDO2KeyCapabilities{SupportsImport: true})
	hw := newMockBackend("tpm2", FIDO2KeyCapabilities{})

	cb.Register(types.BackendTypeSoftware, sw)
	cb.Register(types.BackendTypeTPM2, hw)

	handle, err := cb.ImportPrivateKey([]byte("cred-import"), -7, []byte("pkcs8-data"))
	if err != nil {
		t.Fatalf("ImportPrivateKey() error = %v", err)
	}
	if handle.BackendID() != types.BackendTypeSoftware {
		t.Errorf("handle.BackendID() = %q, want %q", handle.BackendID(), types.BackendTypeSoftware)
	}

	if sw.importCalled.Load() != 1 {
		t.Errorf("software backend importCalled = %d, want 1", sw.importCalled.Load())
	}
	if hw.importCalled.Load() != 0 {
		t.Errorf("tpm2 backend importCalled = %d, want 0", hw.importCalled.Load())
	}
}

func TestCompositeBackend_ImportPrivateKey_DefaultNotFound(t *testing.T) {
	cb := NewCompositeBackend(types.BackendType("nonexistent"))

	_, err := cb.ImportPrivateKey([]byte("cred"), -7, []byte("key"))
	if !errors.Is(err, ErrBackendNotFound) {
		t.Errorf("ImportPrivateKey() error = %v, want %v", err, ErrBackendNotFound)
	}
}

func TestCompositeBackend_Close_ClosesAll(t *testing.T) {
	cb := NewCompositeBackend(types.BackendTypeSoftware)

	sw := newMockBackend("software", FIDO2KeyCapabilities{})
	hw := newMockBackend("tpm2", FIDO2KeyCapabilities{})

	cb.Register(types.BackendTypeSoftware, sw)
	cb.Register(types.BackendTypeTPM2, hw)

	err := cb.Close()
	if err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	if sw.closeCalled.Load() != 1 {
		t.Errorf("software backend closeCalled = %d, want 1", sw.closeCalled.Load())
	}
	if hw.closeCalled.Load() != 1 {
		t.Errorf("tpm2 backend closeCalled = %d, want 1", hw.closeCalled.Load())
	}
}

func TestCompositeBackend_Close_ReturnsFirstError(t *testing.T) {
	cb := NewCompositeBackend(types.BackendTypeSoftware)

	errClose := errors.New("close failed")
	sw := newMockBackend("software", FIDO2KeyCapabilities{})
	sw.closeErr = errClose

	hw := newMockBackend("tpm2", FIDO2KeyCapabilities{})

	cb.Register(types.BackendTypeSoftware, sw)
	cb.Register(types.BackendTypeTPM2, hw)

	err := cb.Close()
	if err == nil {
		t.Fatal("Close() should return an error")
	}
	// Both backends should still be closed.
	if sw.closeCalled.Load() != 1 {
		t.Errorf("software backend closeCalled = %d, want 1", sw.closeCalled.Load())
	}
	if hw.closeCalled.Load() != 1 {
		t.Errorf("tpm2 backend closeCalled = %d, want 1", hw.closeCalled.Load())
	}
}

func TestCompositeBackend_Register_Unregister(t *testing.T) {
	cb := NewCompositeBackend(types.BackendTypeSoftware)

	sw := newMockBackend("software", FIDO2KeyCapabilities{
		SupportedAlgorithms: []int{-7},
	})

	// Register and verify.
	cb.Register(types.BackendTypeSoftware, sw)
	if b := cb.Backend(types.BackendTypeSoftware); b == nil {
		t.Fatal("Backend(types.BackendTypeSoftware) should not be nil after Register")
	}

	backends := cb.Backends()
	if len(backends) != 1 {
		t.Errorf("Backends() length = %d, want 1", len(backends))
	}

	// Unregister and verify.
	cb.Unregister(types.BackendTypeSoftware)
	if b := cb.Backend(types.BackendTypeSoftware); b != nil {
		t.Error("Backend(types.BackendTypeSoftware) should be nil after Unregister")
	}

	backends = cb.Backends()
	if len(backends) != 0 {
		t.Errorf("Backends() length = %d, want 0", len(backends))
	}

	// Operations should fail after unregister.
	_, _, err := cb.GenerateCredentialKey(-7, []byte("cred"))
	if !errors.Is(err, ErrBackendNotFound) {
		t.Errorf("GenerateCredentialKey() error = %v, want %v", err, ErrBackendNotFound)
	}
}

func TestCompositeBackend_SetDefault(t *testing.T) {
	cb := NewCompositeBackend(types.BackendTypeSoftware)

	sw := newMockBackend("software", FIDO2KeyCapabilities{})
	hw := newMockBackend("tpm2", FIDO2KeyCapabilities{})

	cb.Register(types.BackendTypeSoftware, sw)
	cb.Register(types.BackendTypeTPM2, hw)

	// Change default to tpm2.
	cb.SetDefault(types.BackendTypeTPM2)

	credID := []byte("cred-new-default")
	handle, _, err := cb.GenerateCredentialKey(-7, credID)
	if err != nil {
		t.Fatalf("GenerateCredentialKey() error = %v", err)
	}
	if handle.BackendID() != types.BackendTypeTPM2 {
		t.Errorf("handle.BackendID() = %q, want %q", handle.BackendID(), types.BackendTypeTPM2)
	}
	if hw.generateCalled.Load() != 1 {
		t.Errorf("tpm2 backend generateCalled = %d, want 1", hw.generateCalled.Load())
	}
	if sw.generateCalled.Load() != 0 {
		t.Errorf("software backend generateCalled = %d, want 0", sw.generateCalled.Load())
	}
}

func TestCompositeBackend_Backend_NotFound(t *testing.T) {
	cb := NewCompositeBackend(types.BackendTypeSoftware)
	if b := cb.Backend(types.BackendType("nonexistent")); b != nil {
		t.Error("Backend(\"nonexistent\") should return nil")
	}
}

func TestCompositeBackend_Sign_EmptyBackendID_AllFail(t *testing.T) {
	cb := NewCompositeBackend(types.BackendTypeSoftware)

	sw := newMockBackend("software", FIDO2KeyCapabilities{})
	sw.signErr = ErrInvalidKeyHandle

	hw := newMockBackend("tpm2", FIDO2KeyCapabilities{})
	hw.signErr = ErrSigningFailed

	cb.Register(types.BackendTypeSoftware, sw)
	cb.Register(types.BackendTypeTPM2, hw)

	handle := &mockKeyHandle{
		credentialID: []byte("cred"),
		algorithm:    -7,
		backendType:  "",
	}

	_, err := cb.Sign(handle, -7, []byte("data"))
	if err == nil {
		t.Fatal("Sign() should return an error when all backends fail")
	}
}

func TestCompositeBackend_Sign_NoBackends_EmptyBackendID(t *testing.T) {
	cb := NewCompositeBackend(types.BackendTypeSoftware)

	handle := &mockKeyHandle{
		credentialID: []byte("cred"),
		algorithm:    -7,
		backendType:  "",
	}

	_, err := cb.Sign(handle, -7, []byte("data"))
	if !errors.Is(err, ErrBackendNotFound) {
		t.Errorf("Sign() error = %v, want %v", err, ErrBackendNotFound)
	}
}

func TestCompositeBackend_LoadKey_EmptyComposite(t *testing.T) {
	cb := NewCompositeBackend(types.BackendTypeSoftware)

	_, err := cb.LoadKey([]byte("cred"), -7)
	if !errors.Is(err, ErrKeyNotFound) {
		t.Errorf("LoadKey() error = %v, want %v", err, ErrKeyNotFound)
	}
}

func TestCompositeBackend_GenerateCredentialKey_BackendError(t *testing.T) {
	cb := NewCompositeBackend(types.BackendTypeSoftware)

	sw := newMockBackend("software", FIDO2KeyCapabilities{})
	sw.generateErr = ErrUnsupportedAlgorithm

	cb.Register(types.BackendTypeSoftware, sw)

	_, _, err := cb.GenerateCredentialKey(-999, []byte("cred"))
	if !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Errorf("GenerateCredentialKey() error = %v, want %v", err, ErrUnsupportedAlgorithm)
	}
}

// TestCompositeBackend_InterfaceCompliance verifies that CompositeBackend
// satisfies the FIDO2KeyBackend interface at compile time.
func TestCompositeBackend_InterfaceCompliance(t *testing.T) {
	var _ FIDO2KeyBackend = (*CompositeBackend)(nil)
}

func TestCompositeBackend_DefaultID(t *testing.T) {
	cb := NewCompositeBackend(types.BackendTypeSoftware)

	sw := newMockBackend("software", FIDO2KeyCapabilities{})
	hw := newMockBackend("tpm2", FIDO2KeyCapabilities{})

	cb.Register(types.BackendTypeSoftware, sw)
	cb.Register(types.BackendTypeTPM2, hw)

	// DefaultID returns the initial default set in NewCompositeBackend.
	if got := cb.DefaultID(); got != types.BackendTypeSoftware {
		t.Errorf("DefaultID() = %q, want %q", got, types.BackendTypeSoftware)
	}

	// After SetDefault, DefaultID returns the new value.
	cb.SetDefault(types.BackendTypeTPM2)
	if got := cb.DefaultID(); got != types.BackendTypeTPM2 {
		t.Errorf("DefaultID() after SetDefault(types.BackendTypeTPM2) = %q, want %q", got, types.BackendTypeTPM2)
	}

	// Setting default to a non-registered backend still updates the value.
	// (Validation happens at operation time, not at SetDefault time.)
	cb.SetDefault(types.BackendType("nonexistent"))
	if got := cb.DefaultID(); got != types.BackendType("nonexistent") {
		t.Errorf("DefaultID() after SetDefault(\"nonexistent\") = %q, want %q", got, types.BackendType("nonexistent"))
	}
}
