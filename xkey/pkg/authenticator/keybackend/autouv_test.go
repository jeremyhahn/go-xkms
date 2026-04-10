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
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// mockBarrierProvider is a test BarrierStateProvider with configurable state.
type mockBarrierProvider struct {
	active bool
}

func (m *mockBarrierProvider) IsAutoUVActive() bool {
	return m.active
}

// --- NewAutoUVBackend ---

func TestNewAutoUVBackend_ReturnsNonNil(t *testing.T) {
	inner := newMockBackend("software", FIDO2KeyCapabilities{})
	provider := &mockBarrierProvider{active: true}

	backend := NewAutoUVBackend(inner, provider)
	if backend == nil {
		t.Fatal("NewAutoUVBackend() returned nil")
	}
	if backend.inner != inner {
		t.Error("NewAutoUVBackend() inner backend mismatch")
	}
	if backend.provider != provider {
		t.Error("NewAutoUVBackend() provider mismatch")
	}
}

func TestNewAutoUVBackend_PreservesInnerAndProvider(t *testing.T) {
	inner := newMockBackend("tpm2", FIDO2KeyCapabilities{HardwareBacked: true})
	provider := &mockBarrierProvider{active: false}

	backend := NewAutoUVBackend(inner, provider)
	if backend.inner.Type() != types.BackendType("tpm2") {
		t.Errorf("inner Type() = %q, want %q", backend.inner.Type(), "tpm2")
	}
	if backend.provider.IsAutoUVActive() {
		t.Error("provider should report inactive")
	}
}

// --- Type ---

func TestAutoUVBackend_Type_DelegatesToInner(t *testing.T) {
	inner := newMockBackend("pkcs11", FIDO2KeyCapabilities{})
	backend := NewAutoUVBackend(inner, &mockBarrierProvider{active: true})

	if got := backend.Type(); got != types.BackendType("pkcs11") {
		t.Errorf("Type() = %q, want %q", got, "pkcs11")
	}
}

func TestAutoUVBackend_Type_MatchesInnerRegardlessOfProvider(t *testing.T) {
	inner := newMockBackend("software", FIDO2KeyCapabilities{})

	activeBackend := NewAutoUVBackend(inner, &mockBarrierProvider{active: true})
	inactiveBackend := NewAutoUVBackend(inner, &mockBarrierProvider{active: false})

	if activeBackend.Type() != inactiveBackend.Type() {
		t.Errorf("Type() should be same regardless of provider state: %q vs %q",
			activeBackend.Type(), inactiveBackend.Type())
	}
}

// --- Capabilities ---

func TestAutoUVBackend_Capabilities_ActiveOverridesUV(t *testing.T) {
	inner := newMockBackend("software", FIDO2KeyCapabilities{
		SupportedAlgorithms:     []int{COSEAlgES256, COSEAlgES384},
		SupportsExport:          true,
		SupportsImport:          true,
		HardwareBacked:          false,
		HandlesUserVerification: false,
	})
	backend := NewAutoUVBackend(inner, &mockBarrierProvider{active: true})

	caps := backend.Capabilities()

	if !caps.HandlesUserVerification {
		t.Error("Capabilities().HandlesUserVerification should be true when provider is active")
	}
	// Other fields must be preserved.
	if !caps.SupportsExport {
		t.Error("Capabilities().SupportsExport should be preserved from inner")
	}
	if !caps.SupportsImport {
		t.Error("Capabilities().SupportsImport should be preserved from inner")
	}
	if caps.HardwareBacked {
		t.Error("Capabilities().HardwareBacked should be false (inner is software)")
	}
	if len(caps.SupportedAlgorithms) != 2 {
		t.Errorf("SupportedAlgorithms length = %d, want 2", len(caps.SupportedAlgorithms))
	}
}

func TestAutoUVBackend_Capabilities_InactivePreservesInner(t *testing.T) {
	inner := newMockBackend("tpm2", FIDO2KeyCapabilities{
		SupportedAlgorithms:     []int{COSEAlgES256},
		HardwareBacked:          true,
		HandlesUserVerification: false,
		HandlesUserPresence:     true,
	})
	backend := NewAutoUVBackend(inner, &mockBarrierProvider{active: false})

	caps := backend.Capabilities()

	if caps.HandlesUserVerification {
		t.Error("Capabilities().HandlesUserVerification should be false when provider is inactive")
	}
	if !caps.HardwareBacked {
		t.Error("Capabilities().HardwareBacked should be preserved as true from inner")
	}
	if !caps.HandlesUserPresence {
		t.Error("Capabilities().HandlesUserPresence should be preserved from inner")
	}
}

func TestAutoUVBackend_Capabilities_ActivePreservesAlreadyTrueUV(t *testing.T) {
	// When inner already reports HandlesUserVerification=true, active provider
	// should keep it true (idempotent override).
	inner := newMockBackend("phone", FIDO2KeyCapabilities{
		HandlesUserVerification: true,
		HandlesUserPresence:     true,
	})
	backend := NewAutoUVBackend(inner, &mockBarrierProvider{active: true})

	caps := backend.Capabilities()
	if !caps.HandlesUserVerification {
		t.Error("Capabilities().HandlesUserVerification should remain true")
	}
	if !caps.HandlesUserPresence {
		t.Error("Capabilities().HandlesUserPresence should be preserved")
	}
}

func TestAutoUVBackend_Capabilities_InactivePreservesAlreadyTrueUV(t *testing.T) {
	// When inner already reports HandlesUserVerification=true and provider is
	// inactive, the inner's true value must be preserved (no clobbering).
	inner := newMockBackend("phone", FIDO2KeyCapabilities{
		HandlesUserVerification: true,
	})
	backend := NewAutoUVBackend(inner, &mockBarrierProvider{active: false})

	caps := backend.Capabilities()
	if !caps.HandlesUserVerification {
		t.Error("Capabilities().HandlesUserVerification should remain true from inner when provider is inactive")
	}
}

// --- GenerateCredentialKey ---

func TestAutoUVBackend_GenerateCredentialKey_Delegates(t *testing.T) {
	inner := newMockBackend("software", FIDO2KeyCapabilities{})
	backend := NewAutoUVBackend(inner, &mockBarrierProvider{active: true})

	credID := []byte("cred-gen-01")
	handle, pubKey, err := backend.GenerateCredentialKey(COSEAlgES256, credID)
	if err != nil {
		t.Fatalf("GenerateCredentialKey() error = %v", err)
	}
	if handle == nil {
		t.Fatal("GenerateCredentialKey() returned nil handle")
	}
	if len(pubKey) == 0 {
		t.Fatal("GenerateCredentialKey() returned empty public key")
	}
	if inner.generateCalled.Load() != 1 {
		t.Errorf("inner generateCalled = %d, want 1", inner.generateCalled.Load())
	}
}

func TestAutoUVBackend_GenerateCredentialKey_PropagatesError(t *testing.T) {
	inner := newMockBackend("software", FIDO2KeyCapabilities{})
	inner.generateErr = ErrUnsupportedAlgorithm
	backend := NewAutoUVBackend(inner, &mockBarrierProvider{active: true})

	_, _, err := backend.GenerateCredentialKey(-999, []byte("cred"))
	if !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Errorf("GenerateCredentialKey() error = %v, want %v", err, ErrUnsupportedAlgorithm)
	}
}

// --- Sign ---

func TestAutoUVBackend_Sign_Delegates(t *testing.T) {
	inner := newMockBackend("software", FIDO2KeyCapabilities{})
	backend := NewAutoUVBackend(inner, &mockBarrierProvider{active: true})

	handle := &mockKeyHandle{
		credentialID: []byte("cred-sign"),
		algorithm:    COSEAlgES256,
		backendType:  types.BackendTypeSoftware,
	}

	sig, err := backend.Sign(handle, COSEAlgES256, []byte("data-to-sign"))
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	if string(sig) != "signature-from-software" {
		t.Errorf("Sign() = %q, want %q", string(sig), "signature-from-software")
	}
	if inner.signCalled.Load() != 1 {
		t.Errorf("inner signCalled = %d, want 1", inner.signCalled.Load())
	}
}

func TestAutoUVBackend_Sign_PropagatesError(t *testing.T) {
	inner := newMockBackend("software", FIDO2KeyCapabilities{})
	inner.signErr = ErrSigningFailed
	backend := NewAutoUVBackend(inner, &mockBarrierProvider{active: false})

	handle := &mockKeyHandle{
		credentialID: []byte("cred"),
		algorithm:    COSEAlgES256,
		backendType:  types.BackendTypeSoftware,
	}

	_, err := backend.Sign(handle, COSEAlgES256, []byte("data"))
	if !errors.Is(err, ErrSigningFailed) {
		t.Errorf("Sign() error = %v, want %v", err, ErrSigningFailed)
	}
}

// --- LoadKey ---

func TestAutoUVBackend_LoadKey_Delegates(t *testing.T) {
	inner := newMockBackend("software", FIDO2KeyCapabilities{})
	credID := []byte("cred-load")
	inner.mu.Lock()
	inner.keys[string(credID)] = &mockKeyHandle{
		credentialID: credID,
		algorithm:    COSEAlgES256,
		backendType:  types.BackendTypeSoftware,
	}
	inner.mu.Unlock()

	backend := NewAutoUVBackend(inner, &mockBarrierProvider{active: true})

	handle, err := backend.LoadKey(credID, COSEAlgES256)
	if err != nil {
		t.Fatalf("LoadKey() error = %v", err)
	}
	if handle == nil {
		t.Fatal("LoadKey() returned nil handle")
	}
	if inner.loadCalled.Load() != 1 {
		t.Errorf("inner loadCalled = %d, want 1", inner.loadCalled.Load())
	}
}

func TestAutoUVBackend_LoadKey_PropagatesNotFound(t *testing.T) {
	inner := newMockBackend("software", FIDO2KeyCapabilities{})
	backend := NewAutoUVBackend(inner, &mockBarrierProvider{active: true})

	_, err := backend.LoadKey([]byte("nonexistent"), COSEAlgES256)
	if !errors.Is(err, ErrKeyNotFound) {
		t.Errorf("LoadKey() error = %v, want %v", err, ErrKeyNotFound)
	}
}

// --- DeleteKey ---

func TestAutoUVBackend_DeleteKey_Delegates(t *testing.T) {
	inner := newMockBackend("software", FIDO2KeyCapabilities{})
	backend := NewAutoUVBackend(inner, &mockBarrierProvider{active: true})

	handle := &mockKeyHandle{
		credentialID: []byte("cred-del"),
		algorithm:    COSEAlgES256,
		backendType:  types.BackendTypeSoftware,
	}

	err := backend.DeleteKey(handle)
	if err != nil {
		t.Fatalf("DeleteKey() error = %v", err)
	}
	if inner.deleteCalled.Load() != 1 {
		t.Errorf("inner deleteCalled = %d, want 1", inner.deleteCalled.Load())
	}
}

func TestAutoUVBackend_DeleteKey_PropagatesError(t *testing.T) {
	inner := newMockBackend("software", FIDO2KeyCapabilities{})
	inner.deleteErr = ErrBackendClosed
	backend := NewAutoUVBackend(inner, &mockBarrierProvider{active: false})

	handle := &mockKeyHandle{
		credentialID: []byte("cred"),
		algorithm:    COSEAlgES256,
		backendType:  types.BackendTypeSoftware,
	}

	err := backend.DeleteKey(handle)
	if !errors.Is(err, ErrBackendClosed) {
		t.Errorf("DeleteKey() error = %v, want %v", err, ErrBackendClosed)
	}
}

// --- ExportPrivateKey ---

func TestAutoUVBackend_ExportPrivateKey_Delegates(t *testing.T) {
	inner := newMockBackend("software", FIDO2KeyCapabilities{SupportsExport: true})
	backend := NewAutoUVBackend(inner, &mockBarrierProvider{active: true})

	handle := &mockKeyHandle{
		credentialID: []byte("cred-export"),
		algorithm:    COSEAlgES256,
		backendType:  types.BackendTypeSoftware,
	}

	data, err := backend.ExportPrivateKey(handle)
	if err != nil {
		t.Fatalf("ExportPrivateKey() error = %v", err)
	}
	if string(data) != "pkcs8-key-software" {
		t.Errorf("ExportPrivateKey() = %q, want %q", string(data), "pkcs8-key-software")
	}
	if inner.exportCalled.Load() != 1 {
		t.Errorf("inner exportCalled = %d, want 1", inner.exportCalled.Load())
	}
}

func TestAutoUVBackend_ExportPrivateKey_PropagatesError(t *testing.T) {
	inner := newMockBackend("tpm2", FIDO2KeyCapabilities{})
	inner.exportErr = ErrExportNotSupported
	backend := NewAutoUVBackend(inner, &mockBarrierProvider{active: true})

	handle := &mockKeyHandle{
		credentialID: []byte("cred"),
		algorithm:    COSEAlgES256,
		backendType:  types.BackendTypeTPM2,
	}

	_, err := backend.ExportPrivateKey(handle)
	if !errors.Is(err, ErrExportNotSupported) {
		t.Errorf("ExportPrivateKey() error = %v, want %v", err, ErrExportNotSupported)
	}
}

// --- ImportPrivateKey ---

func TestAutoUVBackend_ImportPrivateKey_Delegates(t *testing.T) {
	inner := newMockBackend("software", FIDO2KeyCapabilities{SupportsImport: true})
	backend := NewAutoUVBackend(inner, &mockBarrierProvider{active: true})

	handle, err := backend.ImportPrivateKey([]byte("cred-import"), COSEAlgES256, []byte("pkcs8-data"))
	if err != nil {
		t.Fatalf("ImportPrivateKey() error = %v", err)
	}
	if handle == nil {
		t.Fatal("ImportPrivateKey() returned nil handle")
	}
	if inner.importCalled.Load() != 1 {
		t.Errorf("inner importCalled = %d, want 1", inner.importCalled.Load())
	}
}

func TestAutoUVBackend_ImportPrivateKey_PropagatesError(t *testing.T) {
	inner := newMockBackend("software", FIDO2KeyCapabilities{})
	inner.importErr = ErrImportNotSupported
	backend := NewAutoUVBackend(inner, &mockBarrierProvider{active: false})

	_, err := backend.ImportPrivateKey([]byte("cred"), COSEAlgES256, []byte("key"))
	if !errors.Is(err, ErrImportNotSupported) {
		t.Errorf("ImportPrivateKey() error = %v, want %v", err, ErrImportNotSupported)
	}
}

// --- Close ---

func TestAutoUVBackend_Close_Delegates(t *testing.T) {
	inner := newMockBackend("software", FIDO2KeyCapabilities{})
	backend := NewAutoUVBackend(inner, &mockBarrierProvider{active: true})

	err := backend.Close()
	if err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if inner.closeCalled.Load() != 1 {
		t.Errorf("inner closeCalled = %d, want 1", inner.closeCalled.Load())
	}
}

func TestAutoUVBackend_Close_PropagatesError(t *testing.T) {
	inner := newMockBackend("software", FIDO2KeyCapabilities{})
	inner.closeErr = errors.New("close failed")
	backend := NewAutoUVBackend(inner, &mockBarrierProvider{active: false})

	err := backend.Close()
	if err == nil {
		t.Fatal("Close() should return an error")
	}
	if err.Error() != "close failed" {
		t.Errorf("Close() error = %q, want %q", err.Error(), "close failed")
	}
}

// --- Interface compliance ---

func TestAutoUVBackend_InterfaceCompliance(t *testing.T) {
	var _ FIDO2KeyBackend = (*AutoUVBackend)(nil)
}
