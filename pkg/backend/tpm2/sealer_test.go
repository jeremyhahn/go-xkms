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

package tpm2

import (
	"context"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// sealerMockTPM extends mockTPM with configurable Seal/Unseal/CanSeal behavior.
type sealerMockTPM struct {
	mockTPM
	sealErr       error
	sealResult    *types.SealedData
	unsealErr     error
	unsealResult  []byte
	canSealResult bool
}

func (m *sealerMockTPM) CanSeal() bool {
	return m.canSealResult
}

func (m *sealerMockTPM) Seal(_ context.Context, _ []byte, _ *types.SealOptions) (*types.SealedData, error) {
	if m.sealErr != nil {
		return nil, m.sealErr
	}
	return m.sealResult, nil
}

func (m *sealerMockTPM) Unseal(_ context.Context, _ *types.SealedData, _ *types.UnsealOptions) ([]byte, error) {
	if m.unsealErr != nil {
		return nil, m.unsealErr
	}
	return m.unsealResult, nil
}

// newSealerTestBackend creates a Backend wired to a sealerMockTPM for testing.
func newSealerTestBackend(mock *sealerMockTPM) *Backend {
	return &Backend{
		tpm:    mock,
		logger: nil,
	}
}

func TestSealerInterfaceCompliance(t *testing.T) {
	// Compile-time assertion is in sealer.go (var _ types.Sealer = (*Backend)(nil)).
	// This test verifies the assertion holds at runtime as well.
	var _ types.Sealer = &Backend{}
}

func TestCanSeal_WhenOpen(t *testing.T) {
	mock := &sealerMockTPM{canSealResult: true}
	b := newSealerTestBackend(mock)

	if !b.CanSeal() {
		t.Error("CanSeal() = false, want true when backend is open and TPM supports sealing")
	}
}

func TestCanSeal_WhenClosed(t *testing.T) {
	mock := &sealerMockTPM{canSealResult: true}
	b := newSealerTestBackend(mock)
	b.closed = true

	if b.CanSeal() {
		t.Error("CanSeal() = true, want false when backend is closed")
	}
}

func TestCanSeal_WhenTPMCannotSeal(t *testing.T) {
	mock := &sealerMockTPM{canSealResult: false}
	b := newSealerTestBackend(mock)

	if b.CanSeal() {
		t.Error("CanSeal() = true, want false when TPM cannot seal")
	}
}

func TestSeal_DelegatesToTPM(t *testing.T) {
	expectedSealed := &types.SealedData{
		Backend:    types.BackendTypeTPM2,
		Ciphertext: nil,
		TPMPublic:  []byte("pub-area"),
		TPMPrivate: []byte("priv-area"),
		KeyID:      "test-seal-key",
		Metadata:   map[string][]byte{"k": []byte("v")},
	}

	mock := &sealerMockTPM{
		sealResult: &types.SealedData{
			Backend:    "should-be-overwritten",
			TPMPublic:  expectedSealed.TPMPublic,
			TPMPrivate: expectedSealed.TPMPrivate,
			KeyID:      expectedSealed.KeyID,
			Metadata:   expectedSealed.Metadata,
		},
	}
	b := newSealerTestBackend(mock)

	ctx := context.Background()
	data := []byte("secret-data")
	sealed, err := b.Seal(ctx, data, nil)
	if err != nil {
		t.Fatalf("Seal() unexpected error: %v", err)
	}

	// Verify backend type is set to TPM2 by the backend wrapper
	if sealed.Backend != types.BackendTypeTPM2 {
		t.Errorf("sealed.Backend = %s, want %s", sealed.Backend, types.BackendTypeTPM2)
	}
	if string(sealed.TPMPublic) != string(expectedSealed.TPMPublic) {
		t.Errorf("sealed.TPMPublic = %s, want %s", sealed.TPMPublic, expectedSealed.TPMPublic)
	}
	if string(sealed.TPMPrivate) != string(expectedSealed.TPMPrivate) {
		t.Errorf("sealed.TPMPrivate = %s, want %s", sealed.TPMPrivate, expectedSealed.TPMPrivate)
	}
	if sealed.KeyID != expectedSealed.KeyID {
		t.Errorf("sealed.KeyID = %s, want %s", sealed.KeyID, expectedSealed.KeyID)
	}
}

func TestSeal_WithOptions(t *testing.T) {
	mock := &sealerMockTPM{
		sealResult: &types.SealedData{
			Backend: types.BackendTypeTPM2,
			KeyID:   "opts-key",
		},
	}
	b := newSealerTestBackend(mock)

	ctx := context.Background()
	opts := &types.SealOptions{
		KeyAttributes: &types.KeyAttributes{CN: "seal-key"},
	}
	sealed, err := b.Seal(ctx, []byte("data"), opts)
	if err != nil {
		t.Fatalf("Seal() with options unexpected error: %v", err)
	}
	if sealed.Backend != types.BackendTypeTPM2 {
		t.Errorf("sealed.Backend = %s, want %s", sealed.Backend, types.BackendTypeTPM2)
	}
}

func TestSeal_ErrorWhenClosed(t *testing.T) {
	mock := &sealerMockTPM{}
	b := newSealerTestBackend(mock)
	b.closed = true

	ctx := context.Background()
	_, err := b.Seal(ctx, []byte("data"), nil)
	if !errors.Is(err, ErrNotInitialized) {
		t.Errorf("Seal() error = %v, want ErrNotInitialized", err)
	}
}

func TestSeal_PropagatesTPMError(t *testing.T) {
	tpmErr := errors.New("tpm: seal hardware fault")
	mock := &sealerMockTPM{sealErr: tpmErr}
	b := newSealerTestBackend(mock)

	ctx := context.Background()
	_, err := b.Seal(ctx, []byte("data"), nil)
	if err == nil {
		t.Fatal("Seal() expected error, got nil")
	}
	if !errors.Is(err, tpmErr) {
		t.Errorf("Seal() error = %v, want wrapped %v", err, tpmErr)
	}
}

func TestUnseal_DelegatesToTPM(t *testing.T) {
	expectedPlaintext := []byte("recovered-secret")
	mock := &sealerMockTPM{unsealResult: expectedPlaintext}
	b := newSealerTestBackend(mock)

	ctx := context.Background()
	sealed := &types.SealedData{
		Backend:    types.BackendTypeTPM2,
		TPMPublic:  []byte("pub"),
		TPMPrivate: []byte("priv"),
		KeyID:      "key-1",
	}

	plaintext, err := b.Unseal(ctx, sealed, nil)
	if err != nil {
		t.Fatalf("Unseal() unexpected error: %v", err)
	}
	if string(plaintext) != string(expectedPlaintext) {
		t.Errorf("Unseal() = %s, want %s", plaintext, expectedPlaintext)
	}
}

func TestUnseal_WithOptions(t *testing.T) {
	mock := &sealerMockTPM{unsealResult: []byte("data")}
	b := newSealerTestBackend(mock)

	ctx := context.Background()
	sealed := &types.SealedData{
		Backend: types.BackendTypeTPM2,
		KeyID:   "key-2",
	}
	opts := &types.UnsealOptions{
		KeyAttributes: &types.KeyAttributes{CN: "unseal-key"},
	}

	plaintext, err := b.Unseal(ctx, sealed, opts)
	if err != nil {
		t.Fatalf("Unseal() with options unexpected error: %v", err)
	}
	if string(plaintext) != "data" {
		t.Errorf("Unseal() = %s, want data", plaintext)
	}
}

func TestUnseal_ErrorWhenClosed(t *testing.T) {
	mock := &sealerMockTPM{}
	b := newSealerTestBackend(mock)
	b.closed = true

	ctx := context.Background()
	sealed := &types.SealedData{Backend: types.BackendTypeTPM2}

	_, err := b.Unseal(ctx, sealed, nil)
	if !errors.Is(err, ErrNotInitialized) {
		t.Errorf("Unseal() error = %v, want ErrNotInitialized", err)
	}
}

func TestUnseal_NilSealedData(t *testing.T) {
	mock := &sealerMockTPM{}
	b := newSealerTestBackend(mock)

	ctx := context.Background()
	_, err := b.Unseal(ctx, nil, nil)
	if !errors.Is(err, ErrNilSealedData) {
		t.Errorf("Unseal(nil) error = %v, want ErrNilSealedData", err)
	}
}

func TestUnseal_PropagatesTPMError(t *testing.T) {
	tpmErr := errors.New("tpm: unseal PCR mismatch")
	mock := &sealerMockTPM{unsealErr: tpmErr}
	b := newSealerTestBackend(mock)

	ctx := context.Background()
	sealed := &types.SealedData{
		Backend: types.BackendTypeTPM2,
		KeyID:   "key-3",
	}

	_, err := b.Unseal(ctx, sealed, nil)
	if err == nil {
		t.Fatal("Unseal() expected error, got nil")
	}
	if !errors.Is(err, tpmErr) {
		t.Errorf("Unseal() error = %v, want wrapped %v", err, tpmErr)
	}
}

func TestSeal_NilSealedDataFromClosedBeforeTPM(t *testing.T) {
	// Verify the closed check happens before any TPM delegation.
	// Even if the mock would succeed, a closed backend must fail.
	mock := &sealerMockTPM{
		sealResult: &types.SealedData{Backend: types.BackendTypeTPM2},
	}
	b := newSealerTestBackend(mock)
	b.closed = true

	ctx := context.Background()
	_, err := b.Seal(ctx, []byte("data"), nil)
	if !errors.Is(err, ErrNotInitialized) {
		t.Errorf("Seal() on closed backend error = %v, want ErrNotInitialized", err)
	}
}

func TestUnseal_NilSealedDataCheckedBeforeClosedCheck(t *testing.T) {
	// Ensure nil sealed data is rejected even when the backend is closed,
	// and the nil check takes priority over the closed check.
	mock := &sealerMockTPM{}
	b := newSealerTestBackend(mock)
	b.closed = true

	ctx := context.Background()
	_, err := b.Unseal(ctx, nil, nil)
	if !errors.Is(err, ErrNilSealedData) {
		t.Errorf("Unseal(nil) on closed backend error = %v, want ErrNilSealedData", err)
	}
}
