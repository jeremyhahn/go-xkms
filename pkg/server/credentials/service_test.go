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

package credentials

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// testLogger returns a logger for test output.
func testLogger() *slog.Logger {
	return slog.Default()
}

// newTestBarrier creates a Barrier backed by in-memory storage with a
// SoftwareStrategy, initializes it, and returns it ready for use.
func newTestBarrier(t *testing.T) *seal.Barrier {
	t.Helper()

	base := storage.NewMemory()
	strategy := seal.NewSoftwareStrategy()

	barrier, err := seal.NewBarrier(
		testLogger(),
		base,
		seal.BarrierConfig{RootKeyPath: "test-root-key"},
		strategy,
	)
	if err != nil {
		t.Fatalf("NewBarrier: %v", err)
	}

	if err := barrier.Initialize(context.Background(), seal.Credentials{Secret: "test-password"}); err != nil {
		t.Fatalf("barrier.Initialize: %v", err)
	}

	return barrier
}

// newTestPlatformStore creates a SealedPlatformStore backed by the given barrier.
func newTestPlatformStore(t *testing.T, barrier *seal.Barrier) seal.PlatformStore {
	t.Helper()

	store, err := seal.NewPlatformStore(barrier, testLogger())
	if err != nil {
		t.Fatalf("NewPlatformStore: %v", err)
	}
	return store
}

// --- Constructor tests ---

func TestNewService_ManualStrategy(t *testing.T) {
	svc, err := New(&Config{Strategy: StrategyManual}, nil, nil, testLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if svc.Strategy() != StrategyManual {
		t.Errorf("Strategy() = %q, want %q", svc.Strategy(), StrategyManual)
	}
}

func TestNewService_ManualStrategy_DefaultsWhenEmpty(t *testing.T) {
	svc, err := New(&Config{Strategy: ""}, nil, nil, testLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if svc.Strategy() != StrategyManual {
		t.Errorf("Strategy() = %q, want %q", svc.Strategy(), StrategyManual)
	}
}

func TestNewService_ManualStrategy_NilLogger(t *testing.T) {
	svc, err := New(&Config{Strategy: StrategyManual}, nil, nil, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if svc.logger == nil {
		t.Fatal("expected non-nil logger after nil input")
	}
}

func TestNewService_BarrierStrategy(t *testing.T) {
	barrier := newTestBarrier(t)
	svc, err := New(&Config{Strategy: "barrier"}, nil, barrier, testLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if svc.Strategy() != "barrier" {
		t.Errorf("Strategy() = %q, want barrier", svc.Strategy())
	}
}

func TestNewService_BarrierStrategy_NilBarrier(t *testing.T) {
	_, err := New(&Config{Strategy: "barrier"}, nil, nil, testLogger())
	if !errors.Is(err, ErrNilBarrier) {
		t.Errorf("New: got %v, want %v", err, ErrNilBarrier)
	}
}

func TestNewService_PlatformStrategy_NilStore(t *testing.T) {
	strategies := []string{"tpm2", "pkcs11", "aws_kms", "gcp_kms", "azure_kv", "vault", "software"}
	for _, strategy := range strategies {
		t.Run(strategy, func(t *testing.T) {
			_, err := New(&Config{Strategy: strategy}, nil, nil, testLogger())
			if !errors.Is(err, ErrNilPlatformStore) {
				t.Errorf("New(%s): got %v, want %v", strategy, err, ErrNilPlatformStore)
			}
		})
	}
}

func TestNewService_InvalidStrategy(t *testing.T) {
	_, err := New(&Config{Strategy: "nonexistent"}, nil, nil, testLogger())
	if !errors.Is(err, ErrInvalidStrategy) {
		t.Errorf("New: got %v, want %v", err, ErrInvalidStrategy)
	}
}

// --- StoreCredential tests ---

func TestStoreCredential_Manual(t *testing.T) {
	svc, err := New(&Config{Strategy: StrategyManual}, nil, nil, testLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx := context.Background()
	if err := svc.StoreCredential(ctx, "pkcs11-pin", []byte("1234")); err != nil {
		t.Fatalf("StoreCredential: %v", err)
	}

	// Verify stored in memory.
	svc.mu.RLock()
	val, exists := svc.manualCreds["pkcs11-pin"]
	svc.mu.RUnlock()
	if !exists {
		t.Fatal("credential not found in memory")
	}
	if string(val) != "1234" {
		t.Errorf("stored value = %q, want %q", string(val), "1234")
	}
}

func TestStoreCredential_EmptyName(t *testing.T) {
	svc, err := New(&Config{Strategy: StrategyManual}, nil, nil, testLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	err = svc.StoreCredential(context.Background(), "", []byte("value"))
	if !errors.Is(err, ErrEmptyCredentialName) {
		t.Errorf("StoreCredential: got %v, want %v", err, ErrEmptyCredentialName)
	}
}

func TestStoreCredential_WhitespaceName(t *testing.T) {
	svc, err := New(&Config{Strategy: StrategyManual}, nil, nil, testLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	err = svc.StoreCredential(context.Background(), "   ", []byte("value"))
	if !errors.Is(err, ErrEmptyCredentialName) {
		t.Errorf("StoreCredential: got %v, want %v", err, ErrEmptyCredentialName)
	}
}

func TestStoreCredential_EmptyValue(t *testing.T) {
	svc, err := New(&Config{Strategy: StrategyManual}, nil, nil, testLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	err = svc.StoreCredential(context.Background(), "name", []byte{})
	if !errors.Is(err, ErrEmptyCredentialValue) {
		t.Errorf("StoreCredential: got %v, want %v", err, ErrEmptyCredentialValue)
	}
}

func TestStoreCredential_NilValue(t *testing.T) {
	svc, err := New(&Config{Strategy: StrategyManual}, nil, nil, testLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	err = svc.StoreCredential(context.Background(), "name", nil)
	if !errors.Is(err, ErrEmptyCredentialValue) {
		t.Errorf("StoreCredential: got %v, want %v", err, ErrEmptyCredentialValue)
	}
}

// --- RetrieveCredential tests ---

func TestRetrieveCredential_Manual_AlreadySubmitted(t *testing.T) {
	svc, err := New(&Config{Strategy: StrategyManual}, nil, nil, testLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx := context.Background()
	if err := svc.StoreCredential(ctx, "my-pin", []byte("secret")); err != nil {
		t.Fatalf("StoreCredential: %v", err)
	}

	val, err := svc.RetrieveCredential(ctx, "my-pin")
	if err != nil {
		t.Fatalf("RetrieveCredential: %v", err)
	}
	if string(val) != "secret" {
		t.Errorf("RetrieveCredential = %q, want %q", string(val), "secret")
	}
}

func TestRetrieveCredential_Manual_NotSubmitted_ContextCancelled(t *testing.T) {
	svc, err := New(&Config{Strategy: StrategyManual}, nil, nil, testLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err = svc.RetrieveCredential(ctx, "nonexistent")
	if err == nil {
		t.Fatal("RetrieveCredential: expected error, got nil")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("RetrieveCredential: got %v, want %v", err, context.DeadlineExceeded)
	}
}

func TestRetrieveCredential_EmptyName(t *testing.T) {
	svc, err := New(&Config{Strategy: StrategyManual}, nil, nil, testLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	_, err = svc.RetrieveCredential(context.Background(), "")
	if !errors.Is(err, ErrEmptyCredentialName) {
		t.Errorf("RetrieveCredential: got %v, want %v", err, ErrEmptyCredentialName)
	}
}

// --- SubmitCredential tests ---

func TestSubmitCredential_Manual(t *testing.T) {
	svc, err := New(&Config{Strategy: StrategyManual}, nil, nil, testLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx := context.Background()
	if err := svc.SubmitCredential(ctx, "tpm2-auth", []byte("auth-value")); err != nil {
		t.Fatalf("SubmitCredential: %v", err)
	}

	// Verify retrievable.
	val, err := svc.RetrieveCredential(ctx, "tpm2-auth")
	if err != nil {
		t.Fatalf("RetrieveCredential: %v", err)
	}
	if string(val) != "auth-value" {
		t.Errorf("RetrieveCredential = %q, want %q", string(val), "auth-value")
	}
}

func TestSubmitCredential_Manual_UnblocksWaiter(t *testing.T) {
	svc, err := New(&Config{Strategy: StrategyManual}, nil, nil, testLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx := context.Background()
	errCh := make(chan error, 1)
	valCh := make(chan []byte, 1)

	// Start a goroutine that blocks waiting for the credential.
	go func() {
		val, err := svc.RetrieveCredential(ctx, "delayed-cred")
		errCh <- err
		valCh <- val
	}()

	// Give the goroutine time to register the waiter.
	time.Sleep(20 * time.Millisecond)

	if err := svc.SubmitCredential(ctx, "delayed-cred", []byte("delayed-value")); err != nil {
		t.Fatalf("SubmitCredential: %v", err)
	}

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("RetrieveCredential: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("RetrieveCredential timed out")
	}

	select {
	case val := <-valCh:
		if string(val) != "delayed-value" {
			t.Errorf("RetrieveCredential = %q, want %q", string(val), "delayed-value")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("value channel timed out")
	}
}

func TestSubmitCredential_AlreadySubmitted(t *testing.T) {
	svc, err := New(&Config{Strategy: StrategyManual}, nil, nil, testLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx := context.Background()
	if err := svc.SubmitCredential(ctx, "pin", []byte("1234")); err != nil {
		t.Fatalf("first SubmitCredential: %v", err)
	}

	err = svc.SubmitCredential(ctx, "pin", []byte("5678"))
	if !errors.Is(err, ErrCredentialAlreadySubmitted) {
		t.Errorf("second SubmitCredential: got %v, want %v", err, ErrCredentialAlreadySubmitted)
	}
}

func TestSubmitCredential_EmptyName(t *testing.T) {
	svc, err := New(&Config{Strategy: StrategyManual}, nil, nil, testLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	err = svc.SubmitCredential(context.Background(), "", []byte("value"))
	if !errors.Is(err, ErrEmptyCredentialName) {
		t.Errorf("SubmitCredential: got %v, want %v", err, ErrEmptyCredentialName)
	}
}

func TestSubmitCredential_EmptyValue(t *testing.T) {
	svc, err := New(&Config{Strategy: StrategyManual}, nil, nil, testLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	err = svc.SubmitCredential(context.Background(), "name", []byte{})
	if !errors.Is(err, ErrEmptyCredentialValue) {
		t.Errorf("SubmitCredential: got %v, want %v", err, ErrEmptyCredentialValue)
	}
}

func TestSubmitCredential_NonManual_DelegatesToStore(t *testing.T) {
	barrier := newTestBarrier(t)
	svc, err := New(&Config{Strategy: "barrier"}, nil, barrier, testLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx := context.Background()
	if err := svc.SubmitCredential(ctx, "my-cred", []byte("my-value")); err != nil {
		t.Fatalf("SubmitCredential: %v", err)
	}

	// Verify it was stored in barrier.
	val, err := svc.RetrieveCredential(ctx, "my-cred")
	if err != nil {
		t.Fatalf("RetrieveCredential: %v", err)
	}
	if string(val) != "my-value" {
		t.Errorf("RetrieveCredential = %q, want %q", string(val), "my-value")
	}
}

// --- DeleteCredential tests ---

func TestDeleteCredential_Manual(t *testing.T) {
	svc, err := New(&Config{Strategy: StrategyManual}, nil, nil, testLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx := context.Background()
	if err := svc.StoreCredential(ctx, "to-delete", []byte("value")); err != nil {
		t.Fatalf("StoreCredential: %v", err)
	}

	if err := svc.DeleteCredential(ctx, "to-delete"); err != nil {
		t.Fatalf("DeleteCredential: %v", err)
	}

	// Verify it's gone.
	svc.mu.RLock()
	_, exists := svc.manualCreds["to-delete"]
	svc.mu.RUnlock()
	if exists {
		t.Error("credential still exists after delete")
	}
}

func TestDeleteCredential_Manual_NotFound(t *testing.T) {
	svc, err := New(&Config{Strategy: StrategyManual}, nil, nil, testLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	err = svc.DeleteCredential(context.Background(), "nonexistent")
	if !errors.Is(err, ErrCredentialNotFound) {
		t.Errorf("DeleteCredential: got %v, want %v", err, ErrCredentialNotFound)
	}
}

func TestDeleteCredential_EmptyName(t *testing.T) {
	svc, err := New(&Config{Strategy: StrategyManual}, nil, nil, testLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	err = svc.DeleteCredential(context.Background(), "")
	if !errors.Is(err, ErrEmptyCredentialName) {
		t.Errorf("DeleteCredential: got %v, want %v", err, ErrEmptyCredentialName)
	}
}

// --- AutoUnsealAvailable tests ---

func TestAutoUnsealAvailable_Manual(t *testing.T) {
	svc, err := New(&Config{Strategy: StrategyManual}, nil, nil, testLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if svc.AutoUnsealAvailable() {
		t.Error("AutoUnsealAvailable() = true, want false for manual strategy")
	}
}

func TestAutoUnsealAvailable_Barrier(t *testing.T) {
	barrier := newTestBarrier(t)
	svc, err := New(&Config{Strategy: "barrier"}, nil, barrier, testLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if !svc.AutoUnsealAvailable() {
		t.Error("AutoUnsealAvailable() = false, want true for barrier strategy")
	}
}

func TestAutoUnsealAvailable_TPM2(t *testing.T) {
	barrier := newTestBarrier(t)
	store := newTestPlatformStore(t, barrier)

	svc, err := New(&Config{Strategy: "tpm2"}, store, nil, testLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if !svc.AutoUnsealAvailable() {
		t.Error("AutoUnsealAvailable() = false, want true for tpm2 strategy")
	}
}

// --- Strategy tests ---

func TestStrategy(t *testing.T) {
	tests := []struct {
		name          string
		strategy      string
		wantStrategy  string
		needBarrier   bool
		needPlatStore bool
	}{
		{"manual", StrategyManual, StrategyManual, false, false},
		{"barrier", "barrier", "barrier", true, false},
		{"software", "software", "software", false, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var barrier *seal.Barrier
			var store seal.PlatformStore
			if tt.needBarrier || tt.needPlatStore {
				barrier = newTestBarrier(t)
			}
			if tt.needPlatStore {
				store = newTestPlatformStore(t, barrier)
			}

			svc, err := New(&Config{Strategy: tt.strategy}, store, barrier, testLogger())
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			if svc.Strategy() != tt.wantStrategy {
				t.Errorf("Strategy() = %q, want %q", svc.Strategy(), tt.wantStrategy)
			}
		})
	}
}

// --- Barrier round-trip tests ---

func TestStoreRetrieveCredential_Barrier(t *testing.T) {
	barrier := newTestBarrier(t)
	svc, err := New(&Config{Strategy: "barrier"}, nil, barrier, testLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx := context.Background()
	cred := []byte("super-secret-pin-1234")

	if err := svc.StoreCredential(ctx, "pkcs11-user-pin", cred); err != nil {
		t.Fatalf("StoreCredential: %v", err)
	}

	retrieved, err := svc.RetrieveCredential(ctx, "pkcs11-user-pin")
	if err != nil {
		t.Fatalf("RetrieveCredential: %v", err)
	}
	if string(retrieved) != string(cred) {
		t.Errorf("RetrieveCredential = %q, want %q", string(retrieved), string(cred))
	}
}

func TestStoreRetrieveDeleteCredential_Barrier(t *testing.T) {
	barrier := newTestBarrier(t)
	svc, err := New(&Config{Strategy: "barrier"}, nil, barrier, testLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx := context.Background()
	if err := svc.StoreCredential(ctx, "test-cred", []byte("value")); err != nil {
		t.Fatalf("StoreCredential: %v", err)
	}

	if err := svc.DeleteCredential(ctx, "test-cred"); err != nil {
		t.Fatalf("DeleteCredential: %v", err)
	}

	_, err = svc.RetrieveCredential(ctx, "test-cred")
	if !errors.Is(err, ErrCredentialNotFound) {
		t.Errorf("RetrieveCredential after delete: got %v, want %v", err, ErrCredentialNotFound)
	}
}

func TestDeleteCredential_Barrier_NotFound(t *testing.T) {
	barrier := newTestBarrier(t)
	svc, err := New(&Config{Strategy: "barrier"}, nil, barrier, testLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	err = svc.DeleteCredential(context.Background(), "nonexistent")
	if !errors.Is(err, ErrCredentialNotFound) {
		t.Errorf("DeleteCredential: got %v, want %v", err, ErrCredentialNotFound)
	}
}

func TestRetrieveCredential_Barrier_NotFound(t *testing.T) {
	barrier := newTestBarrier(t)
	svc, err := New(&Config{Strategy: "barrier"}, nil, barrier, testLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	_, err = svc.RetrieveCredential(context.Background(), "nonexistent")
	if !errors.Is(err, ErrCredentialNotFound) {
		t.Errorf("RetrieveCredential: got %v, want %v", err, ErrCredentialNotFound)
	}
}

// --- PlatformStore round-trip tests ---

func TestStoreRetrieveCredential_PlatformStore(t *testing.T) {
	barrier := newTestBarrier(t)
	store := newTestPlatformStore(t, barrier)
	svc, err := New(&Config{Strategy: "software"}, store, nil, testLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx := context.Background()
	cred := []byte("platform-secret")

	if err := svc.StoreCredential(ctx, "test-platform-cred", cred); err != nil {
		t.Fatalf("StoreCredential: %v", err)
	}

	retrieved, err := svc.RetrieveCredential(ctx, "test-platform-cred")
	if err != nil {
		t.Fatalf("RetrieveCredential: %v", err)
	}
	if string(retrieved) != string(cred) {
		t.Errorf("RetrieveCredential = %q, want %q", string(retrieved), string(cred))
	}
}

func TestDeleteCredential_PlatformStore(t *testing.T) {
	barrier := newTestBarrier(t)
	store := newTestPlatformStore(t, barrier)
	svc, err := New(&Config{Strategy: "software"}, store, nil, testLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx := context.Background()
	if err := svc.StoreCredential(ctx, "to-delete", []byte("val")); err != nil {
		t.Fatalf("StoreCredential: %v", err)
	}

	if err := svc.DeleteCredential(ctx, "to-delete"); err != nil {
		t.Fatalf("DeleteCredential: %v", err)
	}

	_, err = svc.RetrieveCredential(ctx, "to-delete")
	if !errors.Is(err, ErrCredentialNotFound) {
		t.Errorf("RetrieveCredential after delete: got %v, want %v", err, ErrCredentialNotFound)
	}
}

func TestDeleteCredential_PlatformStore_NotFound(t *testing.T) {
	barrier := newTestBarrier(t)
	store := newTestPlatformStore(t, barrier)
	svc, err := New(&Config{Strategy: "software"}, store, nil, testLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	err = svc.DeleteCredential(context.Background(), "nonexistent")
	if !errors.Is(err, ErrCredentialNotFound) {
		t.Errorf("DeleteCredential: got %v, want %v", err, ErrCredentialNotFound)
	}
}

func TestRetrieveCredential_PlatformStore_NotFound(t *testing.T) {
	barrier := newTestBarrier(t)
	store := newTestPlatformStore(t, barrier)
	svc, err := New(&Config{Strategy: "software"}, store, nil, testLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	_, err = svc.RetrieveCredential(context.Background(), "nonexistent")
	if !errors.Is(err, ErrCredentialNotFound) {
		t.Errorf("RetrieveCredential: got %v, want %v", err, ErrCredentialNotFound)
	}
}

// --- StoreCredential overwrites existing value ---

func TestStoreCredential_Manual_Overwrite(t *testing.T) {
	svc, err := New(&Config{Strategy: StrategyManual}, nil, nil, testLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx := context.Background()
	if err := svc.StoreCredential(ctx, "cred", []byte("old")); err != nil {
		t.Fatalf("StoreCredential (1): %v", err)
	}
	if err := svc.StoreCredential(ctx, "cred", []byte("new")); err != nil {
		t.Fatalf("StoreCredential (2): %v", err)
	}

	val, err := svc.RetrieveCredential(ctx, "cred")
	if err != nil {
		t.Fatalf("RetrieveCredential: %v", err)
	}
	if string(val) != "new" {
		t.Errorf("value = %q, want %q", string(val), "new")
	}
}

func TestStoreCredential_Barrier_Overwrite(t *testing.T) {
	barrier := newTestBarrier(t)
	svc, err := New(&Config{Strategy: "barrier"}, nil, barrier, testLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx := context.Background()
	if err := svc.StoreCredential(ctx, "cred", []byte("old")); err != nil {
		t.Fatalf("StoreCredential (1): %v", err)
	}
	if err := svc.StoreCredential(ctx, "cred", []byte("new")); err != nil {
		t.Fatalf("StoreCredential (2): %v", err)
	}

	val, err := svc.RetrieveCredential(ctx, "cred")
	if err != nil {
		t.Fatalf("RetrieveCredential: %v", err)
	}
	if string(val) != "new" {
		t.Errorf("value = %q, want %q", string(val), "new")
	}
}

// --- isPlatformStrategy test ---

func TestIsPlatformStrategy(t *testing.T) {
	tests := []struct {
		strategy string
		want     bool
	}{
		{StrategyManual, false},
		{"barrier", false},
		{"tpm2", true},
		{"pkcs11", true},
		{"aws_kms", true},
		{"gcp_kms", true},
		{"azure_kv", true},
		{"vault", true},
		{"software", true},
	}

	for _, tt := range tests {
		t.Run(tt.strategy, func(t *testing.T) {
			if got := isPlatformStrategy(tt.strategy); got != tt.want {
				t.Errorf("isPlatformStrategy(%q) = %v, want %v", tt.strategy, got, tt.want)
			}
		})
	}
}

// --- validateInput test ---

func TestValidateInput(t *testing.T) {
	tests := []struct {
		name    string
		credNm  string
		value   []byte
		wantErr error
	}{
		{"valid", "name", []byte("val"), nil},
		{"empty name", "", []byte("val"), ErrEmptyCredentialName},
		{"whitespace name", "  \t ", []byte("val"), ErrEmptyCredentialName},
		{"nil value", "name", nil, ErrEmptyCredentialValue},
		{"empty value", "name", []byte{}, ErrEmptyCredentialValue},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateInput(tt.credNm, tt.value)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("validateInput(%q, %v) = %v, want %v", tt.credNm, tt.value, err, tt.wantErr)
			}
		})
	}
}

// --- Value isolation tests ---

func TestStoreCredential_Manual_ValueIsolation(t *testing.T) {
	svc, err := New(&Config{Strategy: StrategyManual}, nil, nil, testLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx := context.Background()
	original := []byte("sensitive")
	if err := svc.StoreCredential(ctx, "iso-test", original); err != nil {
		t.Fatalf("StoreCredential: %v", err)
	}

	// Mutate the original slice -- should not affect stored value.
	original[0] = 'X'

	val, err := svc.RetrieveCredential(ctx, "iso-test")
	if err != nil {
		t.Fatalf("RetrieveCredential: %v", err)
	}
	if string(val) != "sensitive" {
		t.Errorf("stored value was mutated: got %q, want %q", string(val), "sensitive")
	}
}

func TestRetrieveCredential_Manual_ReturnIsolation(t *testing.T) {
	svc, err := New(&Config{Strategy: StrategyManual}, nil, nil, testLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx := context.Background()
	if err := svc.StoreCredential(ctx, "iso-test2", []byte("original")); err != nil {
		t.Fatalf("StoreCredential: %v", err)
	}

	val1, err := svc.RetrieveCredential(ctx, "iso-test2")
	if err != nil {
		t.Fatalf("RetrieveCredential (1): %v", err)
	}

	// Mutate returned value.
	val1[0] = 'X'

	val2, err := svc.RetrieveCredential(ctx, "iso-test2")
	if err != nil {
		t.Fatalf("RetrieveCredential (2): %v", err)
	}
	if string(val2) != "original" {
		t.Errorf("stored value was mutated via return: got %q, want %q", string(val2), "original")
	}
}
