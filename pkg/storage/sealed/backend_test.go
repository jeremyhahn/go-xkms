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

package sealed

import (
	"context"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// mockSealer implements types.Sealer with a simple XOR-based reversible
// transform for deterministic unit testing. It is NOT cryptographically
// secure and must never be used outside of tests.
type mockSealer struct {
	canSeal   bool
	sealErr   error
	unsealErr error
	// unsealIntoErr fails UnsealInto alone, after PlaintextLen has succeeded.
	unsealIntoErr error
}

func (m *mockSealer) Seal(_ context.Context, data []byte, _ *types.SealOptions) (*types.SealedData, error) {
	if m.sealErr != nil {
		return nil, m.sealErr
	}
	ciphertext := make([]byte, len(data))
	for i, b := range data {
		ciphertext[i] = b ^ 0xFF
	}
	return &types.SealedData{
		Backend:    "software",
		Ciphertext: ciphertext,
	}, nil
}

func (m *mockSealer) Unseal(_ context.Context, sealed *types.SealedData, _ *types.UnsealOptions) ([]byte, error) {
	if m.unsealErr != nil {
		return nil, m.unsealErr
	}
	plaintext := make([]byte, len(sealed.Ciphertext))
	for i, b := range sealed.Ciphertext {
		plaintext[i] = b ^ 0xFF
	}
	return plaintext, nil
}

func (m *mockSealer) CanSeal() bool { return m.canSeal }

// mockFailingPutBackend wraps a storage.Backend and injects a failure on Put.
// All other operations delegate to the underlying backend.
type mockFailingPutBackend struct {
	storage.Backend
	putErr error
}

func (m *mockFailingPutBackend) Put(_ context.Context, _ string, _ []byte) error {
	return m.putErr
}

// newTestBackend creates a sealed Backend backed by an in-memory store
// with a working mock sealer.
func newTestBackend(t *testing.T) *Backend {
	t.Helper()
	inner := storage.NewMemory()
	sealer := &mockSealer{canSeal: true}
	b, err := New(inner, sealer, nil)
	if err != nil {
		t.Fatalf("New returned unexpected error: %v", err)
	}
	return b
}

// ---------------------------------------------------------------------------
// Constructor tests
// ---------------------------------------------------------------------------

func TestNew_WithSealOptions(t *testing.T) {
	inner := storage.NewMemory()
	sealer := &mockSealer{canSeal: true}
	opts := &types.SealOptions{AAD: []byte("extra")}

	b, err := New(inner, sealer, opts)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if b.sealOpts != opts {
		t.Fatal("expected seal options to be stored")
	}
}

func TestNew_NilInner(t *testing.T) {
	sealer := &mockSealer{canSeal: true}

	b, err := New(nil, sealer, nil)
	if err == nil {
		t.Fatal("expected error for nil inner backend")
	}
	if !errors.Is(err, ErrSealerNotAvailable) {
		t.Fatalf("expected ErrSealerNotAvailable, got %v", err)
	}
	if b != nil {
		t.Fatal("expected nil backend on error")
	}
}

func TestNew_NilSealer(t *testing.T) {
	inner := storage.NewMemory()

	b, err := New(inner, nil, nil)
	if err == nil {
		t.Fatal("expected error for nil sealer")
	}
	if !errors.Is(err, ErrSealerNotAvailable) {
		t.Fatalf("expected ErrSealerNotAvailable, got %v", err)
	}
	if b != nil {
		t.Fatal("expected nil backend on error")
	}
}

func TestNew_CannotSeal(t *testing.T) {
	inner := storage.NewMemory()
	sealer := &mockSealer{canSeal: false}

	b, err := New(inner, sealer, nil)
	if err == nil {
		t.Fatal("expected error when sealer cannot seal")
	}
	if !errors.Is(err, ErrSealerNotAvailable) {
		t.Fatalf("expected ErrSealerNotAvailable, got %v", err)
	}
	if b != nil {
		t.Fatal("expected nil backend on error")
	}
}

// ---------------------------------------------------------------------------
// Put / Get round-trip tests
// ---------------------------------------------------------------------------

func TestPutGet_EmptyValue(t *testing.T) {
	b := newTestBackend(t)

	key := "test/empty"
	value := []byte{}

	if err := b.Put(context.Background(), key, value); err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	got, err := b.Get(context.Background(), key)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}

	if len(got) != 0 {
		t.Fatalf("expected empty value, got %d bytes", len(got))
	}
}

func TestPutGet_BinaryData(t *testing.T) {
	b := newTestBackend(t)

	key := "test/binary"
	value := make([]byte, 256)
	for i := range value {
		value[i] = byte(i)
	}

	if err := b.Put(context.Background(), key, value); err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	got, err := b.Get(context.Background(), key)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}

	if len(got) != len(value) {
		t.Fatalf("length mismatch: got %d, want %d", len(got), len(value))
	}
	for i := range value {
		if got[i] != value[i] {
			t.Fatalf("byte mismatch at index %d: got 0x%02x, want 0x%02x", i, got[i], value[i])
		}
	}
}

func TestPutGet_MultipleKeys(t *testing.T) {
	b := newTestBackend(t)

	entries := map[string][]byte{
		"key/one":   []byte("first value"),
		"key/two":   []byte("second value"),
		"key/three": []byte("third value"),
	}

	for k, v := range entries {
		if err := b.Put(context.Background(), k, v); err != nil {
			t.Fatalf("Put(%q) failed: %v", k, err)
		}
	}

	for k, want := range entries {
		got, err := b.Get(context.Background(), k)
		if err != nil {
			t.Fatalf("Get(%q) failed: %v", k, err)
		}
		if string(got) != string(want) {
			t.Fatalf("Get(%q) = %q, want %q", k, got, want)
		}
	}
}

// ---------------------------------------------------------------------------
// Get error tests
// ---------------------------------------------------------------------------

func TestGet_UnsealFails(t *testing.T) {
	inner := storage.NewMemory()
	sealer := &mockSealer{canSeal: true}

	b, err := New(inner, sealer, nil)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	// Store a valid sealed value first.
	if err := b.Put(context.Background(), "key", []byte("data")); err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	// Now inject an unseal error.
	sealer.unsealErr = errors.New("unseal broken")

	_, err = b.Get(context.Background(), "key")
	if err == nil {
		t.Fatal("expected error when unseal fails")
	}
	if !errors.Is(err, ErrUnsealFailed) {
		t.Fatalf("expected ErrUnsealFailed, got %v", err)
	}
}

func TestGet_CorruptedData(t *testing.T) {
	inner := storage.NewMemory()

	// Manually store non-JSON data in the inner backend.
	if err := inner.Put(context.Background(), "corrupt", []byte("not json{{{")); err != nil {
		t.Fatalf("inner Put failed: %v", err)
	}

	sealer := &mockSealer{canSeal: true}
	b, err := New(inner, sealer, nil)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	_, err = b.Get(context.Background(), "corrupt")
	if err == nil {
		t.Fatal("expected error for corrupted sealed data")
	}
	if !errors.Is(err, ErrUnmarshalFailed) {
		t.Fatalf("expected ErrUnmarshalFailed, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Put error tests
// ---------------------------------------------------------------------------

// TestBackend_Refusals pins each refusal of the sealed backend to its typed
// error, and checks that a refused call leaves the inner store as it was: a
// write that could not be sealed stores nothing, and a guarded delete whose
// stored value cannot be opened deletes nothing.
func TestBackend_Refusals(t *testing.T) {
	const key = "key"
	stored := []byte("stored")

	tests := []struct {
		name string
		// inner is the store under the backend; nil means a fresh Memory store.
		inner  storage.Backend
		sealer *mockSealer
		// seed is written through a working sealer before the call; nil writes nothing.
		seed    []byte
		call    func(ctx context.Context, b *Backend) error
		wantErr error
	}{
		{
			name:    "Put refuses a value the barrier cannot seal",
			sealer:  &mockSealer{canSeal: true, sealErr: errors.New("seal broken")},
			call:    func(ctx context.Context, b *Backend) error { return b.Put(ctx, key, []byte("data")) },
			wantErr: ErrSealFailed,
		},
		{
			name:   "PutIfAbsent refuses a value the barrier cannot seal",
			sealer: &mockSealer{canSeal: true, sealErr: errors.New("seal broken")},
			call: func(ctx context.Context, b *Backend) error {
				_, err := b.PutIfAbsent(ctx, key, []byte("data"))
				return err
			},
			wantErr: ErrSealFailed,
		},
		{
			name:   "PutIfAllAbsent refuses a value the barrier cannot seal",
			sealer: &mockSealer{canSeal: true, sealErr: errors.New("seal broken")},
			call: func(ctx context.Context, b *Backend) error {
				_, err := b.PutIfAllAbsent(ctx, key, []byte("data"), "fence")
				return err
			},
			wantErr: ErrSealFailed,
		},
		{
			// noCADBackend hides every optional capability of the inner store,
			// fenced creation included.
			name:   "PutIfAllAbsent refuses an inner store without fenced creation",
			inner:  noCADBackend{storage.NewMemory()},
			sealer: &mockSealer{canSeal: true},
			call: func(ctx context.Context, b *Backend) error {
				_, err := b.PutIfAllAbsent(ctx, key, []byte("data"), "fence")
				return err
			},
			wantErr: storage.ErrFencedCreateUnsupported,
		},
		{
			name:   "CompareAndDelete refuses a stored value the barrier cannot open",
			sealer: &mockSealer{canSeal: true, unsealErr: errors.New("unseal broken")},
			seed:   stored,
			call: func(ctx context.Context, b *Backend) error {
				_, err := b.CompareAndDelete(ctx, key, stored)
				return err
			},
			wantErr: ErrUnsealFailed,
		},
		{
			// An empty plaintext is still authenticated: a tampered envelope must
			// not "match" an empty guard.
			name:   "CompareAndDelete refuses an empty stored value that fails authentication",
			sealer: &mockSealer{canSeal: true, unsealIntoErr: errors.New("tag mismatch")},
			seed:   []byte{},
			call: func(ctx context.Context, b *Backend) error {
				_, err := b.CompareAndDelete(ctx, key, nil)
				return err
			},
			wantErr: ErrUnsealFailed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			inner := tt.inner
			if inner == nil {
				inner = storage.NewMemory()
			}

			var before []byte
			if tt.seed != nil {
				seeder, err := New(inner, &mockSealer{canSeal: true}, nil)
				if err != nil {
					t.Fatalf("New (seeder) failed: %v", err)
				}
				if err := seeder.Put(ctx, key, tt.seed); err != nil {
					t.Fatalf("seed Put failed: %v", err)
				}
				if before, err = inner.Get(ctx, key); err != nil {
					t.Fatalf("seed Get failed: %v", err)
				}
			}

			b, err := New(inner, tt.sealer, nil)
			if err != nil {
				t.Fatalf("New failed: %v", err)
			}

			if err := tt.call(ctx, b); !errors.Is(err, tt.wantErr) {
				t.Fatalf("error = %v, want %v", err, tt.wantErr)
			}

			after, err := inner.Get(ctx, key)
			if before == nil {
				if !errors.Is(err, storage.ErrNotFound) {
					t.Fatalf("inner Get after refusal = %q, %v; want ErrNotFound", after, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("inner Get after refusal failed: %v", err)
			}
			if string(after) != string(before) {
				t.Fatalf("stored value changed on refusal: got %q, want %q", after, before)
			}
		})
	}
}

func TestPut_InnerBackendFails(t *testing.T) {
	innerErr := errors.New("inner put failed")
	inner := &mockFailingPutBackend{
		Backend: storage.NewMemory(),
		putErr:  innerErr,
	}
	sealer := &mockSealer{canSeal: true}

	b, err := New(inner, sealer, nil)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	err = b.Put(context.Background(), "key", []byte("data"))
	if err == nil {
		t.Fatal("expected error when inner Put fails")
	}
	if !errors.Is(err, innerErr) {
		t.Fatalf("expected inner put error to be propagated, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Delete tests
// ---------------------------------------------------------------------------

func TestDelete_Success(t *testing.T) {
	b := newTestBackend(t)

	key := "delete/me"
	if err := b.Put(context.Background(), key, []byte("temp")); err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	if err := b.Delete(context.Background(), key); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	_, err := b.Get(context.Background(), key)
	if !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("expected ErrNotFound after delete, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// List tests
// ---------------------------------------------------------------------------

func TestList_ReturnsKeys(t *testing.T) {
	b := newTestBackend(t)

	keys := []string{"ns/alpha", "ns/beta", "ns/gamma", "other/delta"}
	for _, k := range keys {
		if err := b.Put(context.Background(), k, []byte("v")); err != nil {
			t.Fatalf("Put(%q) failed: %v", k, err)
		}
	}

	got, err := b.List(context.Background(), "ns/")
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("expected 3 keys with prefix 'ns/', got %d: %v", len(got), got)
	}
}

// ---------------------------------------------------------------------------
// Exists tests
// ---------------------------------------------------------------------------

func TestExists_True(t *testing.T) {
	b := newTestBackend(t)

	key := "exists/key"
	if err := b.Put(context.Background(), key, []byte("data")); err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	exists, err := b.Exists(context.Background(), key)
	if err != nil {
		t.Fatalf("Exists failed: %v", err)
	}
	if !exists {
		t.Fatal("expected key to exist")
	}
}

// ---------------------------------------------------------------------------
// Scan tests
// ---------------------------------------------------------------------------

func TestScan_ReturnsDecryptedPairs(t *testing.T) {
	b := newTestBackend(t)

	entries := map[string][]byte{
		"ns/alpha": []byte("first"),
		"ns/beta":  []byte("second"),
		"ns/gamma": []byte("third"),
	}
	for k, v := range entries {
		if err := b.Put(context.Background(), k, v); err != nil {
			t.Fatalf("Put(%q) failed: %v", k, err)
		}
	}
	// A key outside the prefix must not reach fn.
	if err := b.Put(context.Background(), "other/key", []byte("outside")); err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	got := make(map[string][]byte)
	err := b.Scan(context.Background(), "ns/", func(key string, value []byte) error {
		got[key] = value
		return nil
	})
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("expected 3 pairs, got %d", len(got))
	}
	for k, want := range entries {
		v, ok := got[k]
		if !ok {
			t.Fatalf("Scan missing key %q", k)
		}
		if string(v) != string(want) {
			t.Fatalf("Scan(%q) = %q, want %q", k, v, want)
		}
	}
}

func TestScan_AfterClose(t *testing.T) {
	b := newTestBackend(t)

	if err := b.Put(context.Background(), "key", []byte("value")); err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	if err := b.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	err := b.Scan(context.Background(), "", func(_ string, _ []byte) error { return nil })
	if err == nil {
		t.Fatal("expected error from Scan after close")
	}
	if !errors.Is(err, storage.ErrClosed) {
		t.Fatalf("expected storage.ErrClosed, got %v", err)
	}
}

func TestScan_UnsealFails(t *testing.T) {
	inner := storage.NewMemory()
	sealer := &mockSealer{canSeal: true}

	b, err := New(inner, sealer, nil)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	// Store a valid sealed value.
	if err := b.Put(context.Background(), "key", []byte("data")); err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	// Inject an unseal error before Scan.
	sealer.unsealErr = errors.New("unseal broken")

	err = b.Scan(context.Background(), "", func(_ string, _ []byte) error { return nil })
	if err == nil {
		t.Fatal("expected error when unseal fails during Scan")
	}
	if !errors.Is(err, ErrUnsealFailed) {
		t.Fatalf("expected ErrUnsealFailed, got %v", err)
	}
}

func TestScan_CorruptedData(t *testing.T) {
	inner := storage.NewMemory()

	// Inject corrupt (non-JSON) data directly into the inner backend.
	if err := inner.Put(context.Background(), "bad/key", []byte("not json{{{")); err != nil {
		t.Fatalf("inner Put failed: %v", err)
	}

	sealer := &mockSealer{canSeal: true}
	b, err := New(inner, sealer, nil)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	err = b.Scan(context.Background(), "", func(_ string, _ []byte) error { return nil })
	if err == nil {
		t.Fatal("expected error when Scan encounters corrupted data")
	}
	if !errors.Is(err, ErrUnmarshalFailed) {
		t.Fatalf("expected ErrUnmarshalFailed, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Close tests
// ---------------------------------------------------------------------------

func TestClose_Idempotent(t *testing.T) {
	b := newTestBackend(t)

	if err := b.Close(); err != nil {
		t.Fatalf("first Close failed: %v", err)
	}
	// MemoryBackend.Close() returns nil on subsequent calls.
	if err := b.Close(); err != nil {
		t.Fatalf("second Close failed: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Interface compliance
// ---------------------------------------------------------------------------
