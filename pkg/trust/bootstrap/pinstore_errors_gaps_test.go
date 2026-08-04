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

package bootstrap

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-truststrap/pkg/truststrap"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// =============================================================================
// fakeErrBackend — a storage.Backend that returns configurable errors from
// each method. Used to deterministically exercise StoragePinStore's
// non-not-found error-wrapping branches without any real I/O.
// =============================================================================

type fakeErrBackend struct {
	storage.Backend // embed a real memory backend so unconfigured methods behave normally

	getErr    error
	putErr    error
	deleteErr error
	scanErr   error
}

func newFakeErrBackend() *fakeErrBackend {
	return &fakeErrBackend{Backend: storage.NewMemory()}
}

func (f *fakeErrBackend) Get(ctx context.Context, key string) ([]byte, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	return f.Backend.Get(ctx, key)
}

func (f *fakeErrBackend) Put(ctx context.Context, key string, value []byte) error {
	if f.putErr != nil {
		return f.putErr
	}
	return f.Backend.Put(ctx, key, value)
}

func (f *fakeErrBackend) Delete(ctx context.Context, key string) error {
	if f.deleteErr != nil {
		return f.deleteErr
	}
	return f.Backend.Delete(ctx, key)
}

func (f *fakeErrBackend) Scan(ctx context.Context, prefix string, fn func(key string, value []byte) error) error {
	if f.scanErr != nil {
		return f.scanErr
	}
	return f.Backend.Scan(ctx, prefix, fn)
}

// =============================================================================
// Error / Unwrap methods — every typed pin-store error
// =============================================================================

func TestNilBackendError_Error(t *testing.T) {
	err := NilBackendError{}
	if !strings.Contains(err.Error(), "must not be nil") {
		t.Fatalf("NilBackendError.Error() = %q, want it to mention nil backend", err.Error())
	}
}

func TestPinStoreGetError_ErrorAndUnwrap(t *testing.T) {
	cause := errors.New("boom")
	err := &PinStoreGetError{Key: "trust/tofu/pins/x", Err: cause}
	if !strings.Contains(err.Error(), "trust/tofu/pins/x") || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("PinStoreGetError.Error() = %q, want it to contain key and cause", err.Error())
	}
	if !errors.Is(err, cause) {
		t.Fatalf("errors.Is(err, cause) = false, want true (Unwrap must expose cause)")
	}
}

func TestPinStorePutError_ErrorAndUnwrap(t *testing.T) {
	cause := errors.New("disk full")
	err := &PinStorePutError{Key: "trust/tofu/pins/y", Err: cause}
	if !strings.Contains(err.Error(), "trust/tofu/pins/y") || !strings.Contains(err.Error(), "disk full") {
		t.Fatalf("PinStorePutError.Error() = %q, want it to contain key and cause", err.Error())
	}
	if !errors.Is(err, cause) {
		t.Fatalf("errors.Is(err, cause) = false, want true (Unwrap must expose cause)")
	}
}

func TestPinStoreDeleteError_ErrorAndUnwrap(t *testing.T) {
	cause := errors.New("permission denied")
	err := &PinStoreDeleteError{Key: "trust/tofu/pins/z", Err: cause}
	if !strings.Contains(err.Error(), "trust/tofu/pins/z") || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("PinStoreDeleteError.Error() = %q, want it to contain key and cause", err.Error())
	}
	if !errors.Is(err, cause) {
		t.Fatalf("errors.Is(err, cause) = false, want true (Unwrap must expose cause)")
	}
}

func TestPinStoreListError_ErrorAndUnwrap(t *testing.T) {
	cause := errors.New("scan aborted")
	err := &PinStoreListError{Err: cause}
	if !strings.Contains(err.Error(), "scan aborted") {
		t.Fatalf("PinStoreListError.Error() = %q, want it to contain cause", err.Error())
	}
	if !errors.Is(err, cause) {
		t.Fatalf("errors.Is(err, cause) = false, want true (Unwrap must expose cause)")
	}
}

// =============================================================================
// Get — backend error (not ErrNotFound) and corrupt-JSON unmarshal error
// =============================================================================

func TestStoragePinStore_Get_BackendError(t *testing.T) {
	backend := newFakeErrBackend()
	backend.getErr = errors.New("transport unavailable")
	store, err := NewStoragePinStore(backend)
	if err != nil {
		t.Fatalf("NewStoragePinStore: %v", err)
	}

	_, err = store.Get(context.Background(), "kms.example.com", 8443)
	var getErr *PinStoreGetError
	if !errors.As(err, &getErr) {
		t.Fatalf("expected *PinStoreGetError, got %T: %v", err, err)
	}
	if !strings.Contains(getErr.Error(), "transport unavailable") {
		t.Fatalf("expected wrapped cause in error string, got %q", getErr.Error())
	}
}

func TestStoragePinStore_Get_CorruptJSON(t *testing.T) {
	backend := storage.NewMemory()
	store, err := NewStoragePinStore(backend)
	if err != nil {
		t.Fatalf("NewStoragePinStore: %v", err)
	}

	// Write non-JSON bytes directly at the exact key Get will look up,
	// bypassing Put's marshaling to force a genuine json.Unmarshal failure.
	key := pinStoreKey("corrupt.example.com", 8443)
	if err := backend.Put(context.Background(), key, []byte("not-json{{{")); err != nil {
		t.Fatalf("seed corrupt record: %v", err)
	}

	_, err = store.Get(context.Background(), "corrupt.example.com", 8443)
	var getErr *PinStoreGetError
	if !errors.As(err, &getErr) {
		t.Fatalf("expected *PinStoreGetError for corrupt JSON, got %T: %v", err, err)
	}
}

// =============================================================================
// Put — json.Marshal failure and backend error
// =============================================================================

// TestStoragePinStore_Put_MarshalError forces a genuine encoding/json failure:
// time.Time.MarshalJSON rejects years outside [0, 9999], which Pin.FirstSeen
// carries verbatim into the struct's json.Marshal call.
func TestStoragePinStore_Put_MarshalError(t *testing.T) {
	store, err := NewStoragePinStore(storage.NewMemory())
	if err != nil {
		t.Fatalf("NewStoragePinStore: %v", err)
	}

	pin := &truststrap.Pin{
		Host:            "overflow.example.com",
		Port:            8443,
		SPKISHA256:      strings.Repeat("ab", 32),
		CertFingerprint: strings.Repeat("cd", 32),
		FirstSeen:       time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC), // year > 9999
		Source:          "tofu",
	}

	err = store.Put(context.Background(), pin)
	var putErr *PinStorePutError
	if !errors.As(err, &putErr) {
		t.Fatalf("expected *PinStorePutError from json.Marshal failure, got %T: %v", err, err)
	}
}

func TestStoragePinStore_Put_BackendError(t *testing.T) {
	backend := newFakeErrBackend()
	backend.putErr = errors.New("write failed")
	store, err := NewStoragePinStore(backend)
	if err != nil {
		t.Fatalf("NewStoragePinStore: %v", err)
	}

	err = store.Put(context.Background(), validPin("kms.example.com", 8443))
	var putErr *PinStorePutError
	if !errors.As(err, &putErr) {
		t.Fatalf("expected *PinStorePutError, got %T: %v", err, err)
	}
	if !strings.Contains(putErr.Error(), "write failed") {
		t.Fatalf("expected wrapped cause in error string, got %q", putErr.Error())
	}
}

// =============================================================================
// Delete — backend error distinct from idempotent ErrNotFound
// =============================================================================

func TestStoragePinStore_Delete_BackendError(t *testing.T) {
	backend := newFakeErrBackend()
	backend.deleteErr = errors.New("lock held")
	store, err := NewStoragePinStore(backend)
	if err != nil {
		t.Fatalf("NewStoragePinStore: %v", err)
	}

	err = store.Delete(context.Background(), "kms.example.com", 8443)
	var delErr *PinStoreDeleteError
	if !errors.As(err, &delErr) {
		t.Fatalf("expected *PinStoreDeleteError, got %T: %v", err, err)
	}
	if !strings.Contains(delErr.Error(), "lock held") {
		t.Fatalf("expected wrapped cause in error string, got %q", delErr.Error())
	}
}

// =============================================================================
// List — corrupt records are skipped, and a genuine Scan failure wraps
// =============================================================================

func TestStoragePinStore_List_SkipsCorruptRecord(t *testing.T) {
	backend := storage.NewMemory()
	store, err := NewStoragePinStore(backend)
	if err != nil {
		t.Fatalf("NewStoragePinStore: %v", err)
	}
	ctx := context.Background()

	// One well-formed pin via the public API...
	if err := store.Put(ctx, validPin("good.example.com", 8443)); err != nil {
		t.Fatalf("Put good pin: %v", err)
	}
	// ...and one corrupt record written directly under the same prefix,
	// bypassing Put's marshaling.
	corruptKey := pinKeyPrefix + "bad.example.com:8443"
	if err := backend.Put(ctx, corruptKey, []byte("{not valid json")); err != nil {
		t.Fatalf("seed corrupt record: %v", err)
	}

	pins, err := store.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(pins) != 1 {
		t.Fatalf("List returned %d pins, want 1 (corrupt record must be skipped, not error)", len(pins))
	}
	if pins[0].Host != "good.example.com" {
		t.Fatalf("List()[0].Host = %q, want good.example.com", pins[0].Host)
	}
}

func TestStoragePinStore_List_BackendScanError(t *testing.T) {
	backend := newFakeErrBackend()
	backend.scanErr = errors.New("scan unavailable")
	store, err := NewStoragePinStore(backend)
	if err != nil {
		t.Fatalf("NewStoragePinStore: %v", err)
	}

	_, err = store.List(context.Background())
	var listErr *PinStoreListError
	if !errors.As(err, &listErr) {
		t.Fatalf("expected *PinStoreListError, got %T: %v", err, err)
	}
	if !strings.Contains(listErr.Error(), "scan unavailable") {
		t.Fatalf("expected wrapped cause in error string, got %q", listErr.Error())
	}
}
