// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

package known_hosts_test

import (
	"context"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/ssh/keys"
	"github.com/jeremyhahn/go-xkms/pkg/ssh/known_hosts"
	"github.com/jeremyhahn/go-xkms/pkg/ssh/scope"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// ---------------------------------------------------------------------------
// Error type Error()/Unwrap() coverage
// ---------------------------------------------------------------------------

func TestKHNilInputError_Error(t *testing.T) {
	e := &known_hosts.NilInputError{Field: "store"}
	want := "ssh/known_hosts: nil input: store"
	if e.Error() != want {
		t.Fatalf("got %q, want %q", e.Error(), want)
	}
}

func TestKHNotFoundError_Error(t *testing.T) {
	e := &known_hosts.NotFoundError{Scope: "user", Owner: "alice", Host: "bastion.example.com"}
	if e.Error() == "" {
		t.Fatal("NotFoundError.Error() empty")
	}
}

func TestKHDuplicateError_Error(t *testing.T) {
	e := &known_hosts.DuplicateError{Scope: "user", Owner: "alice", Host: "bastion.example.com"}
	if e.Error() == "" {
		t.Fatal("DuplicateError.Error() empty")
	}
}

func TestKHMismatchError_Error(t *testing.T) {
	e := &known_hosts.MismatchError{
		Host:     "bastion.example.com",
		Expected: "SHA256:expected",
		Received: "SHA256:received",
	}
	if e.Error() == "" {
		t.Fatal("MismatchError.Error() empty")
	}
}

func TestKHRejectedError_Error(t *testing.T) {
	e := &known_hosts.RejectedError{Host: "bastion.example.com", Fingerprint: "SHA256:abc"}
	want := "ssh/known_hosts: host key rejected for bastion.example.com: SHA256:abc"
	if e.Error() != want {
		t.Fatalf("got %q, want %q", e.Error(), want)
	}
}

func TestKHInvalidHostError_Error(t *testing.T) {
	e := &known_hosts.InvalidHostError{Value: "", Reason: "empty"}
	if e.Error() == "" {
		t.Fatal("InvalidHostError.Error() empty")
	}
}

func TestKHInvalidFingerprintError_Error(t *testing.T) {
	e := &known_hosts.InvalidFingerprintError{Value: "bad", Reason: "missing SHA256: prefix"}
	if e.Error() == "" {
		t.Fatal("InvalidFingerprintError.Error() empty")
	}
}

func TestKHStorageError_ErrorAndUnwrap(t *testing.T) {
	inner := errors.New("disk failure")
	e := &known_hosts.StorageError{Op: "put", Err: inner}
	if e.Error() == "" {
		t.Fatal("StorageError.Error() empty")
	}
	if !errors.Is(e, inner) {
		t.Fatal("StorageError.Unwrap() must expose inner error")
	}
}

func TestKHSerializationError_ErrorAndUnwrap(t *testing.T) {
	inner := errors.New("invalid json")
	e := &known_hosts.SerializationError{Op: "unmarshal envelope", Err: inner}
	if e.Error() == "" {
		t.Fatal("SerializationError.Error() empty")
	}
	if !errors.Is(e, inner) {
		t.Fatal("SerializationError.Unwrap() must expose inner error")
	}
}

// ---------------------------------------------------------------------------
// Store: NewBackendStore edge cases
// ---------------------------------------------------------------------------

func TestKHNewBackendStore_NilBackend(t *testing.T) {
	_, err := known_hosts.NewBackendStore(nil)
	var nie *known_hosts.NilInputError
	if !errors.As(err, &nie) {
		t.Fatalf("expected NilInputError for nil backend, got %T: %v", err, err)
	}
}

// ---------------------------------------------------------------------------
// Store.Add: various validation error paths
// ---------------------------------------------------------------------------

func TestKHStore_Add_NilPin(t *testing.T) {
	store := newStore(t)
	err := store.Add(context.Background(), nil)
	var nie *known_hosts.NilInputError
	if !errors.As(err, &nie) {
		t.Fatalf("expected NilInputError for nil pin, got %T: %v", err, err)
	}
}

func TestKHStore_Add_InvalidScope(t *testing.T) {
	store := newStore(t)
	pub := newEd25519PublicKey(t)
	err := store.Add(context.Background(), &known_hosts.Pin{
		Scope:       scope.Scope("badscope"),
		Owner:       "alice",
		Host:        "bastion.example.com",
		Fingerprint: keys.Fingerprint(pub),
	})
	if err == nil {
		t.Fatal("expected error for invalid scope in Add")
	}
}

func TestKHStore_Add_EmptyOwner(t *testing.T) {
	store := newStore(t)
	pub := newEd25519PublicKey(t)
	err := store.Add(context.Background(), &known_hosts.Pin{
		Scope:       scope.User,
		Owner:       "",
		Host:        "bastion.example.com",
		Fingerprint: keys.Fingerprint(pub),
	})
	if err == nil {
		t.Fatal("expected error for empty owner in Add")
	}
}

func TestKHStore_Add_InvalidHost(t *testing.T) {
	store := newStore(t)
	pub := newEd25519PublicKey(t)
	err := store.Add(context.Background(), &known_hosts.Pin{
		Scope:       scope.User,
		Owner:       "alice",
		Host:        "bad/host",
		Fingerprint: keys.Fingerprint(pub),
	})
	var ihe *known_hosts.InvalidHostError
	if !errors.As(err, &ihe) {
		t.Fatalf("expected InvalidHostError for host with slash, got %T: %v", err, err)
	}
}

func TestKHStore_Add_InvalidFingerprint(t *testing.T) {
	store := newStore(t)
	err := store.Add(context.Background(), &known_hosts.Pin{
		Scope:       scope.User,
		Owner:       "alice",
		Host:        "bastion.example.com",
		Fingerprint: "not-a-valid-fingerprint",
	})
	var ife *known_hosts.InvalidFingerprintError
	if !errors.As(err, &ife) {
		t.Fatalf("expected InvalidFingerprintError, got %T: %v", err, err)
	}
}

func TestKHStore_Add_ZeroAddedAt(t *testing.T) {
	// AddedAt zero triggers the time.Now() backfill. Confirm no error.
	store := newStore(t)
	pub := newEd25519PublicKey(t)
	err := store.Add(context.Background(), &known_hosts.Pin{
		Scope:       scope.User,
		Owner:       "alice",
		Host:        "bastion.example.com",
		Fingerprint: keys.Fingerprint(pub),
		PublicKey:   pub.Marshal(),
		// AddedAt intentionally zero
	})
	if err != nil {
		t.Fatalf("Add with zero AddedAt: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Store.Get: invalid scope and non-ErrNotFound storage error
// ---------------------------------------------------------------------------

func TestKHStore_Get_InvalidScope(t *testing.T) {
	store := newStore(t)
	_, err := store.Get(context.Background(), scope.Scope("badscope"), "alice", "bastion.example.com")
	if err == nil {
		t.Fatal("expected error for invalid scope in Get")
	}
}

func TestKHStore_Get_StorageError(t *testing.T) {
	store, err := known_hosts.NewBackendStore(khFailingBackend{})
	if err != nil {
		t.Fatalf("NewBackendStore: %v", err)
	}
	_, err = store.Get(context.Background(), scope.User, "alice", "bastion.example.com")
	var se *known_hosts.StorageError
	if !errors.As(err, &se) {
		t.Fatalf("expected StorageError, got %T: %v", err, err)
	}
}

func TestKHStore_Get_CorruptEnvelope(t *testing.T) {
	store, err := known_hosts.NewBackendStore(khCorruptBackend{})
	if err != nil {
		t.Fatalf("NewBackendStore: %v", err)
	}
	_, err = store.Get(context.Background(), scope.User, "alice", "bastion.example.com")
	var se *known_hosts.SerializationError
	if !errors.As(err, &se) {
		t.Fatalf("expected SerializationError for corrupt envelope, got %T: %v", err, err)
	}
}

// ---------------------------------------------------------------------------
// Store.List: invalid scope, owner-with-slash, StorageError, corrupt envelope
// ---------------------------------------------------------------------------

func TestKHStore_List_InvalidScope(t *testing.T) {
	store := newStore(t)
	_, err := store.List(context.Background(), scope.Scope("badscope"), "")
	if err == nil {
		t.Fatal("expected error for invalid scope in List")
	}
}

func TestKHStore_List_OwnerWithSlash(t *testing.T) {
	store := newStore(t)
	_, err := store.List(context.Background(), scope.User, "alice/bad")
	if err == nil {
		t.Fatal("expected error for owner with slash in List")
	}
}

func TestKHStore_List_StorageError(t *testing.T) {
	store, err := known_hosts.NewBackendStore(khFailingBackend{})
	if err != nil {
		t.Fatalf("NewBackendStore: %v", err)
	}
	_, err = store.List(context.Background(), scope.User, "alice")
	var se *known_hosts.StorageError
	if !errors.As(err, &se) {
		t.Fatalf("expected StorageError on scan failure, got %T: %v", err, err)
	}
}

func TestKHStore_List_CorruptEnvelope(t *testing.T) {
	store, err := known_hosts.NewBackendStore(khCorruptBackend{})
	if err != nil {
		t.Fatalf("NewBackendStore: %v", err)
	}
	_, err = store.List(context.Background(), scope.User, "alice")
	if err == nil {
		t.Fatal("expected error for corrupt envelope in List")
	}
}

// ---------------------------------------------------------------------------
// Store.Remove: invalid scope, non-ErrNotFound storage error
// ---------------------------------------------------------------------------

func TestKHStore_Remove_InvalidScope(t *testing.T) {
	store := newStore(t)
	err := store.Remove(context.Background(), scope.Scope("badscope"), "alice", "bastion.example.com")
	if err == nil {
		t.Fatal("expected error for invalid scope in Remove")
	}
}

func TestKHStore_Remove_StorageError(t *testing.T) {
	store, err := known_hosts.NewBackendStore(khRemoveErrBackend{})
	if err != nil {
		t.Fatalf("NewBackendStore: %v", err)
	}
	err = store.Remove(context.Background(), scope.User, "alice", "bastion.example.com")
	var se *known_hosts.StorageError
	if !errors.As(err, &se) {
		t.Fatalf("expected StorageError on non-ErrNotFound delete, got %T: %v", err, err)
	}
}

// ---------------------------------------------------------------------------
// Verify: nil inputs
// ---------------------------------------------------------------------------

func TestKHVerify_NilStore(t *testing.T) {
	pub := newEd25519PublicKey(t)
	err := known_hosts.Verify(context.Background(), nil, scope.User, "alice", "bastion.example.com", pub)
	var nie *known_hosts.NilInputError
	if !errors.As(err, &nie) {
		t.Fatalf("expected NilInputError for nil store, got %T: %v", err, err)
	}
}

func TestKHVerify_NilReceived(t *testing.T) {
	store := newStore(t)
	err := known_hosts.Verify(context.Background(), store, scope.User, "alice", "bastion.example.com", nil)
	var nie *known_hosts.NilInputError
	if !errors.As(err, &nie) {
		t.Fatalf("expected NilInputError for nil received, got %T: %v", err, err)
	}
}

// ---------------------------------------------------------------------------
// callback: stripPort — host without port (no ':')
// ---------------------------------------------------------------------------

func TestKHStripPort_NoPort(t *testing.T) {
	// Callback strips the port before calling Verify. When the hostname
	// has no port SplitHostPort fails gracefully and the hostname is used
	// as-is. Exercise this via Callback with a bare hostname.
	store := newStore(t)
	ctx := context.Background()
	pub := newEd25519PublicKey(t)
	if err := store.Add(ctx, &known_hosts.Pin{
		Host:        "bastion.example.com",
		Fingerprint: keys.Fingerprint(pub),
		Algorithm:   pub.Type(),
		PublicKey:   pub.Marshal(),
		Scope:       scope.User,
		Owner:       "alice",
	}); err != nil {
		t.Fatalf("Add: %v", err)
	}
	cb := known_hosts.Callback(ctx, store, scope.User, "alice")
	// Pass the hostname WITHOUT a port — exercises the stripPort fallback path.
	if err := cb("bastion.example.com", nil, pub); err != nil {
		t.Fatalf("Callback with bare host: %v", err)
	}
}

// ---------------------------------------------------------------------------
// decodeEnvelope: invalid scope in stored envelope
// ---------------------------------------------------------------------------

func TestKHStore_Get_InvalidScopeInEnvelope(t *testing.T) {
	env := `{"v":1,"scope":"INVALID","owner":"alice","host":"bastion.example.com","fp":"SHA256:abc","added":"2025-01-01T00:00:00Z"}`
	store, err := known_hosts.NewBackendStore(&khPayloadBackend{data: []byte(env)})
	if err != nil {
		t.Fatalf("NewBackendStore: %v", err)
	}
	_, err = store.Get(context.Background(), scope.User, "alice", "bastion.example.com")
	if err == nil {
		t.Fatal("expected error for invalid scope in stored envelope")
	}
}

// ---------------------------------------------------------------------------
// v1 (fingerprint-only) pins: no full-key matching, no new fingerprint-only
// pins, and List skips rather than aborts on one.
// ---------------------------------------------------------------------------

// legacyV1Envelope is a pre-v2 stored envelope: a fingerprint but no "pub"
// field, exactly what a pin recorded before PublicKey existed looks like on
// disk.
const legacyV1Envelope = `{"v":1,"scope":"user","owner":"alice","host":"bastion.example.com","fp":"SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU","added":"2025-01-01T00:00:00Z"}`

// TestKHStore_Get_LegacyPinRequiresRepin proves a v1 (fingerprint-only)
// stored pin is not silently accepted: Get fails closed with
// *LegacyPinError rather than returning a Pin with an empty PublicKey.
func TestKHStore_Get_LegacyPinRequiresRepin(t *testing.T) {
	store, err := known_hosts.NewBackendStore(&khPayloadBackend{data: []byte(legacyV1Envelope)})
	if err != nil {
		t.Fatalf("NewBackendStore: %v", err)
	}
	_, err = store.Get(context.Background(), scope.User, "alice", "bastion.example.com")
	var legacy *known_hosts.LegacyPinError
	if !errors.As(err, &legacy) {
		t.Fatalf("expected LegacyPinError, got %T: %v", err, err)
	}
	if legacy.Host != "bastion.example.com" {
		t.Fatalf("Host = %q, want bastion.example.com", legacy.Host)
	}
}

// TestKHVerify_LegacyPinRequiresRepin proves Verify propagates the same
// fail-closed rejection: a v1 pin can no longer be matched against, whether
// or not the presented key is the one that was originally pinned.
func TestKHVerify_LegacyPinRequiresRepin(t *testing.T) {
	store, err := known_hosts.NewBackendStore(&khPayloadBackend{data: []byte(legacyV1Envelope)})
	if err != nil {
		t.Fatalf("NewBackendStore: %v", err)
	}
	pub := newEd25519PublicKey(t)
	err = known_hosts.Verify(context.Background(), store, scope.User, "alice", "bastion.example.com", pub)
	var legacy *known_hosts.LegacyPinError
	if !errors.As(err, &legacy) {
		t.Fatalf("expected LegacyPinError, got %T: %v", err, err)
	}
}

// TestKHStore_List_SkipsLegacyPin proves List discovery is not blocked by
// one unmatchable v1 pin in scope: it is skipped, not surfaced as a scan
// failure that would hide every other pin under the same prefix.
func TestKHStore_List_SkipsLegacyPin(t *testing.T) {
	store, err := known_hosts.NewBackendStore(&khPayloadBackend{data: []byte(legacyV1Envelope)})
	if err != nil {
		t.Fatalf("NewBackendStore: %v", err)
	}
	pins, err := store.List(context.Background(), scope.User, "alice")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(pins) != 0 {
		t.Fatalf("expected legacy pin to be skipped, got %d pins", len(pins))
	}
}

// TestKHStore_Add_RequiresPublicKey proves a new pin cannot be created
// fingerprint-only: Store.Add now requires a PublicKey.
func TestKHStore_Add_RequiresPublicKey(t *testing.T) {
	store := newStore(t)
	pub := newEd25519PublicKey(t)
	err := store.Add(context.Background(), &known_hosts.Pin{
		Scope:       scope.User,
		Owner:       "alice",
		Host:        "bastion.example.com",
		Fingerprint: keys.Fingerprint(pub),
		// PublicKey intentionally omitted.
	})
	var req *known_hosts.PublicKeyRequiredError
	if !errors.As(err, &req) {
		t.Fatalf("expected PublicKeyRequiredError, got %T: %v", err, err)
	}
}

// ---------------------------------------------------------------------------
// Add: StorageError from backend.Exists + Put failures
// ---------------------------------------------------------------------------

func TestKHStore_Add_ExistsStorageError(t *testing.T) {
	store, err := known_hosts.NewBackendStore(khFailingBackend{})
	if err != nil {
		t.Fatalf("NewBackendStore: %v", err)
	}
	pub := newEd25519PublicKey(t)
	err = store.Add(context.Background(), &known_hosts.Pin{
		Scope:       scope.User,
		Owner:       "alice",
		Host:        "bastion.example.com",
		Fingerprint: keys.Fingerprint(pub),
		PublicKey:   pub.Marshal(),
	})
	var se *known_hosts.StorageError
	if !errors.As(err, &se) {
		t.Fatalf("expected StorageError on Exists failure, got %T: %v", err, err)
	}
}

func TestKHStore_Add_PutStorageError(t *testing.T) {
	store, err := known_hosts.NewBackendStore(khPutFailBackend{})
	if err != nil {
		t.Fatalf("NewBackendStore: %v", err)
	}
	pub := newEd25519PublicKey(t)
	err = store.Add(context.Background(), &known_hosts.Pin{
		Scope:       scope.User,
		Owner:       "alice",
		Host:        "bastion.example.com",
		Fingerprint: keys.Fingerprint(pub),
		PublicKey:   pub.Marshal(),
	})
	var se *known_hosts.StorageError
	if !errors.As(err, &se) {
		t.Fatalf("expected StorageError on Put failure, got %T: %v", err, err)
	}
}

// ---------------------------------------------------------------------------
// Failing backends
// ---------------------------------------------------------------------------

var errKHFail = errors.New("injected backend failure")

// khFailingBackend always fails on every operation.
type khFailingBackend struct{}

func (khFailingBackend) Get(_ context.Context, _ string) ([]byte, error) { return nil, errKHFail }
func (khFailingBackend) Put(_ context.Context, _ string, _ []byte) error { return errKHFail }
func (khFailingBackend) PutIfAbsent(_ context.Context, _ string, _ []byte) (bool, error) {
	return false, errKHFail
}

// CompareAndDelete mirrors khFailingBackend.Delete: it always returns errKHFail.
func (khFailingBackend) CompareAndDelete(_ context.Context, _ string, _ []byte) (bool, error) {
	return false, errKHFail
}
func (khFailingBackend) Delete(_ context.Context, _ string) error { return errKHFail }
func (khFailingBackend) List(_ context.Context, _ string) ([]string, error) {
	return nil, errKHFail
}
func (khFailingBackend) Scan(_ context.Context, _ string, _ func(string, []byte) error) error {
	return errKHFail
}
func (khFailingBackend) Exists(_ context.Context, _ string) (bool, error) { return false, errKHFail }
func (khFailingBackend) Close() error                                     { return nil }

// khCorruptBackend returns corrupt JSON from Get and Scan.
type khCorruptBackend struct{ khFailingBackend }

func (khCorruptBackend) Get(_ context.Context, _ string) ([]byte, error) {
	return []byte("{{{not json"), nil
}
func (khCorruptBackend) Exists(_ context.Context, _ string) (bool, error) { return false, nil }
func (khCorruptBackend) Scan(_ context.Context, _ string, fn func(string, []byte) error) error {
	return fn("k", []byte("{{{not json"))
}

// khPutFailBackend lets Exists succeed (returns not present) but fails Put.
type khPutFailBackend struct{ khFailingBackend }

func (khPutFailBackend) Exists(_ context.Context, _ string) (bool, error) { return false, nil }

// khRemoveErrBackend fails Delete with a non-ErrNotFound error.
type khRemoveErrBackend struct{ khFailingBackend }

func (khRemoveErrBackend) Exists(_ context.Context, _ string) (bool, error) { return false, nil }
func (khRemoveErrBackend) Delete(_ context.Context, _ string) error         { return errKHFail }

// khPayloadBackend returns caller-provided bytes for Get.
type khPayloadBackend struct {
	data []byte
}

func (b *khPayloadBackend) Get(_ context.Context, _ string) ([]byte, error) {
	return b.data, nil
}
func (b *khPayloadBackend) Scan(_ context.Context, _ string, fn func(string, []byte) error) error {
	return fn("k", b.data)
}
func (b *khPayloadBackend) Put(_ context.Context, _ string, _ []byte) error { return nil }
func (b *khPayloadBackend) PutIfAbsent(_ context.Context, _ string, _ []byte) (bool, error) {
	return true, nil
}

// CompareAndDelete mirrors khPayloadBackend.Delete, which always succeeds: it
// reports the key as removed.
func (b *khPayloadBackend) CompareAndDelete(_ context.Context, _ string, _ []byte) (bool, error) {
	return true, nil
}
func (b *khPayloadBackend) Delete(_ context.Context, _ string) error           { return nil }
func (b *khPayloadBackend) List(_ context.Context, _ string) ([]string, error) { return nil, nil }
func (b *khPayloadBackend) Exists(_ context.Context, _ string) (bool, error)   { return true, nil }
func (b *khPayloadBackend) Close() error                                       { return nil }

// Compile-time check that test backends implement storage.Backend.
var (
	_ storage.Backend = khFailingBackend{}
	_ storage.Backend = khCorruptBackend{}
	_ storage.Backend = khPutFailBackend{}
	_ storage.Backend = khRemoveErrBackend{}
	_ storage.Backend = (*khPayloadBackend)(nil)
)
