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

	"github.com/jeremyhahn/go-xkms/pkg/dao"
	"github.com/jeremyhahn/go-xkms/pkg/ssh/keys"
	"github.com/jeremyhahn/go-xkms/pkg/ssh/known_hosts"
	"github.com/jeremyhahn/go-xkms/pkg/ssh/scope"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/storage/kvadapter"
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
	e := &known_hosts.SerializationError{Op: "parse pin public key", Err: inner}
	if e.Error() == "" {
		t.Fatal("SerializationError.Error() empty")
	}
	if !errors.Is(e, inner) {
		t.Fatal("SerializationError.Unwrap() must expose inner error")
	}
}

// ---------------------------------------------------------------------------
// Store: NewDAOStore edge cases
// ---------------------------------------------------------------------------

func TestKHNewDAOStore_NilFactory(t *testing.T) {
	_, err := known_hosts.NewDAOStore(nil)
	var nie *known_hosts.NilInputError
	if !errors.As(err, &nie) || nie.Field != "daos" {
		t.Fatalf("expected NilInputError{daos} for nil factory, got %T: %v", err, err)
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
	_, err := storeOver(t, khFailingBackend{}).Get(context.Background(), scope.User, "alice", "bastion.example.com")
	var se *known_hosts.StorageError
	if !errors.As(err, &se) || se.Op != "get" {
		t.Fatalf("expected StorageError{get}, got %T: %v", err, err)
	}
}

func TestKHStore_Get_CorruptRecord(t *testing.T) {
	_, err := corruptStore(t).Get(context.Background(), scope.User, "alice", "bastion.example.com")
	var se *known_hosts.StorageError
	if !errors.As(err, &se) {
		t.Fatalf("expected StorageError for corrupt record, got %T: %v", err, err)
	}
}

// ---------------------------------------------------------------------------
// Store.List: invalid scope, owner-with-slash, StorageError
// ---------------------------------------------------------------------------

func TestKHStore_List_OwnerWithSlash(t *testing.T) {
	store := newStore(t)
	_, err := store.List(context.Background(), scope.User, "alice/bad")
	if err == nil {
		t.Fatal("expected error for owner with slash in List")
	}
}

func TestKHStore_List_StorageError(t *testing.T) {
	_, err := storeOver(t, khFailingBackend{}).List(context.Background(), scope.User, "alice")
	var se *known_hosts.StorageError
	if !errors.As(err, &se) || se.Op != "list" {
		t.Fatalf("expected StorageError{list} on scan failure, got %T: %v", err, err)
	}
}

// ---------------------------------------------------------------------------
// Store.Remove: invalid scope, storage errors
// ---------------------------------------------------------------------------

func TestKHStore_Remove_InvalidScope(t *testing.T) {
	store := newStore(t)
	err := store.Remove(context.Background(), scope.Scope("badscope"), "alice", "bastion.example.com")
	if err == nil {
		t.Fatal("expected error for invalid scope in Remove")
	}
}

func TestKHStore_Remove_StorageError(t *testing.T) {
	err := storeOver(t, khFailingBackend{}).Remove(context.Background(), scope.User, "alice", "bastion.example.com")
	var se *known_hosts.StorageError
	if !errors.As(err, &se) || se.Op != "delete" {
		t.Fatalf("expected StorageError{delete}, got %T: %v", err, err)
	}
	if err := corruptStore(t).Remove(context.Background(), scope.User, "alice", "bastion.example.com"); !errors.As(err, &se) {
		t.Fatalf("Remove over corrupt record: want StorageError, got %T: %v", err, err)
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
// Add: a pin must carry its full public key
// ---------------------------------------------------------------------------

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
// Add: StorageError from the DAO
// ---------------------------------------------------------------------------

func TestKHStore_Add_StorageError(t *testing.T) {
	pub := newEd25519PublicKey(t)
	err := storeOver(t, khFailingBackend{}).Add(context.Background(), &known_hosts.Pin{
		Scope:       scope.User,
		Owner:       "alice",
		Host:        "bastion.example.com",
		Fingerprint: keys.Fingerprint(pub),
		PublicKey:   pub.Marshal(),
	})
	var se *known_hosts.StorageError
	if !errors.As(err, &se) || se.Op != "put" {
		t.Fatalf("expected StorageError{put}, got %T: %v", err, err)
	}
}

// ---------------------------------------------------------------------------
// Failing backends
// ---------------------------------------------------------------------------

var errKHFail = errors.New("injected backend failure")

// khFailingBackend is a storage.Backend whose operations always fail. It
// implements the guarded writes, so the DAO over it is atomic and every
// failure is the backend's.
type khFailingBackend struct{}

func (khFailingBackend) Get(_ context.Context, _ string) ([]byte, error) { return nil, errKHFail }
func (khFailingBackend) Put(_ context.Context, _ string, _ []byte) error { return errKHFail }
func (khFailingBackend) PutIfAbsent(_ context.Context, _ string, _ []byte) (bool, error) {
	return false, errKHFail
}
func (khFailingBackend) CompareAndSwap(_ context.Context, _ string, _, _ []byte) (bool, []byte, error) {
	return false, nil, errKHFail
}
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

// khCorruptBackend serves every value it stores as undecodable bytes.
type khCorruptBackend struct{ storage.Backend }

// CompareAndSwap forwards to the wrapped backend, keeping the DAO atomic.
func (b khCorruptBackend) CompareAndSwap(ctx context.Context, key string, expected, next []byte) (bool, []byte, error) {
	return b.Backend.(storage.CompareAndSwapper).CompareAndSwap(ctx, key, expected, next)
}

// CompareAndDelete forwards to the wrapped backend, keeping the DAO atomic.
func (b khCorruptBackend) CompareAndDelete(ctx context.Context, key string, expected []byte) (bool, error) {
	return b.Backend.(storage.CompareAndDeleter).CompareAndDelete(ctx, key, expected)
}

func (b khCorruptBackend) Get(ctx context.Context, key string) ([]byte, error) {
	if _, err := b.Backend.Get(ctx, key); err != nil {
		return nil, err
	}
	return []byte("{{{not json"), nil
}
func (b khCorruptBackend) Scan(ctx context.Context, prefix string, fn func(string, []byte) error) error {
	return b.Backend.Scan(ctx, prefix, func(key string, _ []byte) error {
		return fn(key, []byte("{{{not json"))
	})
}

// storeOver returns the DAOStore over backend.
func storeOver(t *testing.T, backend storage.Backend) *known_hosts.DAOStore {
	t.Helper()
	kv, err := kvadapter.New(backend)
	if err != nil {
		t.Fatalf("kvadapter.New: %v", err)
	}
	store, err := known_hosts.NewDAOStore(dao.NewStoreFactory(kv))
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	return store
}

// corruptStore returns a DAOStore whose pins -- user alice's and tenant
// acme's, both for bastion.example.com -- read back undecodable.
func corruptStore(t *testing.T) *known_hosts.DAOStore {
	t.Helper()
	backend := storage.New()
	clean := storeOver(t, backend)
	pub := newEd25519PublicKey(t)
	ctx := context.Background()
	for _, c := range []struct {
		sc    scope.Scope
		owner string
	}{{scope.User, "alice"}, {scope.Tenant, "acme"}} {
		if err := clean.Add(ctx, known_hosts.PinFromPublicKey("bastion.example.com", c.sc, c.owner, pub, "")); err != nil {
			t.Fatalf("seed %s pin: %v", c.sc, err)
		}
	}
	return storeOver(t, khCorruptBackend{Backend: backend})
}

// Compile-time check that test backends implement storage.Backend.
var (
	_ storage.Backend = khFailingBackend{}
	_ storage.Backend = khCorruptBackend{}
)
