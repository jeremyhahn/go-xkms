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

package authorized_test

import (
	"context"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/dao"
	"github.com/jeremyhahn/go-xkms/pkg/ssh/authorized"
	"github.com/jeremyhahn/go-xkms/pkg/ssh/keys"
	"github.com/jeremyhahn/go-xkms/pkg/ssh/scope"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/storage/kvadapter"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
)

// ---------------------------------------------------------------------------
// failingBackend is a storage.Backend whose operations always return errFail.
// It implements the guarded writes, so the DAO over it is atomic and every
// failure is the backend's. Used to exercise StorageError wrapping paths.
// ---------------------------------------------------------------------------

var errFail = errors.New("injected backend failure")

type failingBackend struct{}

func (failingBackend) Get(_ context.Context, _ string) ([]byte, error) { return nil, errFail }
func (failingBackend) Put(_ context.Context, _ string, _ []byte) error { return errFail }
func (failingBackend) PutIfAbsent(_ context.Context, _ string, _ []byte) (bool, error) {
	return false, errFail
}
func (failingBackend) CompareAndSwap(_ context.Context, _ string, _, _ []byte) (bool, []byte, error) {
	return false, nil, errFail
}
func (failingBackend) CompareAndDelete(_ context.Context, _ string, _ []byte) (bool, error) {
	return false, errFail
}
func (failingBackend) Delete(_ context.Context, _ string) error { return errFail }
func (failingBackend) List(_ context.Context, _ string) ([]string, error) {
	return nil, errFail
}
func (failingBackend) Scan(_ context.Context, _ string, _ func(string, []byte) error) error {
	return errFail
}
func (failingBackend) Exists(_ context.Context, _ string) (bool, error) { return false, errFail }
func (failingBackend) Close() error                                     { return nil }

// corruptBackend serves every value it stores as undecodable bytes.
type corruptBackend struct{ storage.Backend }

// CompareAndSwap forwards to the wrapped backend, keeping the DAO atomic.
func (b corruptBackend) CompareAndSwap(ctx context.Context, key string, expected, next []byte) (bool, []byte, error) {
	return b.Backend.(storage.CompareAndSwapper).CompareAndSwap(ctx, key, expected, next)
}

// CompareAndDelete forwards to the wrapped backend, keeping the DAO atomic.
func (b corruptBackend) CompareAndDelete(ctx context.Context, key string, expected []byte) (bool, error) {
	return b.Backend.(storage.CompareAndDeleter).CompareAndDelete(ctx, key, expected)
}

func (b corruptBackend) Get(ctx context.Context, key string) ([]byte, error) {
	if _, err := b.Backend.Get(ctx, key); err != nil {
		return nil, err
	}
	return []byte("not-json{{{"), nil
}
func (b corruptBackend) Scan(ctx context.Context, prefix string, fn func(string, []byte) error) error {
	return b.Backend.Scan(ctx, prefix, func(key string, _ []byte) error {
		return fn(key, []byte("not-json{{{"))
	})
}

// newStore returns a DAOStore over a fresh in-memory DAO factory.
func newStore(t *testing.T) *authorized.DAOStore {
	t.Helper()
	store, err := authorized.NewDAOStore(testutil.NewMemoryDAOFactory())
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	return store
}

// storeOver returns the DAOStore over backend.
func storeOver(t *testing.T, backend storage.Backend) *authorized.DAOStore {
	t.Helper()
	kv, err := kvadapter.New(backend)
	if err != nil {
		t.Fatalf("kvadapter.New: %v", err)
	}
	store, err := authorized.NewDAOStore(dao.NewStoreFactory(kv))
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	return store
}

// corruptStore returns a DAOStore whose records -- the user entry
// alice/laptop and the tenant entry acme/deploy -- read back undecodable.
func corruptStore(t *testing.T) *authorized.DAOStore {
	t.Helper()
	backend := storage.New()
	clean := storeOver(t, backend)
	k := generateKey(t, keys.AlgorithmEd25519)
	defer k.Destroy()
	ctx := context.Background()
	if err := clean.Add(ctx, scope.User, "alice", "laptop", &authorized.Entry{Key: k}); err != nil {
		t.Fatalf("seed user entry: %v", err)
	}
	if err := clean.Add(ctx, scope.Tenant, "acme", "deploy", &authorized.Entry{Key: k}); err != nil {
		t.Fatalf("seed tenant entry: %v", err)
	}
	return storeOver(t, corruptBackend{Backend: backend})
}

// ---------------------------------------------------------------------------
// Error type string/unwrap coverage
// ---------------------------------------------------------------------------

func TestNilInputError_Error(t *testing.T) {
	e := &authorized.NilInputError{Field: "entry"}
	want := "ssh/authorized: nil input: entry"
	if e.Error() != want {
		t.Fatalf("NilInputError.Error() = %q, want %q", e.Error(), want)
	}
}

func TestMalformedLineError_ErrorAndUnwrap(t *testing.T) {
	inner := errors.New("parse failure")
	e := &authorized.MalformedLineError{Line: "bad line", Err: inner}
	if e.Error() == "" {
		t.Fatal("MalformedLineError.Error() empty")
	}
	if !errors.Is(e, inner) {
		t.Fatal("MalformedLineError.Unwrap() must expose inner error")
	}
}

func TestNotFoundError_Error(t *testing.T) {
	e := &authorized.NotFoundError{Scope: "user", Owner: "alice", Name: "laptop"}
	if e.Error() == "" {
		t.Fatal("NotFoundError.Error() empty")
	}
}

func TestDuplicateError_Error(t *testing.T) {
	e := &authorized.DuplicateError{Scope: "user", Owner: "alice", Name: "laptop"}
	if e.Error() == "" {
		t.Fatal("DuplicateError.Error() empty")
	}
}

func TestInvalidNameError_Error(t *testing.T) {
	e := &authorized.InvalidNameError{Value: "", Reason: "empty"}
	if e.Error() == "" {
		t.Fatal("InvalidNameError.Error() empty")
	}
}

func TestStorageError_ErrorAndUnwrap(t *testing.T) {
	inner := errors.New("disk I/O error")
	e := &authorized.StorageError{Op: "put", Err: inner}
	if e.Error() == "" {
		t.Fatal("StorageError.Error() empty")
	}
	if !errors.Is(e, inner) {
		t.Fatal("StorageError.Unwrap() must expose inner error")
	}
}

// ---------------------------------------------------------------------------
// Emit edge cases
// ---------------------------------------------------------------------------

func TestEmit_NilPublicKey(t *testing.T) {
	// Entry with Key set but Key.PublicKey nil.
	_, err := authorized.Emit(&authorized.Entry{Key: &keys.Key{PublicKey: nil}})
	var nie *authorized.NilInputError
	if !errors.As(err, &nie) {
		t.Fatalf("expected NilInputError for nil Key.PublicKey, got %T: %v", err, err)
	}
}

func TestEmitAll_Empty(t *testing.T) {
	block, err := authorized.EmitAll(nil)
	if err != nil {
		t.Fatalf("EmitAll(nil): %v", err)
	}
	if block != "" {
		t.Fatalf("EmitAll(nil) should return empty string, got %q", block)
	}
}

func TestEmitAll_ErrorPropagates(t *testing.T) {
	// Mix valid + invalid entry; EmitAll must propagate the error.
	good := generateKey(t, keys.AlgorithmEd25519)
	defer good.Destroy()
	entries := []*authorized.Entry{
		{Key: good},
		{Key: nil}, // will fail
	}
	_, err := authorized.EmitAll(entries)
	var nie *authorized.NilInputError
	if !errors.As(err, &nie) {
		t.Fatalf("expected NilInputError from EmitAll with nil-key entry, got %T: %v", err, err)
	}
}

// ---------------------------------------------------------------------------
// ParseLine edge cases
// ---------------------------------------------------------------------------

func TestParseLine_CommentLine(t *testing.T) {
	_, err := authorized.ParseLine("# a comment")
	var m *authorized.MalformedLineError
	if !errors.As(err, &m) {
		t.Fatalf("expected MalformedLineError for comment line, got %T: %v", err, err)
	}
	if err.Error() == "" {
		t.Fatal("MalformedLineError.Error() returned empty string for comment line")
	}
}

func TestParseLine_EmptyLine(t *testing.T) {
	_, err := authorized.ParseLine("")
	var m *authorized.MalformedLineError
	if !errors.As(err, &m) {
		t.Fatalf("expected MalformedLineError for empty line, got %T: %v", err, err)
	}
	if err.Error() == "" {
		t.Fatal("MalformedLineError.Error() returned empty string")
	}
}

// ---------------------------------------------------------------------------
// Store edge cases: invalid scope, name, owner
// ---------------------------------------------------------------------------

func TestNewDAOStore_NilFactory(t *testing.T) {
	_, err := authorized.NewDAOStore(nil)
	var nie *authorized.NilInputError
	if !errors.As(err, &nie) {
		t.Fatalf("expected NilInputError for nil factory, got %T: %v", err, err)
	}
}

func TestStore_Add_InvalidScope(t *testing.T) {
	store := newStore(t)
	var err error
	k := generateKey(t, keys.AlgorithmEd25519)
	defer k.Destroy()
	err = store.Add(context.Background(), scope.Scope("bogus"), "owner", "name", &authorized.Entry{Key: k})
	if err == nil {
		t.Fatal("expected error for invalid scope")
	}
}

func TestStore_Add_EmptyOwner(t *testing.T) {
	store := newStore(t)
	var err error
	k := generateKey(t, keys.AlgorithmEd25519)
	defer k.Destroy()
	err = store.Add(context.Background(), scope.User, "", "name", &authorized.Entry{Key: k})
	if err == nil {
		t.Fatal("expected error for empty owner")
	}
}

func TestStore_Add_OwnerWithSlash(t *testing.T) {
	store := newStore(t)
	var err error
	k := generateKey(t, keys.AlgorithmEd25519)
	defer k.Destroy()
	err = store.Add(context.Background(), scope.User, "alice/mallory", "name", &authorized.Entry{Key: k})
	if err == nil {
		t.Fatal("expected error for owner containing slash")
	}
}

func TestStore_Add_EmptyName(t *testing.T) {
	store := newStore(t)
	var err error
	k := generateKey(t, keys.AlgorithmEd25519)
	defer k.Destroy()
	err = store.Add(context.Background(), scope.User, "alice", "", &authorized.Entry{Key: k})
	if err == nil {
		t.Fatal("expected error for empty name")
	}
	var inv *authorized.InvalidNameError
	if !errors.As(err, &inv) {
		t.Fatalf("expected InvalidNameError, got %T: %v", err, err)
	}
}

func TestStore_Add_NameWithSlash(t *testing.T) {
	store := newStore(t)
	var err error
	k := generateKey(t, keys.AlgorithmEd25519)
	defer k.Destroy()
	err = store.Add(context.Background(), scope.User, "alice", "path/separator", &authorized.Entry{Key: k})
	if err == nil {
		t.Fatal("expected error for name containing slash")
	}
	var inv *authorized.InvalidNameError
	if !errors.As(err, &inv) {
		t.Fatalf("expected InvalidNameError, got %T: %v", err, err)
	}
}

func TestStore_Add_NilEntry(t *testing.T) {
	store := newStore(t)
	err := store.Add(context.Background(), scope.User, "alice", "laptop", nil)
	if err == nil {
		t.Fatal("expected error for nil entry")
	}
	var nie *authorized.NilInputError
	if !errors.As(err, &nie) {
		t.Fatalf("expected NilInputError, got %T: %v", err, err)
	}
}

func TestStore_Remove_NotFound(t *testing.T) {
	store := newStore(t)
	err := store.Remove(context.Background(), scope.User, "alice", "ghost")
	var nf *authorized.NotFoundError
	if !errors.As(err, &nf) {
		t.Fatalf("expected NotFoundError on missing remove, got %T: %v", err, err)
	}
}

func TestStore_Remove_InvalidScope(t *testing.T) {
	store := newStore(t)
	err := store.Remove(context.Background(), scope.Scope("badscope"), "alice", "laptop")
	if err == nil {
		t.Fatal("expected error for invalid scope in Remove")
	}
}

func TestStore_Get_InvalidScope(t *testing.T) {
	store := newStore(t)
	var err error
	_, err = store.Get(context.Background(), scope.Scope("badscope"), "alice", "laptop")
	if err == nil {
		t.Fatal("expected error for invalid scope in Get")
	}
}

func TestStore_List_InvalidScope(t *testing.T) {
	store := newStore(t)
	var err error
	_, err = store.List(context.Background(), scope.Scope("invalid"), "")
	if err == nil {
		t.Fatal("expected error for invalid scope in List")
	}
}

func TestStore_List_OwnerWithSlash(t *testing.T) {
	store := newStore(t)
	var err error
	_, err = store.List(context.Background(), scope.User, "alice/bad")
	if err == nil {
		t.Fatal("expected error for owner with slash in List")
	}
}

// ---------------------------------------------------------------------------
// Verify edge cases
// ---------------------------------------------------------------------------

func TestVerify_NilStore(t *testing.T) {
	k := generateKey(t, keys.AlgorithmEd25519)
	defer k.Destroy()
	_, err := authorized.Verify(context.Background(), nil, scope.User, "alice", k.PublicKey)
	var nie *authorized.NilInputError
	if !errors.As(err, &nie) {
		t.Fatalf("expected NilInputError for nil store, got %T: %v", err, err)
	}
}

func TestVerify_NilReceived(t *testing.T) {
	store := newStore(t)
	var err error
	_, err = authorized.Verify(context.Background(), store, scope.User, "alice", nil)
	var nie *authorized.NilInputError
	if !errors.As(err, &nie) {
		t.Fatalf("expected NilInputError for nil received key, got %T: %v", err, err)
	}
}

// ---------------------------------------------------------------------------
// parseErr.Error() coverage — call .Error() on a MalformedLineError that
// wraps one of the internal sentinel errors (errEmptyLine / errCommentLine).
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// validateName: NUL byte in name
// ---------------------------------------------------------------------------

func TestStore_Add_NameWithNUL(t *testing.T) {
	store := newStore(t)
	var err error
	k := generateKey(t, keys.AlgorithmEd25519)
	defer k.Destroy()
	err = store.Add(context.Background(), scope.User, "alice", "name\x00bad", &authorized.Entry{Key: k})
	if err == nil {
		t.Fatal("expected error for name containing NUL byte")
	}
	var inv *authorized.InvalidNameError
	if !errors.As(err, &inv) {
		t.Fatalf("expected InvalidNameError, got %T: %v", err, err)
	}
}

// ---------------------------------------------------------------------------
// Storage error paths: failingBackend triggers StorageError on Add/Get/List/Remove
// ---------------------------------------------------------------------------

func TestStore_Add_StorageError_Exists(t *testing.T) {
	store := storeOver(t, failingBackend{})
	var err error
	k := generateKey(t, keys.AlgorithmEd25519)
	defer k.Destroy()
	err = store.Add(context.Background(), scope.User, "alice", "laptop", &authorized.Entry{Key: k})
	var se *authorized.StorageError
	if !errors.As(err, &se) {
		t.Fatalf("expected StorageError, got %T: %v", err, err)
	}
}

func TestStore_Get_StorageError(t *testing.T) {
	store := storeOver(t, failingBackend{})
	var err error
	_, err = store.Get(context.Background(), scope.User, "alice", "laptop")
	var se *authorized.StorageError
	if !errors.As(err, &se) {
		t.Fatalf("expected StorageError, got %T: %v", err, err)
	}
}

func TestStore_List_StorageError(t *testing.T) {
	store := storeOver(t, failingBackend{})
	var err error
	_, err = store.List(context.Background(), scope.User, "alice")
	var se *authorized.StorageError
	if !errors.As(err, &se) {
		t.Fatalf("expected StorageError, got %T: %v", err, err)
	}
}

func TestStore_Remove_StorageError(t *testing.T) {
	store := storeOver(t, failingBackend{})
	err := store.Remove(context.Background(), scope.User, "alice", "laptop")
	var se *authorized.StorageError
	if !errors.As(err, &se) {
		t.Fatalf("expected StorageError, got %T: %v", err, err)
	}
}

// TestVerify_ListError ensures Verify propagates list errors.
func TestVerify_ListError(t *testing.T) {
	// Use a store whose List fails.
	store := storeOver(t, failingBackend{})
	var err error
	k := generateKey(t, keys.AlgorithmEd25519)
	defer k.Destroy()
	_, err = authorized.Verify(context.Background(), store, scope.User, "alice", k.PublicKey)
	if err == nil {
		t.Fatal("expected error from Verify when list fails")
	}
}

// TestParseAll_MalformedLine ensures ParseAll propagates errors from ParseLine.
func TestParseAll_MalformedLine(t *testing.T) {
	// Feed a file with one valid line and one malformed non-comment line.
	k := generateKey(t, keys.AlgorithmEd25519)
	defer k.Destroy()
	validLine, err := authorized.Emit(&authorized.Entry{Key: k})
	if err != nil {
		t.Fatalf("emit: %v", err)
	}
	data := []byte(validLine + "\nnot-a-valid-key-line\n")
	_, err = authorized.ParseAll(data)
	var m *authorized.MalformedLineError
	if !errors.As(err, &m) {
		t.Fatalf("expected MalformedLineError from ParseAll, got %T: %v", err, err)
	}
}

// ---------------------------------------------------------------------------
// Undecodable records surface as StorageError
// ---------------------------------------------------------------------------

func TestStore_Get_CorruptRecord(t *testing.T) {
	_, err := corruptStore(t).Get(context.Background(), scope.User, "alice", "laptop")
	var se *authorized.StorageError
	if !errors.As(err, &se) {
		t.Fatalf("expected StorageError for corrupt record, got %T: %v", err, err)
	}
}

// ---------------------------------------------------------------------------
// Verify: list returns entries with nil Key (nil-key guard path in Verify)
// ---------------------------------------------------------------------------

// nilKeyStore is a Store whose reads yield degenerate Records: an Entry
// with a nil Key, a Record with a nil Entry, and a nil Record.
type nilKeyStore struct{}

func (nilKeyStore) Add(_ context.Context, _ scope.Scope, _, _ string, _ *authorized.Entry) error {
	return nil
}
func (nilKeyStore) Get(_ context.Context, _ scope.Scope, _, _ string) (*authorized.Record, error) {
	return &authorized.Record{Name: "nilkey", Entry: &authorized.Entry{Key: nil}}, nil
}
func (nilKeyStore) List(_ context.Context, _ scope.Scope, _ string) ([]*authorized.Record, error) {
	// Exercise all three guard branches in Verify.
	return []*authorized.Record{
		{Name: "nilkey", Entry: &authorized.Entry{Key: nil}},
		{Name: "nilentry"},
		nil,
	}, nil
}
func (nilKeyStore) Remove(_ context.Context, _ scope.Scope, _, _ string) error { return nil }

func TestVerify_EntryWithNilKey(t *testing.T) {
	k := generateKey(t, keys.AlgorithmEd25519)
	defer k.Destroy()
	// List returns entries with nil / nil-Key — Verify must skip them and
	// eventually return NotFoundError.
	_, err := authorized.Verify(context.Background(), nilKeyStore{}, scope.User, "alice", k.PublicKey)
	var nf *authorized.NotFoundError
	if !errors.As(err, &nf) {
		t.Fatalf("expected NotFoundError after nil-key entries, got %T: %v", err, err)
	}
}
