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

	"github.com/jeremyhahn/go-xkms/pkg/ssh/authorized"
	"github.com/jeremyhahn/go-xkms/pkg/ssh/keys"
	"github.com/jeremyhahn/go-xkms/pkg/ssh/scope"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// ---------------------------------------------------------------------------
// failingBackend is a storage.Backend whose operations always return errFail.
// Used to exercise StorageError wrapping paths.
// ---------------------------------------------------------------------------

var errFail = errors.New("injected backend failure")

type failingBackend struct{}

func (failingBackend) Get(_ context.Context, _ string) ([]byte, error) { return nil, errFail }
func (failingBackend) Put(_ context.Context, _ string, _ []byte) error { return errFail }
func (failingBackend) PutIfAbsent(_ context.Context, _ string, _ []byte) (bool, error) {
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

// corruptBackend returns corrupt JSON for every Get and reports Exists=false.
type corruptBackend struct{ failingBackend }

func (corruptBackend) Exists(_ context.Context, _ string) (bool, error) { return false, nil }
func (corruptBackend) Get(_ context.Context, _ string) ([]byte, error) {
	return []byte("not-json{{{"), nil
}
func (corruptBackend) Put(_ context.Context, _ string, _ []byte) error { return nil }
func (corruptBackend) Scan(_ context.Context, _ string, fn func(string, []byte) error) error {
	return fn("key", []byte("not-json{{{"))
}

// putFailBackend reports Exists=false but fails on Put.
type putFailBackend struct{ failingBackend }

func (putFailBackend) Exists(_ context.Context, _ string) (bool, error) { return false, nil }

// removeErrBackend fails Delete with a non-ErrNotFound error.
type removeErrBackend struct{ failingBackend }

func (removeErrBackend) Exists(_ context.Context, _ string) (bool, error) { return false, nil }
func (removeErrBackend) Delete(_ context.Context, _ string) error         { return errFail }

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

func TestSerializationError_ErrorAndUnwrap(t *testing.T) {
	inner := errors.New("invalid JSON")
	e := &authorized.SerializationError{Op: "marshal envelope", Err: inner}
	if e.Error() == "" {
		t.Fatal("SerializationError.Error() empty")
	}
	if !errors.Is(e, inner) {
		t.Fatal("SerializationError.Unwrap() must expose inner error")
	}
}

// ---------------------------------------------------------------------------
// Emit edge cases
// ---------------------------------------------------------------------------

func TestEmit_NilKey_InEntry(t *testing.T) {
	// Entry with nil Key.
	_, err := authorized.Emit(&authorized.Entry{Key: nil})
	var nie *authorized.NilInputError
	if !errors.As(err, &nie) {
		t.Fatalf("expected NilInputError for nil Key, got %T: %v", err, err)
	}
}

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
	if err == nil {
		t.Fatal("expected error from EmitAll with nil-key entry")
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
}

func TestParseLine_EmptyLine(t *testing.T) {
	_, err := authorized.ParseLine("")
	var m *authorized.MalformedLineError
	if !errors.As(err, &m) {
		t.Fatalf("expected MalformedLineError for empty line, got %T: %v", err, err)
	}
}

// TestParseLine_UnsupportedAlgorithm checks that an algorithm the package
// doesn't recognise produces a MalformedLineError. We can't easily forge
// such a key through the normal path so we rely on the existing table
// (AlgorithmFromPublicKey will accept ed25519/rsa/ecdsa; other types would
// trigger the error path but are hard to generate via standard Go crypto).
// We instead verify the happy path for all supported algos to confirm
// AlgorithmFromPublicKey is exercised.
func TestParseLine_AllAlgorithms(t *testing.T) {
	algos := []keys.Algorithm{
		keys.AlgorithmEd25519,
		keys.AlgorithmECDSAP256,
		keys.AlgorithmECDSAP384,
		keys.AlgorithmECDSAP521,
	}
	for _, algo := range algos {
		t.Run(string(algo), func(t *testing.T) {
			k := generateKey(t, algo)
			defer k.Destroy()
			line, err := authorized.Emit(&authorized.Entry{Key: k, Comment: "test"})
			if err != nil {
				t.Fatalf("Emit: %v", err)
			}
			entry, err := authorized.ParseLine(line)
			if err != nil {
				t.Fatalf("ParseLine: %v", err)
			}
			if entry.Key.Fingerprint != k.Fingerprint {
				t.Fatalf("fingerprint mismatch after round-trip for %s", algo)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Store edge cases: invalid scope, name, owner
// ---------------------------------------------------------------------------

func TestNewBackendStore_NilBackend(t *testing.T) {
	_, err := authorized.NewBackendStore(nil)
	var nie *authorized.NilInputError
	if !errors.As(err, &nie) {
		t.Fatalf("expected NilInputError for nil backend, got %T: %v", err, err)
	}
}

func TestStore_Add_InvalidScope(t *testing.T) {
	backend, err := storage.NewMemoryBackend()
	if err != nil {
		t.Fatalf("backend: %v", err)
	}
	store, err := authorized.NewBackendStore(backend)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	k := generateKey(t, keys.AlgorithmEd25519)
	defer k.Destroy()
	err = store.Add(context.Background(), scope.Scope("bogus"), "owner", "name", &authorized.Entry{Key: k})
	if err == nil {
		t.Fatal("expected error for invalid scope")
	}
}

func TestStore_Add_EmptyOwner(t *testing.T) {
	backend, err := storage.NewMemoryBackend()
	if err != nil {
		t.Fatalf("backend: %v", err)
	}
	store, err := authorized.NewBackendStore(backend)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	k := generateKey(t, keys.AlgorithmEd25519)
	defer k.Destroy()
	err = store.Add(context.Background(), scope.User, "", "name", &authorized.Entry{Key: k})
	if err == nil {
		t.Fatal("expected error for empty owner")
	}
}

func TestStore_Add_OwnerWithSlash(t *testing.T) {
	backend, err := storage.NewMemoryBackend()
	if err != nil {
		t.Fatalf("backend: %v", err)
	}
	store, err := authorized.NewBackendStore(backend)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	k := generateKey(t, keys.AlgorithmEd25519)
	defer k.Destroy()
	err = store.Add(context.Background(), scope.User, "alice/mallory", "name", &authorized.Entry{Key: k})
	if err == nil {
		t.Fatal("expected error for owner containing slash")
	}
}

func TestStore_Add_EmptyName(t *testing.T) {
	backend, err := storage.NewMemoryBackend()
	if err != nil {
		t.Fatalf("backend: %v", err)
	}
	store, err := authorized.NewBackendStore(backend)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
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
	backend, err := storage.NewMemoryBackend()
	if err != nil {
		t.Fatalf("backend: %v", err)
	}
	store, err := authorized.NewBackendStore(backend)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
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
	backend, err := storage.NewMemoryBackend()
	if err != nil {
		t.Fatalf("backend: %v", err)
	}
	store, err := authorized.NewBackendStore(backend)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	err = store.Add(context.Background(), scope.User, "alice", "laptop", nil)
	if err == nil {
		t.Fatal("expected error for nil entry")
	}
	var nie *authorized.NilInputError
	if !errors.As(err, &nie) {
		t.Fatalf("expected NilInputError, got %T: %v", err, err)
	}
}

func TestStore_Remove_NotFound(t *testing.T) {
	backend, err := storage.NewMemoryBackend()
	if err != nil {
		t.Fatalf("backend: %v", err)
	}
	store, err := authorized.NewBackendStore(backend)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	err = store.Remove(context.Background(), scope.User, "alice", "ghost")
	var nf *authorized.NotFoundError
	if !errors.As(err, &nf) {
		t.Fatalf("expected NotFoundError on missing remove, got %T: %v", err, err)
	}
}

func TestStore_Remove_InvalidScope(t *testing.T) {
	backend, err := storage.NewMemoryBackend()
	if err != nil {
		t.Fatalf("backend: %v", err)
	}
	store, err := authorized.NewBackendStore(backend)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	err = store.Remove(context.Background(), scope.Scope("badscope"), "alice", "laptop")
	if err == nil {
		t.Fatal("expected error for invalid scope in Remove")
	}
}

func TestStore_Get_InvalidScope(t *testing.T) {
	backend, err := storage.NewMemoryBackend()
	if err != nil {
		t.Fatalf("backend: %v", err)
	}
	store, err := authorized.NewBackendStore(backend)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	_, err = store.Get(context.Background(), scope.Scope("badscope"), "alice", "laptop")
	if err == nil {
		t.Fatal("expected error for invalid scope in Get")
	}
}

func TestStore_List_AllScopes(t *testing.T) {
	backend, err := storage.NewMemoryBackend()
	if err != nil {
		t.Fatalf("backend: %v", err)
	}
	store, err := authorized.NewBackendStore(backend)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	ctx := context.Background()

	// Add entries under two different scopes.
	k1 := generateKey(t, keys.AlgorithmEd25519)
	defer k1.Destroy()
	k2 := generateKey(t, keys.AlgorithmEd25519)
	defer k2.Destroy()
	if err := store.Add(ctx, scope.User, "alice", "laptop", &authorized.Entry{Key: k1}); err != nil {
		t.Fatalf("Add user: %v", err)
	}
	if err := store.Add(ctx, scope.Tenant, "acme", "shared", &authorized.Entry{Key: k2}); err != nil {
		t.Fatalf("Add tenant: %v", err)
	}

	// List with empty scope → all entries.
	all, err := store.List(ctx, scope.Scope(""), "")
	if err != nil {
		t.Fatalf("List all: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(all))
	}
}

func TestStore_List_InvalidScope(t *testing.T) {
	backend, err := storage.NewMemoryBackend()
	if err != nil {
		t.Fatalf("backend: %v", err)
	}
	store, err := authorized.NewBackendStore(backend)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	_, err = store.List(context.Background(), scope.Scope("invalid"), "")
	if err == nil {
		t.Fatal("expected error for invalid scope in List")
	}
}

func TestStore_List_OwnerWithSlash(t *testing.T) {
	backend, err := storage.NewMemoryBackend()
	if err != nil {
		t.Fatalf("backend: %v", err)
	}
	store, err := authorized.NewBackendStore(backend)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
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
	backend, err := storage.NewMemoryBackend()
	if err != nil {
		t.Fatalf("backend: %v", err)
	}
	store, err := authorized.NewBackendStore(backend)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
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

func TestParseLine_EmptyLine_ErrorString(t *testing.T) {
	_, err := authorized.ParseLine("")
	if err == nil {
		t.Fatal("expected error")
	}
	msg := err.Error()
	if msg == "" {
		t.Fatal("MalformedLineError.Error() returned empty string")
	}
	// The inner parseErr.Error() is exercised through MalformedLineError.Error().
}

func TestParseLine_CommentLine_ErrorString(t *testing.T) {
	_, err := authorized.ParseLine("# comment line")
	if err == nil {
		t.Fatal("expected error")
	}
	if err.Error() == "" {
		t.Fatal("MalformedLineError.Error() returned empty string for comment line")
	}
}

// ---------------------------------------------------------------------------
// validateName: NUL byte in name
// ---------------------------------------------------------------------------

func TestStore_Add_NameWithNUL(t *testing.T) {
	backend, err := storage.NewMemoryBackend()
	if err != nil {
		t.Fatalf("backend: %v", err)
	}
	store, err := authorized.NewBackendStore(backend)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
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
	store, err := authorized.NewBackendStore(failingBackend{})
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	k := generateKey(t, keys.AlgorithmEd25519)
	defer k.Destroy()
	err = store.Add(context.Background(), scope.User, "alice", "laptop", &authorized.Entry{Key: k})
	var se *authorized.StorageError
	if !errors.As(err, &se) {
		t.Fatalf("expected StorageError, got %T: %v", err, err)
	}
}

func TestStore_Get_StorageError(t *testing.T) {
	store, err := authorized.NewBackendStore(failingBackend{})
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	_, err = store.Get(context.Background(), scope.User, "alice", "laptop")
	var se *authorized.StorageError
	if !errors.As(err, &se) {
		t.Fatalf("expected StorageError, got %T: %v", err, err)
	}
}

func TestStore_List_StorageError(t *testing.T) {
	store, err := authorized.NewBackendStore(failingBackend{})
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	_, err = store.List(context.Background(), scope.User, "alice")
	var se *authorized.StorageError
	if !errors.As(err, &se) {
		t.Fatalf("expected StorageError, got %T: %v", err, err)
	}
}

func TestStore_Remove_StorageError(t *testing.T) {
	store, err := authorized.NewBackendStore(failingBackend{})
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	err = store.Remove(context.Background(), scope.User, "alice", "laptop")
	var se *authorized.StorageError
	if !errors.As(err, &se) {
		t.Fatalf("expected StorageError, got %T: %v", err, err)
	}
}

func TestStore_Remove_NonNotFoundStorageError(t *testing.T) {
	store, err := authorized.NewBackendStore(removeErrBackend{})
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	err = store.Remove(context.Background(), scope.User, "alice", "laptop")
	var se *authorized.StorageError
	if !errors.As(err, &se) {
		t.Fatalf("expected StorageError on non-ErrNotFound delete, got %T: %v", err, err)
	}
}

func TestStore_Add_PutStorageError(t *testing.T) {
	store, err := authorized.NewBackendStore(putFailBackend{})
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	k := generateKey(t, keys.AlgorithmEd25519)
	defer k.Destroy()
	err = store.Add(context.Background(), scope.User, "alice", "laptop", &authorized.Entry{Key: k})
	var se *authorized.StorageError
	if !errors.As(err, &se) {
		t.Fatalf("expected StorageError on put failure, got %T: %v", err, err)
	}
}

// TestVerify_ListError ensures Verify propagates list errors.
func TestVerify_ListError(t *testing.T) {
	// Use a store whose List fails.
	store, err := authorized.NewBackendStore(failingBackend{})
	if err != nil {
		t.Fatalf("store: %v", err)
	}
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
// decodeEnvelope: corrupt JSON triggers SerializationError from Get path
// ---------------------------------------------------------------------------

func TestStore_Get_CorruptEnvelope(t *testing.T) {
	store, err := authorized.NewBackendStore(corruptBackend{})
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	_, err = store.Get(context.Background(), scope.User, "alice", "laptop")
	var se *authorized.SerializationError
	if !errors.As(err, &se) {
		t.Fatalf("expected SerializationError for corrupt envelope, got %T: %v", err, err)
	}
}

func TestStore_List_CorruptEnvelope(t *testing.T) {
	store, err := authorized.NewBackendStore(corruptBackend{})
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	_, err = store.List(context.Background(), scope.User, "alice")
	if err == nil {
		t.Fatal("expected error for corrupt envelope in List")
	}
}

// ---------------------------------------------------------------------------
// Verify: list returns entries with nil Key (nil-key guard path in Verify)
// ---------------------------------------------------------------------------

// nilKeyStore is a Store that returns one Entry with nil Key.
type nilKeyStore struct{}

func (nilKeyStore) Add(_ context.Context, _ scope.Scope, _, _ string, _ *authorized.Entry) error {
	return nil
}
func (nilKeyStore) Get(_ context.Context, _ scope.Scope, _, _ string) (*authorized.Entry, error) {
	return &authorized.Entry{Key: nil}, nil
}
func (nilKeyStore) List(_ context.Context, _ scope.Scope, _ string) ([]*authorized.Entry, error) {
	// Return one entry with nil Key and one nil entry to exercise both guard branches.
	return []*authorized.Entry{{Key: nil}, nil}, nil
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
