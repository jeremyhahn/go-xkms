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

package webauthn

import (
	"context"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// errStoreFault is a generic non-sentinel storage fault used to exercise the
// wrapped-error branches of BackendUserStore/BackendCredentialStore. It is
// deliberately not storage.ErrNotFound.
var errStoreFault = errors.New("backend_stores_gaps: storage unavailable")

// faultyStore wraps a real storage.Backend and forces an error on selected
// exact keys for selected operations, letting tests drive the wrapped-error
// branches of BackendUserStore/BackendCredentialStore without a live backend
// fault.
type faultyStore struct {
	storage.Backend

	getErr    map[string]error
	putErr    map[string]error
	deleteErr map[string]error
	existsErr map[string]error
}

func newFaultyStore() *faultyStore {
	return &faultyStore{
		Backend:   storage.NewMemory(),
		getErr:    map[string]error{},
		putErr:    map[string]error{},
		deleteErr: map[string]error{},
		existsErr: map[string]error{},
	}
}

func (f *faultyStore) Get(ctx context.Context, key string) ([]byte, error) {
	if err, ok := f.getErr[key]; ok {
		return nil, err
	}
	return f.Backend.Get(ctx, key)
}

func (f *faultyStore) Put(ctx context.Context, key string, value []byte) error {
	if err, ok := f.putErr[key]; ok {
		return err
	}
	return f.Backend.Put(ctx, key, value)
}

func (f *faultyStore) PutIfAbsent(ctx context.Context, key string, value []byte) (bool, error) {
	if err, ok := f.putErr[key]; ok {
		return false, err
	}
	return f.Backend.PutIfAbsent(ctx, key, value)
}

func (f *faultyStore) Delete(ctx context.Context, key string) error {
	if err, ok := f.deleteErr[key]; ok {
		return err
	}
	return f.Backend.Delete(ctx, key)
}

func (f *faultyStore) Exists(ctx context.Context, key string) (bool, error) {
	if err, ok := f.existsErr[key]; ok {
		return false, err
	}
	return f.Backend.Exists(ctx, key)
}

// ----- BackendUserStore: unmarshal / decode branches -----

func TestBackendUserStore_GetByID_UnmarshalError(t *testing.T) {
	ctx := context.Background()
	mem := storage.NewMemory()
	uid := []byte{1, 2, 3}
	if err := mem.Put(ctx, userKey(uid), []byte("not-json")); err != nil {
		t.Fatalf("seed: %v", err)
	}
	_, err := NewBackendUserStore(mem).GetByID(ctx, uid)
	var wae *WebAuthnError
	if !errors.As(err, &wae) {
		t.Fatalf("GetByID(corrupt record) = %v, want *WebAuthnError", err)
	}
}

func TestBackendUserStore_GetByEmail_DecodeIndexError(t *testing.T) {
	ctx := context.Background()
	mem := storage.NewMemory()
	if err := mem.Put(ctx, emailKey("bad@example.com"), []byte("not-hex!!")); err != nil {
		t.Fatalf("seed: %v", err)
	}
	_, err := NewBackendUserStore(mem).GetByEmail(ctx, "bad@example.com")
	var wae *WebAuthnError
	if !errors.As(err, &wae) {
		t.Fatalf("GetByEmail(corrupt index) = %v, want *WebAuthnError", err)
	}
}

// ----- BackendUserStore: backend faults distinct from not-found -----

func TestBackendUserStore_GetByID_BackendFault(t *testing.T) {
	ctx := context.Background()
	uid := []byte{7, 7, 7}
	fs := newFaultyStore()
	fs.getErr[userKey(uid)] = errStoreFault
	_, err := NewBackendUserStore(fs).GetByID(ctx, uid)
	if errors.Is(err, ErrUserNotFound) {
		t.Fatal("a real backend fault must not be classified as not-found")
	}
	var wae *WebAuthnError
	if !errors.As(err, &wae) || !errors.Is(err, errStoreFault) {
		t.Fatalf("GetByID(backend fault) = %v, want wrapped errStoreFault", err)
	}
}

func TestBackendUserStore_GetByEmail_BackendFault(t *testing.T) {
	ctx := context.Background()
	fs := newFaultyStore()
	fs.getErr[emailKey("fault@example.com")] = errStoreFault
	_, err := NewBackendUserStore(fs).GetByEmail(ctx, "fault@example.com")
	if errors.Is(err, ErrUserNotFound) {
		t.Fatal("a real backend fault must not be classified as not-found")
	}
	if !errors.Is(err, errStoreFault) {
		t.Fatalf("GetByEmail(backend fault) = %v, want wrapped errStoreFault", err)
	}
}

func TestBackendUserStore_Create_ExistsError(t *testing.T) {
	ctx := context.Background()
	fs := newFaultyStore()
	fs.existsErr[emailKey("exists-fault@example.com")] = errStoreFault
	_, err := NewBackendUserStore(fs).Create(ctx, "exists-fault@example.com", "Fault")
	if !errors.Is(err, errStoreFault) {
		t.Fatalf("Create(exists fault) = %v, want wrapped errStoreFault", err)
	}
}

func TestBackendUserStore_Create_PutUserError(t *testing.T) {
	ctx := context.Background()
	email := "put-fault@example.com"
	uid := GenerateUserID(email)
	fs := newFaultyStore()
	fs.putErr[userKey(uid)] = errStoreFault
	_, err := NewBackendUserStore(fs).Create(ctx, email, "Fault")
	if !errors.Is(err, errStoreFault) {
		t.Fatalf("Create(put-user fault) = %v, want wrapped errStoreFault", err)
	}
}

func TestBackendUserStore_Create_PutEmailIndexError(t *testing.T) {
	ctx := context.Background()
	email := "put-index-fault@example.com"
	fs := newFaultyStore()
	fs.putErr[emailKey(email)] = errStoreFault
	_, err := NewBackendUserStore(fs).Create(ctx, email, "Fault")
	if !errors.Is(err, errStoreFault) {
		t.Fatalf("Create(put-email-index fault) = %v, want wrapped errStoreFault", err)
	}
}

func TestBackendUserStore_Save_InvalidUserType(t *testing.T) {
	store := NewBackendUserStore(storage.NewMemory())
	if err := store.Save(context.Background(), nil); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("Save(nil user) = %v, want ErrInvalidRequest", err)
	}
}

func TestBackendUserStore_Delete_DeleteUserError(t *testing.T) {
	ctx := context.Background()
	email := "delete-fault@example.com"
	fs := newFaultyStore()
	store := NewBackendUserStore(fs)
	u, err := store.Create(ctx, email, "Fault")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	fs.deleteErr[userKey(u.WebAuthnID())] = errStoreFault
	if err := store.Delete(ctx, u.WebAuthnID()); !errors.Is(err, errStoreFault) {
		t.Fatalf("Delete(user delete fault) = %v, want wrapped errStoreFault", err)
	}
}

func TestBackendUserStore_Delete_DeleteEmailIndexError(t *testing.T) {
	ctx := context.Background()
	email := "delete-index-fault@example.com"
	fs := newFaultyStore()
	store := NewBackendUserStore(fs)
	u, err := store.Create(ctx, email, "Fault")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	fs.deleteErr[emailKey(email)] = errStoreFault
	if err := store.Delete(ctx, u.WebAuthnID()); !errors.Is(err, errStoreFault) {
		t.Fatalf("Delete(email-index delete fault) = %v, want wrapped errStoreFault", err)
	}
}

// ----- BackendCredentialStore: backend faults -----

func TestBackendCredentialStore_GetByCredentialID_BackendFault(t *testing.T) {
	ctx := context.Background()
	credID := []byte{9}
	fs := newFaultyStore()
	fs.getErr[backendCredKey(credID)] = errStoreFault
	_, err := NewBackendCredentialStore(fs).GetByCredentialID(ctx, credID)
	if errors.Is(err, ErrCredentialNotFound) {
		t.Fatal("a real backend fault must not be classified as not-found")
	}
	if !errors.Is(err, errStoreFault) {
		t.Fatalf("GetByCredentialID(backend fault) = %v, want wrapped errStoreFault", err)
	}
}

func TestBackendCredentialStore_GetByCredentialID_UnmarshalError(t *testing.T) {
	ctx := context.Background()
	mem := storage.NewMemory()
	credID := []byte{5, 5}
	if err := mem.Put(ctx, backendCredKey(credID), []byte("not-json")); err != nil {
		t.Fatalf("seed: %v", err)
	}
	_, err := NewBackendCredentialStore(mem).GetByCredentialID(ctx, credID)
	var wae *WebAuthnError
	if !errors.As(err, &wae) {
		t.Fatalf("GetByCredentialID(corrupt blob) = %v, want *WebAuthnError", err)
	}
}

func TestBackendCredentialStore_Save_PutCredentialError(t *testing.T) {
	ctx := context.Background()
	cred := &Credential{ID: []byte{1}, UserID: []byte{2}}
	fs := newFaultyStore()
	fs.putErr[backendCredKey(cred.ID)] = errStoreFault
	if err := NewBackendCredentialStore(fs).Save(ctx, cred); !errors.Is(err, errStoreFault) {
		t.Fatalf("Save(put-credential fault) = %v, want wrapped errStoreFault", err)
	}
}

func TestBackendCredentialStore_Save_PutUserIndexError(t *testing.T) {
	ctx := context.Background()
	cred := &Credential{ID: []byte{3}, UserID: []byte{4}}
	fs := newFaultyStore()
	fs.putErr[credByUserKey(cred.UserID, cred.ID)] = errStoreFault
	if err := NewBackendCredentialStore(fs).Save(ctx, cred); !errors.Is(err, errStoreFault) {
		t.Fatalf("Save(put-user-index fault) = %v, want wrapped errStoreFault", err)
	}
}

func TestBackendCredentialStore_GetByUserID_ListError(t *testing.T) {
	ctx := context.Background()
	store := NewBackendCredentialStore(&listErrBackend{Backend: storage.NewMemory(), err: errStoreFault})
	if _, err := store.GetByUserID(ctx, []byte{1}); !errors.Is(err, errStoreFault) {
		t.Fatalf("GetByUserID(list fault) = %v, want wrapped errStoreFault", err)
	}
}

// listErrBackend forces List to fail, independent of any per-key map, since
// List keys are prefix-derived rather than a single fixed key.
type listErrBackend struct {
	storage.Backend
	err error
}

func (b *listErrBackend) List(ctx context.Context, prefix string) ([]string, error) {
	return nil, b.err
}

func TestBackendCredentialStore_Update_GetError(t *testing.T) {
	ctx := context.Background()
	cred := &Credential{ID: []byte{6}, UserID: []byte{7}}
	fs := newFaultyStore()
	fs.getErr[backendCredKey(cred.ID)] = errStoreFault
	if err := NewBackendCredentialStore(fs).Update(ctx, cred); !errors.Is(err, errStoreFault) {
		t.Fatalf("Update(get fault) = %v, want wrapped errStoreFault", err)
	}
}

func TestBackendCredentialStore_Delete_KVDeleteCredError(t *testing.T) {
	ctx := context.Background()
	fs := newFaultyStore()
	store := NewBackendCredentialStore(fs)
	cred := &Credential{ID: []byte{8}, UserID: []byte{9}}
	if err := store.Save(ctx, cred); err != nil {
		t.Fatalf("seed: %v", err)
	}
	fs.deleteErr[backendCredKey(cred.ID)] = errStoreFault
	if err := store.Delete(ctx, cred.ID); !errors.Is(err, errStoreFault) {
		t.Fatalf("Delete(cred delete fault) = %v, want wrapped errStoreFault", err)
	}
}

func TestBackendCredentialStore_Delete_KVDeleteIndexError(t *testing.T) {
	ctx := context.Background()
	fs := newFaultyStore()
	store := NewBackendCredentialStore(fs)
	cred := &Credential{ID: []byte{10}, UserID: []byte{11}}
	if err := store.Save(ctx, cred); err != nil {
		t.Fatalf("seed: %v", err)
	}
	fs.deleteErr[credByUserKey(cred.UserID, cred.ID)] = errStoreFault
	if err := store.Delete(ctx, cred.ID); !errors.Is(err, errStoreFault) {
		t.Fatalf("Delete(user-index delete fault) = %v, want wrapped errStoreFault", err)
	}
}

func TestBackendCredentialStore_DeleteByUserID_PropagatesRealError(t *testing.T) {
	ctx := context.Background()
	fs := newFaultyStore()
	store := NewBackendCredentialStore(fs)
	userID := []byte{12}
	cred := &Credential{ID: []byte{13}, UserID: userID}
	if err := store.Save(ctx, cred); err != nil {
		t.Fatalf("seed: %v", err)
	}
	fs.deleteErr[backendCredKey(cred.ID)] = errStoreFault
	err := store.DeleteByUserID(ctx, userID)
	if !errors.Is(err, errStoreFault) {
		t.Fatalf("DeleteByUserID(propagated fault) = %v, want wrapped errStoreFault", err)
	}
}
