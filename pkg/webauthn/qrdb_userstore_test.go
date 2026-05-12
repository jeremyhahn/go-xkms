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
	"strconv"
	"strings"
	"sync"
	"testing"

	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
)

// ----- in-memory qrdbtransport.UserClient stub -----

type fakeUserClient struct {
	mu      sync.Mutex
	byID    map[string]*qrdbtransport.User
	byUname map[string]*qrdbtransport.User // tenantID|username -> user
	nextID  uint64
}

func newFakeUserClient() *fakeUserClient {
	return &fakeUserClient{
		byID:    make(map[string]*qrdbtransport.User),
		byUname: make(map[string]*qrdbtransport.User),
		nextID:  1,
	}
}

func (f *fakeUserClient) keyFor(tenantID, username string) string {
	return tenantID + "|" + username
}

func (f *fakeUserClient) CreateUser(ctx context.Context, req *qrdbtransport.CreateUserRequest) (*qrdbtransport.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	k := f.keyFor(req.TenantID, req.Username)
	if _, ok := f.byUname[k]; ok {
		return nil, errors.New("already exists")
	}
	u := &qrdbtransport.User{
		ID:       strconv.FormatUint(f.nextID, 10),
		Username: req.Username,
		TenantID: req.TenantID,
		Enabled:  true,
	}
	f.nextID++
	f.byID[u.ID] = u
	f.byUname[k] = u
	return u, nil
}

func (f *fakeUserClient) GetUser(ctx context.Context, id string) (*qrdbtransport.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, ok := f.byID[id]
	if !ok {
		return nil, errors.New("user not found")
	}
	return u, nil
}

func (f *fakeUserClient) GetUserByUsername(ctx context.Context, tenantID, username string) (*qrdbtransport.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, ok := f.byUname[f.keyFor(tenantID, username)]
	if !ok {
		return nil, errors.New("user not found")
	}
	return u, nil
}

func (f *fakeUserClient) UpdateUser(ctx context.Context, req *qrdbtransport.UpdateUserRequest) (*qrdbtransport.User, error) {
	return nil, errors.New("not implemented in stub")
}

func (f *fakeUserClient) DeleteUser(ctx context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, ok := f.byID[id]
	if !ok {
		return errors.New("user not found")
	}
	delete(f.byID, id)
	delete(f.byUname, f.keyFor(u.TenantID, u.Username))
	return nil
}

func (f *fakeUserClient) ListUsers(ctx context.Context, req *qrdbtransport.ListUsersRequest) (*qrdbtransport.ListUsersResponse, error) {
	return nil, errors.New("not implemented in stub")
}

func (f *fakeUserClient) EnableUser(ctx context.Context, id string) error {
	return nil
}

func (f *fakeUserClient) DisableUser(ctx context.Context, id string) error {
	return nil
}

// ----- in-memory qrdbtransport.KVClient stub -----

type fakeKV struct {
	mu sync.Mutex
	m  map[string][]byte
}

func newFakeKV() *fakeKV {
	return &fakeKV{m: make(map[string][]byte)}
}

func (f *fakeKV) Put(ctx context.Context, key string, value []byte, opts ...qrdbtransport.WriteOption) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := make([]byte, len(value))
	copy(cp, value)
	f.m[key] = cp
	return nil
}

func (f *fakeKV) Get(ctx context.Context, key string, opts ...qrdbtransport.ReadOption) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.m[key]
	if !ok {
		return nil, errors.New("key not found")
	}
	cp := make([]byte, len(v))
	copy(cp, v)
	return cp, nil
}

func (f *fakeKV) Delete(ctx context.Context, key string, opts ...qrdbtransport.WriteOption) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.m, key)
	return nil
}

func (f *fakeKV) Scan(ctx context.Context, prefix string, opts ...qrdbtransport.ReadOption) (map[string][]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make(map[string][]byte)
	for k, v := range f.m {
		if strings.HasPrefix(k, prefix) {
			cp := make([]byte, len(v))
			copy(cp, v)
			out[k] = cp
		}
	}
	return out, nil
}

func (f *fakeKV) List(ctx context.Context, prefix string, opts ...qrdbtransport.ReadOption) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, 0)
	for k := range f.m {
		if strings.HasPrefix(k, prefix) {
			out = append(out, k)
		}
	}
	return out, nil
}

func (f *fakeKV) Exists(ctx context.Context, key string, opts ...qrdbtransport.ReadOption) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.m[key]
	return ok, nil
}

// ----- adapter tests -----

func newTestAdapter(t *testing.T) (UserStore, CredentialStore, *fakeUserClient, *fakeKV) {
	t.Helper()
	u := newFakeUserClient()
	k := newFakeKV()
	us, cs, err := NewQRDBUserStoreAdapter(QRDBUserStoreOptions{
		Users: u, KV: k, TenantID: "system",
	})
	if err != nil {
		t.Fatalf("adapter: %v", err)
	}
	return us, cs, u, k
}

func TestQRDBAdapter_NewMissingFields(t *testing.T) {
	cases := []QRDBUserStoreOptions{
		{KV: newFakeKV(), TenantID: "system"},
		{Users: newFakeUserClient(), TenantID: "system"},
		{Users: newFakeUserClient(), KV: newFakeKV()},
	}
	for i, c := range cases {
		_, _, err := NewQRDBUserStoreAdapter(c)
		if err == nil {
			t.Fatalf("case %d: expected error", i)
		}
		var qae *QRDBAdapterConfigError
		if !errors.As(err, &qae) {
			t.Fatalf("case %d: expected *QRDBAdapterConfigError, got %T (%v)", i, err, err)
		}
	}
}

func TestQRDBAdapter_CreateAndGetByEmail(t *testing.T) {
	us, _, _, _ := newTestAdapter(t)
	ctx := context.Background()
	user, err := us.Create(ctx, "alice@example.com", "Alice")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if user.WebAuthnName() != "alice@example.com" {
		t.Fatalf("WebAuthnName: %q", user.WebAuthnName())
	}
	if user.WebAuthnDisplayName() != "Alice" {
		t.Fatalf("WebAuthnDisplayName: %q", user.WebAuthnDisplayName())
	}

	// GetByEmail should return same user
	got, err := us.GetByEmail(ctx, "alice@example.com")
	if err != nil {
		t.Fatalf("GetByEmail: %v", err)
	}
	if string(got.WebAuthnID()) != string(user.WebAuthnID()) {
		t.Fatalf("ID mismatch")
	}
}

func TestQRDBAdapter_GetByEmail_NotFound(t *testing.T) {
	us, _, _, _ := newTestAdapter(t)
	_, err := us.GetByEmail(context.Background(), "nobody@example.com")
	if !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("expected ErrUserNotFound, got %v", err)
	}
}

func TestQRDBAdapter_GetByID(t *testing.T) {
	us, _, _, _ := newTestAdapter(t)
	ctx := context.Background()
	user, err := us.Create(ctx, "bob@example.com", "Bob")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	got, err := us.GetByID(ctx, user.WebAuthnID())
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.WebAuthnName() != "bob@example.com" {
		t.Fatalf("name mismatch")
	}
}

func TestQRDBAdapter_GetByID_Empty(t *testing.T) {
	us, _, _, _ := newTestAdapter(t)
	_, err := us.GetByID(context.Background(), nil)
	if !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("expected ErrUserNotFound, got %v", err)
	}
}

func TestQRDBAdapter_CredentialSaveAndGet(t *testing.T) {
	us, cs, _, _ := newTestAdapter(t)
	ctx := context.Background()
	user, err := us.Create(ctx, "carol@example.com", "Carol")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	cred := &Credential{
		ID:        []byte("cred-id-1"),
		UserID:    user.WebAuthnID(),
		PublicKey: []byte("pubkey-bytes"),
	}
	if err := cs.Save(ctx, cred); err != nil {
		t.Fatalf("cred Save: %v", err)
	}
	// GetByCredentialID
	got, err := cs.GetByCredentialID(ctx, []byte("cred-id-1"))
	if err != nil {
		t.Fatalf("GetByCredentialID: %v", err)
	}
	if string(got.ID) != "cred-id-1" {
		t.Fatalf("got ID %q", got.ID)
	}

	// GetByUserID returns the credential
	creds, err := cs.GetByUserID(ctx, user.WebAuthnID())
	if err != nil {
		t.Fatalf("GetByUserID: %v", err)
	}
	if len(creds) != 1 {
		t.Fatalf("expected 1 cred, got %d", len(creds))
	}
}

func TestQRDBAdapter_CredentialSaveDuplicate(t *testing.T) {
	us, cs, _, _ := newTestAdapter(t)
	ctx := context.Background()
	user, _ := us.Create(ctx, "dan@example.com", "Dan")
	cred := &Credential{
		ID:     []byte("c"),
		UserID: user.WebAuthnID(),
	}
	if err := cs.Save(ctx, cred); err != nil {
		t.Fatalf("first Save: %v", err)
	}
	// Saving the same id again should be a no-op (not an error).
	if err := cs.Save(ctx, cred); err != nil {
		t.Fatalf("dup Save: %v", err)
	}
	creds, _ := cs.GetByUserID(ctx, user.WebAuthnID())
	if len(creds) != 1 {
		t.Fatalf("expected 1 cred after dup save, got %d", len(creds))
	}
}

func TestQRDBAdapter_CredentialUpdate(t *testing.T) {
	us, cs, _, _ := newTestAdapter(t)
	ctx := context.Background()
	user, _ := us.Create(ctx, "ed@example.com", "Ed")
	cred := &Credential{ID: []byte("c"), UserID: user.WebAuthnID(), PublicKey: []byte("v1")}
	if err := cs.Save(ctx, cred); err != nil {
		t.Fatalf("save: %v", err)
	}
	cred.PublicKey = []byte("v2")
	if err := cs.Update(ctx, cred); err != nil {
		t.Fatalf("update: %v", err)
	}
	got, _ := cs.GetByCredentialID(ctx, []byte("c"))
	if string(got.PublicKey) != "v2" {
		t.Fatalf("expected v2, got %q", got.PublicKey)
	}
}

func TestQRDBAdapter_CredentialUpdate_NotFound(t *testing.T) {
	_, cs, _, _ := newTestAdapter(t)
	cred := &Credential{ID: []byte("missing"), UserID: []byte("1")}
	err := cs.Update(context.Background(), cred)
	if !errors.Is(err, ErrCredentialNotFound) {
		t.Fatalf("expected ErrCredentialNotFound, got %v", err)
	}
}

func TestQRDBAdapter_CredentialDelete(t *testing.T) {
	us, cs, _, _ := newTestAdapter(t)
	ctx := context.Background()
	user, _ := us.Create(ctx, "fay@example.com", "Fay")
	cred := &Credential{ID: []byte("c"), UserID: user.WebAuthnID()}
	if err := cs.Save(ctx, cred); err != nil {
		t.Fatalf("save: %v", err)
	}
	if err := cs.Delete(ctx, []byte("c")); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := cs.GetByCredentialID(ctx, []byte("c")); !errors.Is(err, ErrCredentialNotFound) {
		t.Fatalf("expected ErrCredentialNotFound after delete, got %v", err)
	}
	// User cred set should be empty
	creds, _ := cs.GetByUserID(ctx, user.WebAuthnID())
	if len(creds) != 0 {
		t.Fatalf("expected 0 creds after delete, got %d", len(creds))
	}
}

func TestQRDBAdapter_CredentialDelete_NotFound(t *testing.T) {
	_, cs, _, _ := newTestAdapter(t)
	err := cs.Delete(context.Background(), []byte("nope"))
	if !errors.Is(err, ErrCredentialNotFound) {
		t.Fatalf("expected ErrCredentialNotFound, got %v", err)
	}
}

func TestQRDBAdapter_DeleteByUserID(t *testing.T) {
	us, cs, _, _ := newTestAdapter(t)
	ctx := context.Background()
	user, _ := us.Create(ctx, "g@example.com", "G")
	for i := 0; i < 3; i++ {
		cred := &Credential{ID: []byte("c-" + strconv.Itoa(i)), UserID: user.WebAuthnID()}
		if err := cs.Save(ctx, cred); err != nil {
			t.Fatalf("save %d: %v", i, err)
		}
	}
	if err := cs.DeleteByUserID(ctx, user.WebAuthnID()); err != nil {
		t.Fatalf("DeleteByUserID: %v", err)
	}
	creds, _ := cs.GetByUserID(ctx, user.WebAuthnID())
	if len(creds) != 0 {
		t.Fatalf("expected 0 creds, got %d", len(creds))
	}
}

func TestQRDBAdapter_UserDeleteCascadesCredentials(t *testing.T) {
	us, cs, _, _ := newTestAdapter(t)
	ctx := context.Background()
	user, _ := us.Create(ctx, "h@example.com", "H")
	cred := &Credential{ID: []byte("c"), UserID: user.WebAuthnID()}
	if err := cs.Save(ctx, cred); err != nil {
		t.Fatalf("save: %v", err)
	}
	if err := us.Delete(ctx, user.WebAuthnID()); err != nil {
		t.Fatalf("user Delete: %v", err)
	}
	// User gone
	if _, err := us.GetByID(ctx, user.WebAuthnID()); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("expected ErrUserNotFound, got %v", err)
	}
	// Credential gone
	if _, err := cs.GetByCredentialID(ctx, []byte("c")); !errors.Is(err, ErrCredentialNotFound) {
		t.Fatalf("expected ErrCredentialNotFound, got %v", err)
	}
}

func TestQRDBAdapter_SaveCredential_NilArg(t *testing.T) {
	_, cs, _, _ := newTestAdapter(t)
	if err := cs.Save(context.Background(), nil); err == nil {
		t.Fatalf("expected error for nil credential")
	}
}

func TestQRDBAdapter_SaveCredential_EmptyID(t *testing.T) {
	_, cs, _, _ := newTestAdapter(t)
	err := cs.Save(context.Background(), &Credential{UserID: []byte("1")})
	if !errors.Is(err, ErrInvalidCredential) {
		t.Fatalf("expected ErrInvalidCredential, got %v", err)
	}
}

func TestQRDBAdapter_SaveUser_NilArg(t *testing.T) {
	us, _, _, _ := newTestAdapter(t)
	if err := us.Save(context.Background(), nil); err == nil {
		t.Fatalf("expected error for nil user")
	}
}

func TestQRDBAdapter_FormatUserIDForTest(t *testing.T) {
	got := formatUserIDForTest(42)
	if string(got) != "42" {
		t.Fatalf("got %q", got)
	}
}
