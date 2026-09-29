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
	"bytes"
	"context"
	"errors"
	"strconv"
	"strings"
	"sync"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
)

// errFakeUserNotFound is what the fake user client answers for a missing
// user: the typed not-found the real transports return (go-qrdb#286), not
// a bare message, because the store classifies by type since #183.
var errFakeUserNotFound error = &qrdbtransport.UserNotFoundError{ID: 0}

// ----- in-memory qrdbtransport.UserClient stub -----

type fakeUserClient struct {
	mu      sync.Mutex
	byID    map[uint64]*qrdbtransport.User
	byUname map[string]*qrdbtransport.User // tenantID|username -> user
	byEmail map[string]*qrdbtransport.User // tenantID|normalized-email -> user
	nextID  uint64
}

func newFakeUserClient() *fakeUserClient {
	return &fakeUserClient{
		byID:    make(map[uint64]*qrdbtransport.User),
		byUname: make(map[string]*qrdbtransport.User),
		byEmail: make(map[string]*qrdbtransport.User),
		nextID:  1,
	}
}

func (f *fakeUserClient) keyFor(tenantID, username string) string {
	return tenantID + "|" + username
}

// emailKeyFor mirrors the store: tenant-scoped and normalized. It is a SEPARATE
// index from byUname on purpose — resolving an email through the username map
// would make this double answer lookups the real store cannot, which is exactly
// the drift #185 exists to remove.
func (f *fakeUserClient) emailKeyFor(tenantID, email string) string {
	return tenantID + "|" + qrdbsdk.NormalizeEmail(email)
}

func (f *fakeUserClient) CreateUser(ctx context.Context, req *qrdbtransport.CreateUserRequest) (*qrdbtransport.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	k := f.keyFor(req.TenantID, req.Username)
	if _, ok := f.byUname[k]; ok {
		return nil, errors.New("already exists")
	}
	email := qrdbsdk.NormalizeEmail(req.Email)
	ek := f.emailKeyFor(req.TenantID, email)
	if email != "" {
		if _, ok := f.byEmail[ek]; ok {
			return nil, errors.New("already exists")
		}
	}
	lifecycle := qrdbsdk.LifecycleActive
	if req.Pending || req.Lifecycle == string(qrdbsdk.LifecyclePending) {
		lifecycle = qrdbsdk.LifecyclePending
	}
	u := &qrdbtransport.User{
		ID:        f.nextID,
		Username:  req.Username,
		Email:     email,
		Name:      req.Name,
		TenantID:  req.TenantID,
		Lifecycle: string(lifecycle),
	}
	f.nextID++
	f.byID[u.ID] = u
	f.byUname[k] = u
	if email != "" {
		f.byEmail[ek] = u
	}
	return u, nil
}

func (f *fakeUserClient) GetUser(ctx context.Context, id uint64) (*qrdbtransport.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, ok := f.byID[id]
	if !ok {
		return nil, errFakeUserNotFound
	}
	return u, nil
}

func (f *fakeUserClient) GetUserByUsername(ctx context.Context, tenantID, username string) (*qrdbtransport.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, ok := f.byUname[f.keyFor(tenantID, username)]
	if !ok {
		return nil, errFakeUserNotFound
	}
	return u, nil
}

func (f *fakeUserClient) GetUserByEmail(ctx context.Context, tenantID, email string) (*qrdbtransport.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if qrdbsdk.NormalizeEmail(email) == "" {
		return nil, errFakeUserNotFound
	}
	u, ok := f.byEmail[f.emailKeyFor(tenantID, email)]
	if !ok {
		return nil, errFakeUserNotFound
	}
	return u, nil
}

func (f *fakeUserClient) GetUserByCertThumbprint(ctx context.Context, thumbprint string) (*qrdbtransport.User, error) {
	return nil, errFakeUserNotFound
}

// UpdateUser models the real store: a non-empty field replaces, and a changed
// email moves its index rather than merely rewriting the record. It was an
// unimplemented stub until Save stopped writing a side key and started updating
// the record (#185) — a stub here would have made Save's new path untestable.
func (f *fakeUserClient) UpdateUser(ctx context.Context, req *qrdbtransport.UpdateUserRequest) (*qrdbtransport.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, ok := f.byID[req.ID]
	if !ok {
		return nil, errFakeUserNotFound
	}
	if req.Name != "" {
		u.Name = req.Name
	}
	if req.Lifecycle != "" {
		u.Lifecycle = req.Lifecycle
	}
	if newEmail := qrdbsdk.NormalizeEmail(req.Email); newEmail != "" && newEmail != u.Email {
		nk := f.emailKeyFor(u.TenantID, newEmail)
		if _, taken := f.byEmail[nk]; taken {
			return nil, errors.New("already exists")
		}
		if u.Email != "" {
			delete(f.byEmail, f.emailKeyFor(u.TenantID, u.Email))
		}
		u.Email = newEmail
		f.byEmail[nk] = u
	}
	return u, nil
}

func (f *fakeUserClient) DeleteUser(ctx context.Context, id uint64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, ok := f.byID[id]
	if !ok {
		return errFakeUserNotFound
	}
	delete(f.byID, id)
	delete(f.byUname, f.keyFor(u.TenantID, u.Username))
	return nil
}

func (f *fakeUserClient) ListUsers(ctx context.Context, req *qrdbtransport.ListUsersRequest) (*qrdbtransport.ListUsersResponse, error) {
	return nil, errors.New("not implemented in stub")
}

func (f *fakeUserClient) EnableUser(ctx context.Context, id uint64) error {
	return nil
}

func (f *fakeUserClient) DisableUser(ctx context.Context, id uint64) error {
	return nil
}

func (f *fakeUserClient) RemoveCertBinding(ctx context.Context, userID uint64, thumbprint string) (*qrdbtransport.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, ok := f.byID[userID]
	if !ok {
		return nil, errFakeUserNotFound
	}
	return u, nil
}

func (f *fakeUserClient) AddCertBinding(ctx context.Context, userID uint64, thumbprint string, notAfterUnix int64) (*qrdbtransport.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, ok := f.byID[userID]
	if !ok {
		return nil, errFakeUserNotFound
	}
	return u, nil
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
		// The real KV transports report a missing key as
		// *transport.KeyNotFoundError, and the adapter classifies on that type
		// rather than on message text. A stub returning a plain error would
		// exercise a path the production transports never produce.
		return nil, &qrdbtransport.KeyNotFoundError{Key: key}
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

// PutIfAbsent, CompareAndDelete and CompareAndSwap make the stub a
// qrdbtransport.GuardedKVClient, which the adapter requires.
func (f *fakeKV) PutIfAbsent(ctx context.Context, key string, value []byte) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.m[key]; ok {
		return false, nil
	}
	f.m[key] = bytes.Clone(value)
	return true, nil
}

func (f *fakeKV) CompareAndDelete(ctx context.Context, key string, expected []byte) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.m[key]
	if !ok || !bytes.Equal(v, expected) {
		return false, nil
	}
	delete(f.m, key)
	return true, nil
}

func (f *fakeKV) CompareAndSwap(ctx context.Context, key string, expected, next []byte) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.m[key]
	if !ok || !bytes.Equal(v, expected) {
		return false, nil
	}
	f.m[key] = bytes.Clone(next)
	return true, nil
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
	// Saving the same id again is refused: Save creates, Update edits
	// (go-xkms#1295).
	if err := cs.Save(ctx, cred); !errors.Is(err, ErrCredentialAlreadyExists) {
		t.Fatalf("dup Save = %v, want ErrCredentialAlreadyExists", err)
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
	// The webauthn handle is the fixed 8-byte big-endian form of the qrdb
	// uint64 user id, matching qrdb's on-disk key encoding.
	got := formatUserIDForTest(42)
	if len(got) != 8 {
		t.Fatalf("expected 8-byte handle, got %d bytes", len(got))
	}
	id, err := UserIDFromHandle(got)
	if err != nil {
		t.Fatalf("UserIDFromHandle: %v", err)
	}
	if id != 42 {
		t.Fatalf("got id %d want 42", id)
	}
}

// TestUserHandleRoundTrip proves a qrdb uint64 user id survives the
// WebAuthn handle encode/decode cycle for representative values, and
// that a malformed (non-8-byte) handle is rejected with a typed error.
func TestUserHandleRoundTrip(t *testing.T) {
	for _, n := range []uint64{0, 1, 42, 1 << 20, 1<<63 + 7, ^uint64(0)} {
		h := HandleFromUserID(n)
		if len(h) != 8 {
			t.Fatalf("id %d: expected 8-byte handle, got %d", n, len(h))
		}
		got, err := UserIDFromHandle(h)
		if err != nil {
			t.Fatalf("id %d: decode: %v", n, err)
		}
		if got != n {
			t.Fatalf("id %d: round-trip got %d", n, got)
		}
	}

	for _, bad := range [][]byte{nil, {}, []byte("1"), make([]byte, 7), make([]byte, 9)} {
		_, err := UserIDFromHandle(bad)
		var ihe *InvalidUserHandleError
		if !errors.As(err, &ihe) {
			t.Fatalf("handle %v: expected *InvalidUserHandleError, got %T (%v)", bad, err, err)
		}
		if ihe.Length != len(bad) {
			t.Fatalf("handle %v: reported length %d", bad, ihe.Length)
		}
	}
}
