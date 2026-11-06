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
	"fmt"
	"strconv"
	"strings"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
)

// errKVFault is a non-not-found storage fault. It must NOT be mapped to the
// not-found sentinels, so error wrapping (500-class) is exercised.
var errKVFault = errors.New("kv: transport failure")

// ----- failing KV store -----

// faultyStore wraps go-qrdb's in-process store and forces faults on selected
// verbs, so the credential store's error paths run through a real DAO.
type faultyStore struct {
	atomicKVStore

	putErr    error // Put, PutIfAbsent, CompareAndSwap
	getErr    error // Get
	listErr   error // QueryIndex, Scan: the lookups behind GetByUserID
	deleteErr error // Delete, CompareAndDelete
}

func (f *faultyStore) Put(ctx context.Context, key string, value []byte) error {
	if f.putErr != nil {
		return f.putErr
	}
	return f.atomicKVStore.Put(ctx, key, value)
}

func (f *faultyStore) PutIfAbsent(ctx context.Context, key string, value []byte) (bool, error) {
	if f.putErr != nil {
		return false, f.putErr
	}
	return f.atomicKVStore.PutIfAbsent(ctx, key, value)
}

func (f *faultyStore) CompareAndSwap(ctx context.Context, key string, expected, next []byte) (bool, error) {
	if f.putErr != nil {
		return false, f.putErr
	}
	return f.atomicKVStore.CompareAndSwap(ctx, key, expected, next)
}

func (f *faultyStore) Get(ctx context.Context, key string) ([]byte, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	return f.atomicKVStore.Get(ctx, key)
}

func (f *faultyStore) QueryIndex(ctx context.Context, indexName string, value []byte) ([][]byte, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	return f.atomicKVStore.QueryIndex(ctx, indexName, value)
}

func (f *faultyStore) Scan(ctx context.Context, prefix string, fn func(key string, value []byte) error) error {
	if f.listErr != nil {
		return f.listErr
	}
	return f.atomicKVStore.Scan(ctx, prefix, fn)
}

func (f *faultyStore) Delete(ctx context.Context, key string) error {
	if f.deleteErr != nil {
		return f.deleteErr
	}
	return f.atomicKVStore.Delete(ctx, key)
}

func (f *faultyStore) CompareAndDelete(ctx context.Context, key string, expected []byte) (bool, error) {
	if f.deleteErr != nil {
		return false, f.deleteErr
	}
	return f.atomicKVStore.CompareAndDelete(ctx, key, expected)
}

// newFaultyStore returns a fault-free wrapper over a fresh in-process store
// and a DAO factory over it; a test seeds data, then arms a fault.
func newFaultyStore() (*faultyStore, *qrdbsdk.DAOFactory) {
	store := &faultyStore{atomicKVStore: qrdbsdk.NewMemoryKVStore()}
	return store, qrdbsdk.NewDAOFactory(func(uint64) qrdbsdk.KVStore { return store })
}

// ----- failing user-client wrapper -----

type faultyUserClient struct {
	inner *fakeUserClient

	createErr error
	updateErr error
	deleteErr error
}

func (f *faultyUserClient) CreateUser(ctx context.Context, req *qrdbtransport.CreateUserRequest) (*qrdbtransport.User, error) {
	if f.createErr != nil {
		return nil, f.createErr
	}
	return f.inner.CreateUser(ctx, req)
}

func (f *faultyUserClient) GetUser(ctx context.Context, id uint64) (*qrdbtransport.User, error) {
	return f.inner.GetUser(ctx, id)
}

func (f *faultyUserClient) GetUserByUsername(ctx context.Context, tenantID, username string) (*qrdbtransport.User, error) {
	return f.inner.GetUserByUsername(ctx, tenantID, username)
}

func (f *faultyUserClient) GetUserByEmail(ctx context.Context, tenantID, email string) (*qrdbtransport.User, error) {
	return f.inner.GetUserByEmail(ctx, tenantID, email)
}

func (f *faultyUserClient) GetUserByCertThumbprint(ctx context.Context, thumbprint string) (*qrdbtransport.User, error) {
	return f.inner.GetUserByCertThumbprint(ctx, thumbprint)
}

func (f *faultyUserClient) UpdateUser(ctx context.Context, req *qrdbtransport.UpdateUserRequest) (*qrdbtransport.User, error) {
	if f.updateErr != nil {
		return nil, f.updateErr
	}
	return f.inner.UpdateUser(ctx, req)
}

func (f *faultyUserClient) DeleteUser(ctx context.Context, id uint64) error {
	if f.deleteErr != nil {
		return f.deleteErr
	}
	return f.inner.DeleteUser(ctx, id)
}

func (f *faultyUserClient) ListUsers(ctx context.Context, req *qrdbtransport.ListUsersRequest) (*qrdbtransport.ListUsersResponse, error) {
	return f.inner.ListUsers(ctx, req)
}

func (f *faultyUserClient) EnableUser(ctx context.Context, id uint64) error {
	return f.inner.EnableUser(ctx, id)
}

func (f *faultyUserClient) DisableUser(ctx context.Context, id uint64) error {
	return f.inner.DisableUser(ctx, id)
}

func (f *faultyUserClient) SuspendUser(ctx context.Context, id uint64) error {
	return f.inner.SuspendUser(ctx, id)
}

func (f *faultyUserClient) UnsuspendUser(ctx context.Context, id uint64) error {
	return f.inner.UnsuspendUser(ctx, id)
}

func (f *faultyUserClient) RemoveCertBinding(ctx context.Context, userID uint64, thumbprint string) (*qrdbtransport.User, error) {
	return f.inner.RemoveCertBinding(ctx, userID, thumbprint)
}

func (f *faultyUserClient) AddCertBinding(ctx context.Context, userID uint64, thumbprint string, notAfterUnix int64) (*qrdbtransport.User, error) {
	return f.inner.AddCertBinding(ctx, userID, thumbprint, notAfterUnix)
}

// newFaultyAdapter builds an adapter pair over uc and factory so tests can
// drive the qrdb store error paths.
func newFaultyAdapter(t *testing.T, uc qrdbtransport.UserClient, factory *qrdbsdk.DAOFactory) (UserStore, CredentialStore) {
	t.Helper()
	us, cs, err := NewQRDBUserStoreAdapter(QRDBUserStoreOptions{
		Users: uc, DAOFactory: factory, TenantID: "system",
	})
	if err != nil {
		t.Fatalf("adapter: %v", err)
	}
	return us, cs
}

// ----- Create error paths -----

func TestQRDBAdapter_Create_EmptyEmail(t *testing.T) {
	us, _, _ := newTestAdapter(t)
	_, err := us.Create(context.Background(), "", "Name")
	var qae *QRDBAdapterConfigError
	if !errors.As(err, &qae) {
		t.Fatalf("expected *QRDBAdapterConfigError, got %v", err)
	}
}

func TestQRDBAdapter_Create_UserClientError(t *testing.T) {
	uc := &faultyUserClient{inner: newFakeUserClient(), createErr: errKVFault}
	us, _ := newFaultyAdapter(t, uc, newTestDAOFactory())
	_, err := us.Create(context.Background(), "a@example.com", "A")
	if !errors.Is(err, errKVFault) {
		t.Fatalf("expected wrapped create error, got %v", err)
	}
}

// errDeleteDenied is the refusal the embedded node's service principal gets
// for users:delete, a permission it is deliberately not granted
// (serviceprincipal TestOption_PrincipalCannotDeleteUsers).
var errDeleteDenied = errors.New("permission denied: users:delete")

// newDeleteDeniedAdapter is a store whose user client refuses DeleteUser, as
// the real service principal does, and fails every rename until updateErr
// is cleared.
func newDeleteDeniedAdapter(t *testing.T) (*faultyUserClient, UserStore, CredentialStore) {
	t.Helper()
	uc := &faultyUserClient{inner: newFakeUserClient(), updateErr: errKVFault, deleteErr: errDeleteDenied}
	us, cs := newFaultyAdapter(t, uc, newTestDAOFactory())
	return uc, us, cs
}

// TestQRDBAdapter_Create_UsernameAssignError_LeavesEmailRegistrable checks a
// failed rename to the user ID is a *QRDBUsernameAssignError that deletes
// nothing, and that the record it leaves under the placeholder does not lock
// the email out: the next registration finishes the rename and gets that user.
func TestQRDBAdapter_Create_UsernameAssignError_LeavesEmailRegistrable(t *testing.T) {
	uc, us, cs := newDeleteDeniedAdapter(t)
	cfg := validTestConfig()
	cfg.AllowPublicRegistration = openRegistration()
	svc, err := NewService(ServiceParams{
		Config:          cfg,
		UserStore:       us,
		SessionStore:    NewMemorySessionStore(),
		CredentialStore: cs,
	})
	if err != nil {
		t.Fatalf("service: %v", err)
	}
	ctx := context.Background()

	_, _, err = svc.BeginRegistration(ctx, "a@example.com", "A")
	var assignErr *QRDBUsernameAssignError
	if !errors.As(err, &assignErr) {
		t.Fatalf("expected *QRDBUsernameAssignError, got %T: %v", err, err)
	}
	if !errors.Is(err, errKVFault) || errors.Is(err, errDeleteDenied) {
		t.Fatalf("the error must carry the rename fault and no delete: %v", err)
	}

	uc.updateErr = nil
	if _, _, err := svc.BeginRegistration(ctx, "a@example.com", "A"); err != nil {
		t.Fatalf("registration after a failed rename: %v", err)
	}
	if n := len(uc.inner.byID); n != 1 {
		t.Fatalf("records = %d, want the one recovered record", n)
	}
	rec, err := uc.inner.GetUserByEmail(ctx, "system", "a@example.com")
	if err != nil {
		t.Fatalf("GetUserByEmail: %v", err)
	}
	if rec.ID != assignErr.UserID || rec.Username != strconv.FormatUint(rec.ID, 10) {
		t.Fatalf("record %d has Username %q, want the first record named by its ID", rec.ID, rec.Username)
	}
}

// TestQRDBAdapter_Create_PendingUserWithCredentialIsNotTakenOver checks a
// placeholder record that already holds a credential is never renamed and
// handed to a new registration of its email.
func TestQRDBAdapter_Create_PendingUserWithCredentialIsNotTakenOver(t *testing.T) {
	uc, us, cs := newDeleteDeniedAdapter(t)
	ctx := context.Background()

	_, err := us.Create(ctx, "a@example.com", "A")
	var assignErr *QRDBUsernameAssignError
	if !errors.As(err, &assignErr) {
		t.Fatalf("expected *QRDBUsernameAssignError, got %T: %v", err, err)
	}
	cred := &Credential{ID: []byte("cred-1"), UserID: HandleFromUserID(assignErr.UserID), PublicKey: []byte("pk")}
	if err := cs.Save(ctx, cred); err != nil {
		t.Fatalf("cred Save: %v", err)
	}

	uc.updateErr = nil
	_, err = us.Create(ctx, "a@example.com", "A")
	var claimedErr *QRDBPendingUserClaimedError
	if !errors.As(err, &claimedErr) || claimedErr.UserID != assignErr.UserID {
		t.Fatalf("expected *QRDBPendingUserClaimedError for user %d, got %T: %v", assignErr.UserID, err, err)
	}
	rec, err := uc.inner.GetUser(ctx, assignErr.UserID)
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	if !strings.HasPrefix(rec.Username, pendingUsernamePrefix) {
		t.Fatalf("the credentialed placeholder was renamed to %q", rec.Username)
	}
}

// The display name is a field of the qrdb record (#185), not a write to a
// side key: Create succeeds with every datastore write failing, and the name
// round-trips on the record.
func TestQRDBAdapter_Create_StoresNameOnTheRecord(t *testing.T) {
	inner := newFakeUserClient()
	store, factory := newFaultyStore()
	store.putErr = errKVFault
	us, _ := newFaultyAdapter(t, inner, factory)

	u, err := us.Create(context.Background(), "b@example.com", "B")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if got := u.DisplayName(); got != "B" {
		t.Fatalf("display name not carried: got %q, want %q", got, "B")
	}
	if got := u.WebAuthnName(); got != "b@example.com" {
		t.Fatalf("webauthn name is not the email login key: got %q", got)
	}

	rec, err := inner.GetUserByEmail(context.Background(), "system", "b@example.com")
	if err != nil {
		t.Fatalf("record not resolvable by email: %v", err)
	}
	if rec.Name != "B" || rec.Email != "b@example.com" {
		t.Fatalf("record fields wrong: name=%q email=%q", rec.Name, rec.Email)
	}
}

// ----- user Save -----

func TestQRDBAdapter_UserSave_EmptyDisplayName_NoOp(t *testing.T) {
	us, _, _ := newTestAdapter(t)
	user := NewDefaultUser(HandleFromUserID(1), "u@example.com", "")
	if err := us.Save(context.Background(), user); err != nil {
		t.Fatalf("expected no-op save, got %v", err)
	}
}

// Save writes the display name through UpdateUser, so a datastore write
// fault must not fail it.
func TestQRDBAdapter_UserSave_StoreFaultDoesNotAffectIt(t *testing.T) {
	ctx := context.Background()
	inner := newFakeUserClient()
	seeded, err := inner.CreateUser(ctx, &qrdbtransport.CreateUserRequest{
		Username: "u@example.com", Email: "u@example.com", TenantID: "system",
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	store, factory := newFaultyStore()
	store.putErr = errKVFault
	us, _ := newFaultyAdapter(t, inner, factory)

	user := NewDefaultUser(HandleFromUserID(seeded.ID), "u@example.com", "Display")
	if err := us.Save(ctx, user); err != nil {
		t.Fatalf("Save must not write to the datastore: %v", err)
	}
	rec, err := inner.GetUser(ctx, seeded.ID)
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	if rec.Name != "Display" {
		t.Fatalf("Save did not update the record name: %q", rec.Name)
	}
}

// ----- user Delete -----

func TestQRDBAdapter_UserDelete_ClientError(t *testing.T) {
	uc := &faultyUserClient{inner: newFakeUserClient(), deleteErr: errKVFault}
	us, _ := newFaultyAdapter(t, uc, newTestDAOFactory())
	if err := us.Delete(context.Background(), HandleFromUserID(1)); !errors.Is(err, errKVFault) {
		t.Fatalf("expected delete error, got %v", err)
	}
}

// TestQRDBAdapter_UserDelete_CredentialLookupErrorPropagates proves Delete
// reports a failure to find the user's credentials after the record is gone,
// rather than silently leaving them orphaned.
func TestQRDBAdapter_UserDelete_CredentialLookupErrorPropagates(t *testing.T) {
	ctx := context.Background()
	store, factory := newFaultyStore()
	us, cs := newFaultyAdapter(t, newFakeUserClient(), factory)
	user, err := us.Create(ctx, "userdel@example.com", "User Del")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := cs.Save(ctx, &Credential{ID: []byte("a"), UserID: user.WebAuthnID()}); err != nil {
		t.Fatalf("save: %v", err)
	}

	store.listErr = errKVFault
	if err := us.Delete(ctx, user.WebAuthnID()); !errors.Is(err, errKVFault) {
		t.Fatalf("expected credential lookup error, got %v", err)
	}
}

// TestQRDBAdapter_UserDelete_CredentialDeleteErrorPropagates proves a failure
// deleting one of the user's credentials reaches the caller.
func TestQRDBAdapter_UserDelete_CredentialDeleteErrorPropagates(t *testing.T) {
	ctx := context.Background()
	store, factory := newFaultyStore()
	us, cs := newFaultyAdapter(t, newFakeUserClient(), factory)
	user, err := us.Create(ctx, "userdel2@example.com", "User Del2")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := cs.Save(ctx, &Credential{ID: []byte("a"), UserID: user.WebAuthnID()}); err != nil {
		t.Fatalf("save: %v", err)
	}

	store.deleteErr = errKVFault
	if err := us.Delete(ctx, user.WebAuthnID()); !errors.Is(err, errKVFault) {
		t.Fatalf("expected credential delete error, got %v", err)
	}
}

// ----- materialize -----

// A credential read failure while materializing a user is returned through
// both lookups, never answered with a user missing credentials.
func TestQRDBAdapter_Materialize_CredentialLookupError(t *testing.T) {
	ctx := context.Background()
	store, factory := newFaultyStore()
	us, _ := newFaultyAdapter(t, newFakeUserClient(), factory)
	user, err := us.Create(ctx, "m@example.com", "M")
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	store.listErr = errKVFault
	if _, err := us.GetByID(ctx, user.WebAuthnID()); !errors.Is(err, errKVFault) {
		t.Fatalf("GetByID: expected credential lookup error, got %v", err)
	}
	if _, err := us.GetByEmail(ctx, "m@example.com"); !errors.Is(err, errKVFault) {
		t.Fatalf("GetByEmail: expected credential lookup error, got %v", err)
	}
}

func TestQRDBAdapter_Materialize_FullHydration(t *testing.T) {
	ctx := context.Background()
	us, cs, _ := newTestAdapter(t)

	user, err := us.Create(ctx, "mat@example.com", "Materialize")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	cred := &Credential{ID: []byte("mc"), UserID: user.WebAuthnID(), PublicKey: []byte("pk")}
	if err := cs.Save(ctx, cred); err != nil {
		t.Fatalf("save cred: %v", err)
	}

	got, err := us.GetByID(ctx, user.WebAuthnID())
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.WebAuthnDisplayName() != "Materialize" {
		t.Fatalf("display name not hydrated: %q", got.WebAuthnDisplayName())
	}
	if len(got.WebAuthnCredentials()) != 1 {
		t.Fatalf("expected 1 hydrated credential, got %d", len(got.WebAuthnCredentials()))
	}
}

// ----- credential store write and read faults -----

func TestQRDBAdapter_CredSave_StoreError(t *testing.T) {
	store, factory := newFaultyStore()
	store.putErr = errKVFault
	_, cs := newFaultyAdapter(t, newFakeUserClient(), factory)
	cred := &Credential{ID: []byte("c"), UserID: HandleFromUserID(1)}
	err := cs.Save(context.Background(), cred)
	if !errors.Is(err, errKVFault) {
		t.Fatalf("expected store error, got %v", err)
	}
	if errors.Is(err, ErrCredentialAlreadyExists) {
		t.Fatal("a store fault must not read as a duplicate")
	}
}

// A read fault is a failure to answer, never "not found".
func TestQRDBAdapter_GetByCredentialID_StoreError(t *testing.T) {
	store, factory := newFaultyStore()
	_, cs := newFaultyAdapter(t, newFakeUserClient(), factory)
	if err := cs.Save(context.Background(), &Credential{ID: []byte("c"), UserID: HandleFromUserID(1)}); err != nil {
		t.Fatalf("save: %v", err)
	}

	store.getErr = errKVFault
	_, err := cs.GetByCredentialID(context.Background(), []byte("c"))
	if !errors.Is(err, errKVFault) {
		t.Fatalf("expected get error, got %v", err)
	}
	if errors.Is(err, ErrCredentialNotFound) {
		t.Fatal("a store fault must not be classified as not-found")
	}
}

func TestQRDBAdapter_GetByUserID_StoreError(t *testing.T) {
	store, factory := newFaultyStore()
	store.listErr = errKVFault
	_, cs := newFaultyAdapter(t, newFakeUserClient(), factory)
	if _, err := cs.GetByUserID(context.Background(), HandleFromUserID(1)); !errors.Is(err, errKVFault) {
		t.Fatalf("expected lookup error, got %v", err)
	}
	if err := cs.DeleteByUserID(context.Background(), HandleFromUserID(1)); !errors.Is(err, errKVFault) {
		t.Fatalf("DeleteByUserID: expected lookup error, got %v", err)
	}
}

func TestQRDBAdapter_Update_StoreError(t *testing.T) {
	ctx := context.Background()
	store, factory := newFaultyStore()
	_, cs := newFaultyAdapter(t, newFakeUserClient(), factory)
	cred := &Credential{ID: []byte("u1"), UserID: HandleFromUserID(1), PublicKey: []byte("v1")}
	if err := cs.Save(ctx, cred); err != nil {
		t.Fatalf("seed: %v", err)
	}

	store.putErr = errKVFault
	cred.PublicKey = []byte("v2")
	err := cs.Update(ctx, cred)
	if !errors.Is(err, errKVFault) {
		t.Fatalf("expected store error on update, got %v", err)
	}
	if errors.Is(err, ErrCredentialUpdateConflict) {
		t.Fatal("a store fault must not read as a lost race")
	}
}

func TestQRDBAdapter_CredDelete_StoreError(t *testing.T) {
	ctx := context.Background()
	store, factory := newFaultyStore()
	_, cs := newFaultyAdapter(t, newFakeUserClient(), factory)
	if err := cs.Save(ctx, &Credential{ID: []byte("a"), UserID: HandleFromUserID(1)}); err != nil {
		t.Fatalf("save: %v", err)
	}

	store.deleteErr = errKVFault
	if err := cs.Delete(ctx, []byte("a")); !errors.Is(err, errKVFault) {
		t.Fatalf("Delete: expected store error, got %v", err)
	}
	if err := cs.DeleteByUserID(ctx, HandleFromUserID(1)); !errors.Is(err, errKVFault) {
		t.Fatalf("DeleteByUserID: expected store error, got %v", err)
	}
}

func TestQRDBAdapter_CredDelete_KeepsPeers(t *testing.T) {
	ctx := context.Background()
	us, cs, _ := newTestAdapter(t)
	user, err := us.Create(ctx, "multi@example.com", "Multi")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	for _, id := range []string{"a", "b", "c"} {
		if err := cs.Save(ctx, &Credential{ID: []byte(id), UserID: user.WebAuthnID()}); err != nil {
			t.Fatalf("save %s: %v", id, err)
		}
	}
	if err := cs.Delete(ctx, []byte("b")); err != nil {
		t.Fatalf("delete: %v", err)
	}
	creds, err := cs.GetByUserID(ctx, user.WebAuthnID())
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(creds) != 2 {
		t.Fatalf("expected 2 remaining creds, got %d", len(creds))
	}
	for _, c := range creds {
		if string(c.ID) == "b" {
			t.Fatal("deleted credential still found under its user")
		}
	}
}

// ----- not-found classification -----

// TestIsUserNotFound covers the user-record classifier. It is typed and
// fails closed (#183): the typed not-found of every transport is an
// absence, the opaque QUIC form is recognised only by the user service's
// own canonical message, and a failure that merely mentions "not found" is
// a failure.
func TestIsUserNotFound(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"REST typed", &qrdbtransport.UserNotFoundError{ID: 42}, true},
		{"gRPC/MCP/embedded typed", &qrdbtransport.KeyNotFoundError{Key: "42"}, true},
		{"typed, wrapped", fmt.Errorf("lookup: %w", &qrdbtransport.UserNotFoundError{ID: 42}), true},
		{"QUIC opaque, canonical pre-0.16.3 message",
			&qrdbtransport.RequestError{Method: "GetUser", Err: errors.New("user not found: 42")}, true},
		{"QUIC opaque, canonical typed message",
			&qrdbtransport.RequestError{Method: "GetUserByEmail", Err: errors.New("user: not found: email/a@b")}, true},

		// Failures to answer. Each of these classified as "absent" before #183.
		{"bare text", errors.New("user not found"), false},
		{"the qrdb code in prose", errors.New("ErrCodeNotFound"), false},
		{"driver no rows", errors.New("sql: no rows in result set"), false},
		{"connection not found", errors.New("connection not found"), false},
		{"tenant not found", errors.New("tenant not found: t1"), false},
		{"host not found", errors.New("host not found: dial tcp 10.0.0.1:7443"), false},
		{"QUIC opaque, a different subject", &qrdbtransport.RequestError{Method: "GetUser",
			Err: errors.New("tenant not found: t1")}, false},
		{"QUIC opaque, not-found buried in prose", &qrdbtransport.RequestError{Method: "GetUser",
			Err: errors.New("route to user not found: 42")}, false},
		{"QUIC opaque, no message", &qrdbtransport.RequestError{Method: "GetUser", StatusCode: 500}, false},
		{"transport unavailable", errors.New("transport unavailable"), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := isUserNotFound(c.err); got != c.want {
				t.Fatalf("isUserNotFound(%v) = %v want %v", c.err, got, c.want)
			}
		})
	}
}

func TestMapNotFound_NonNotFound(t *testing.T) {
	err := mapNotFound(errKVFault)
	if errors.Is(err, ErrUserNotFound) {
		t.Fatal("non-not-found must not map to ErrUserNotFound")
	}
	if !errors.Is(err, errKVFault) {
		t.Fatalf("expected wrapped errKVFault, got %v", err)
	}
}
