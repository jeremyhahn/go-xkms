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
	"testing"

	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
)

// errKVFault is a non-not-found KV fault. It must NOT be mapped to the
// not-found sentinels, so error wrapping (500-class) is exercised.
var errKVFault = errors.New("kv: transport failure")

// ----- failing KV wrapper -----

// faultyKV wraps the in-memory fakeKV and forces faults on selected ops.
// putErr/getErr/deleteErr are applied to ALL keys when set.
type faultyKV struct {
	inner *fakeKV

	putErr    error
	getErr    error
	deleteErr error

	// getFaultKeyPrefix, when set, only faults Get for keys with this prefix.
	getFaultKeyPrefix string
}

func (f *faultyKV) Put(ctx context.Context, key string, value []byte, opts ...qrdbtransport.WriteOption) error {
	if f.putErr != nil {
		return f.putErr
	}
	return f.inner.Put(ctx, key, value, opts...)
}

func (f *faultyKV) Get(ctx context.Context, key string, opts ...qrdbtransport.ReadOption) ([]byte, error) {
	if f.getErr != nil {
		if f.getFaultKeyPrefix == "" || hasPrefix(key, f.getFaultKeyPrefix) {
			return nil, f.getErr
		}
	}
	return f.inner.Get(ctx, key, opts...)
}

func (f *faultyKV) Delete(ctx context.Context, key string, opts ...qrdbtransport.WriteOption) error {
	if f.deleteErr != nil {
		return f.deleteErr
	}
	return f.inner.Delete(ctx, key, opts...)
}

func (f *faultyKV) Scan(ctx context.Context, prefix string, opts ...qrdbtransport.ReadOption) (map[string][]byte, error) {
	return f.inner.Scan(ctx, prefix, opts...)
}

func (f *faultyKV) List(ctx context.Context, prefix string, opts ...qrdbtransport.ReadOption) ([]string, error) {
	return f.inner.List(ctx, prefix, opts...)
}

func (f *faultyKV) Exists(ctx context.Context, key string, opts ...qrdbtransport.ReadOption) (bool, error) {
	return f.inner.Exists(ctx, key, opts...)
}

func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

// ----- failing user-client wrapper -----

type faultyUserClient struct {
	inner *fakeUserClient

	createErr error
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

func (f *faultyUserClient) RemoveCertBinding(ctx context.Context, userID uint64, thumbprint string) (*qrdbtransport.User, error) {
	return nil, errors.New("not implemented in fake")
}

func (f *faultyUserClient) AddCertBinding(ctx context.Context, userID uint64, thumbprint string, notAfterUnix int64) (*qrdbtransport.User, error) {
	return f.inner.AddCertBinding(ctx, userID, thumbprint, notAfterUnix)
}

// newFaultyAdapter builds an adapter pair over the faulty wrappers so tests
// can drive the qrdb store error paths.
func newFaultyAdapter(t *testing.T, uc qrdbtransport.UserClient, kv qrdbtransport.KVClient) (UserStore, CredentialStore) {
	t.Helper()
	us, cs, err := NewQRDBUserStoreAdapter(QRDBUserStoreOptions{
		Users: uc, KV: kv, TenantID: "system",
	})
	if err != nil {
		t.Fatalf("adapter: %v", err)
	}
	return us, cs
}

// ----- Create error paths -----

func TestQRDBAdapter_Create_EmptyEmail(t *testing.T) {
	us, _, _, _ := newTestAdapter(t)
	_, err := us.Create(context.Background(), "", "Name")
	var qae *QRDBAdapterConfigError
	if !errors.As(err, &qae) {
		t.Fatalf("expected *QRDBAdapterConfigError, got %v", err)
	}
}

func TestQRDBAdapter_Create_UserClientError(t *testing.T) {
	uc := &faultyUserClient{inner: newFakeUserClient(), createErr: errKVFault}
	us, _ := newFaultyAdapter(t, uc, newFakeKV())
	_, err := us.Create(context.Background(), "a@example.com", "A")
	if err == nil || errors.Is(err, errKVFault) == false {
		t.Fatalf("expected wrapped create error, got %v", err)
	}
}

// Create no longer writes the display name to a side key, so a KV put fault
// cannot fail it. The name is a field of the qrdb record (#185): this asserts
// it round-trips through Create, which is the property that replaced the
// deleted put-error path.
func TestQRDBAdapter_Create_StoresNameOnTheRecord(t *testing.T) {
	inner := newFakeUserClient()
	kv := &faultyKV{inner: newFakeKV(), putErr: errKVFault}
	us, _ := newFaultyAdapter(t, inner, kv)

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

	// And it is on the qrdb record, not beside it.
	rec, err := inner.GetUserByEmail(context.Background(), "system", "b@example.com")
	if err != nil {
		t.Fatalf("record not resolvable by email: %v", err)
	}
	if rec.Name != "B" || rec.Email != "b@example.com" {
		t.Fatalf("record fields wrong: name=%q email=%q", rec.Name, rec.Email)
	}
}

// ----- user Save error path -----

func TestQRDBAdapter_UserSave_EmptyDisplayName_NoOp(t *testing.T) {
	us, _, _, _ := newTestAdapter(t)
	user := NewDefaultUser(HandleFromUserID(1), "u@example.com", "")
	// Empty display name -> early return, never touches KV.
	if err := us.Save(context.Background(), user); err != nil {
		t.Fatalf("expected no-op save, got %v", err)
	}
}

// Save writes the display name through UpdateUser now, so its failure mode is
// an update error rather than a KV put error. A KV fault must NOT fail it —
// that is the observable proof the side-table write is gone.
func TestQRDBAdapter_UserSave_KVFaultDoesNotAffectIt(t *testing.T) {
	ctx := context.Background()
	inner := newFakeUserClient()
	seeded, err := inner.CreateUser(ctx, &qrdbtransport.CreateUserRequest{
		Username: "u@example.com", Email: "u@example.com", TenantID: "system",
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	kv := &faultyKV{inner: newFakeKV(), putErr: errKVFault}
	us, _ := newFaultyAdapter(t, inner, kv)

	user := NewDefaultUser(HandleFromUserID(seeded.ID), "u@example.com", "Display")
	if err := us.Save(ctx, user); err != nil {
		t.Fatalf("Save must not touch KV: %v", err)
	}

	rec, err := inner.GetUser(ctx, seeded.ID)
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	if rec.Name != "Display" {
		t.Fatalf("Save did not update the record name: %q", rec.Name)
	}
}

// ----- user Delete error path -----

func TestQRDBAdapter_UserDelete_ClientError(t *testing.T) {
	uc := &faultyUserClient{inner: newFakeUserClient(), deleteErr: errKVFault}
	us, _ := newFaultyAdapter(t, uc, newFakeKV())
	if err := us.Delete(context.Background(), HandleFromUserID(1)); !errors.Is(err, errKVFault) {
		t.Fatalf("expected delete error, got %v", err)
	}
}

// ----- GetByEmail / GetByID underlying error (not a not-found) -----

func TestQRDBAdapter_GetByID_MaterializeError(t *testing.T) {
	// The user exists, but loading the credential index faults (non-not-found),
	// exercising the materialize error path through GetByID.
	inner := newFakeUserClient()
	ctx := context.Background()
	u, err := inner.CreateUser(ctx, &qrdbtransport.CreateUserRequest{Username: "m@example.com", TenantID: "system"})
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	kv := &faultyKV{
		inner:             newFakeKV(),
		getErr:            errKVFault,
		getFaultKeyPrefix: userCredSetKey(u.ID),
	}
	us, _ := newFaultyAdapter(t, inner, kv)
	if _, err := us.GetByID(ctx, HandleFromUserID(u.ID)); !errors.Is(err, errKVFault) {
		t.Fatalf("expected materialize/cred-index error, got %v", err)
	}
}

// ----- credential Save error paths -----

func TestQRDBAdapter_CredSave_PutCredentialError(t *testing.T) {
	kv := &faultyKV{inner: newFakeKV(), putErr: errKVFault}
	_, cs := newFaultyAdapter(t, newFakeUserClient(), kv)
	cred := &Credential{ID: []byte("c"), UserID: HandleFromUserID(1)}
	if err := cs.Save(context.Background(), cred); !errors.Is(err, errKVFault) {
		t.Fatalf("expected put-credential error, got %v", err)
	}
}

func TestQRDBAdapter_CredSave_PutIndexError(t *testing.T) {
	// Putting the credential succeeds, putting the index fails. Fault only the
	// cred-set index key.
	kv := &faultyKV{
		inner: newFakeKV(),
	}
	// Use a custom put that only fails on the index key.
	idxKV := &indexPutFailKV{faultyKV: kv}
	_, cs := newFaultyAdapter(t, newFakeUserClient(), idxKV)
	cred := &Credential{ID: []byte("c"), UserID: HandleFromUserID(1)}
	if err := cs.Save(context.Background(), cred); !errors.Is(err, errKVFault) {
		t.Fatalf("expected put-index error, got %v", err)
	}
}

// indexPutFailKV fails Put only on the user-cred-set index key, letting the
// credential blob persist first.
type indexPutFailKV struct {
	*faultyKV
}

func (f *indexPutFailKV) Put(ctx context.Context, key string, value []byte, opts ...qrdbtransport.WriteOption) error {
	if hasPrefix(key, "__xkms:webauthn/users/") && hasSuffix(key, "/credentials") {
		return errKVFault
	}
	return f.inner.Put(ctx, key, value, opts...)
}

func hasSuffix(s, suffix string) bool {
	return len(s) >= len(suffix) && s[len(s)-len(suffix):] == suffix
}

// ----- credential GetByCredentialID error paths -----

func TestQRDBAdapter_GetByCredentialID_GetError(t *testing.T) {
	kv := &faultyKV{
		inner:             newFakeKV(),
		getErr:            errKVFault,
		getFaultKeyPrefix: "__xkms:webauthn/credentials/",
	}
	_, cs := newFaultyAdapter(t, newFakeUserClient(), kv)
	_, err := cs.GetByCredentialID(context.Background(), []byte("c"))
	if !errors.Is(err, errKVFault) {
		t.Fatalf("expected get error, got %v", err)
	}
}

func TestQRDBAdapter_GetByCredentialID_NotFound(t *testing.T) {
	// fakeKV returns "key not found" which maps to ErrCredentialNotFound.
	_, cs, _, _ := newTestAdapter(t)
	_, err := cs.GetByCredentialID(context.Background(), []byte("nope"))
	if !errors.Is(err, ErrCredentialNotFound) {
		t.Fatalf("expected ErrCredentialNotFound, got %v", err)
	}
}

func TestQRDBAdapter_GetByCredentialID_CorruptBlob(t *testing.T) {
	kv := newFakeKV()
	// Store the corrupt blob under the canonical key the lookup will
	// derive for the raw credential id []byte("c") — credKey segments are
	// base64url-encoded so binary credential ids round-trip losslessly.
	_ = kv.Put(context.Background(), credKey(credIDToString([]byte("c"))), []byte("{not-json"))
	_, cs := newFaultyAdapter(t, newFakeUserClient(), kv)
	_, err := cs.GetByCredentialID(context.Background(), []byte("c"))
	if err == nil {
		t.Fatal("expected decode error for corrupt credential blob")
	}
	if errors.Is(err, ErrCredentialNotFound) {
		t.Fatal("corrupt blob must not be classified as not-found")
	}
}

// ----- GetByUserID propagates index error -----

func TestQRDBAdapter_GetByUserID_IndexError(t *testing.T) {
	kv := &faultyKV{
		inner:             newFakeKV(),
		getErr:            errKVFault,
		getFaultKeyPrefix: userCredSetKey(1),
	}
	_, cs := newFaultyAdapter(t, newFakeUserClient(), kv)
	_, err := cs.GetByUserID(context.Background(), HandleFromUserID(1))
	if !errors.Is(err, errKVFault) {
		t.Fatalf("expected index error, got %v", err)
	}
}

// ----- DeleteByUserID propagates index error -----

func TestQRDBAdapter_DeleteByUserID_IndexError(t *testing.T) {
	kv := &faultyKV{
		inner:             newFakeKV(),
		getErr:            errKVFault,
		getFaultKeyPrefix: userCredSetKey(1),
	}
	_, cs := newFaultyAdapter(t, newFakeUserClient(), kv)
	if err := cs.DeleteByUserID(context.Background(), HandleFromUserID(1)); !errors.Is(err, errKVFault) {
		t.Fatalf("expected index error, got %v", err)
	}
}

// ----- corrupt index blob -----

func TestQRDBAdapter_ListUserCredIDs_CorruptIndex(t *testing.T) {
	kv := newFakeKV()
	_ = kv.Put(context.Background(), userCredSetKey(1), []byte("not-json-array"))
	_, cs := newFaultyAdapter(t, newFakeUserClient(), kv)
	_, err := cs.GetByUserID(context.Background(), HandleFromUserID(1))
	if err == nil {
		t.Fatal("expected decode error for corrupt cred index")
	}
}

// ----- helper predicate coverage -----

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

func TestMapNotFoundCred_NonNotFound(t *testing.T) {
	err := mapNotFoundCred(errKVFault)
	if errors.Is(err, ErrCredentialNotFound) {
		t.Fatal("non-not-found must not map to ErrCredentialNotFound")
	}
	if !errors.Is(err, errKVFault) {
		t.Fatalf("expected wrapped errKVFault, got %v", err)
	}
}

// ----- materialize hydrates display name + credentials -----

func TestQRDBAdapter_Materialize_FullHydration(t *testing.T) {
	ctx := context.Background()
	us, cs, _, _ := newTestAdapter(t)

	user, err := us.Create(ctx, "mat@example.com", "Materialize")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	cred := &Credential{ID: []byte("mc"), UserID: user.WebAuthnID(), PublicKey: []byte("pk")}
	if err := cs.Save(ctx, cred); err != nil {
		t.Fatalf("save cred: %v", err)
	}

	// GetByID materializes display name + credential set.
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

// materialize skips a credential whose blob vanished from the index (a
// not-found on the individual credential key is tolerated).
func TestQRDBAdapter_Materialize_SkipsMissingCredential(t *testing.T) {
	ctx := context.Background()
	kv := newFakeKV()
	uc := newFakeUserClient()
	u, err := uc.CreateUser(ctx, &qrdbtransport.CreateUserRequest{Username: "skip@example.com", TenantID: "system"})
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	// Index references a credential id that has no stored blob.
	idxBlob := []byte(`["ghost"]`)
	_ = kv.Put(ctx, userCredSetKey(u.ID), idxBlob)

	us, _ := newFaultyAdapter(t, uc, kv)
	got, err := us.GetByID(ctx, HandleFromUserID(u.ID))
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if len(got.WebAuthnCredentials()) != 0 {
		t.Fatalf("expected ghost credential to be skipped, got %d", len(got.WebAuthnCredentials()))
	}
}

// ----- Update succeeds, then put fails -----

func TestQRDBAdapter_Update_PutError(t *testing.T) {
	ctx := context.Background()
	kv := newFakeKV()
	// Seed an existing credential so the GetByCredentialID guard passes.
	cred := &Credential{ID: []byte("u1"), UserID: HandleFromUserID(1), PublicKey: []byte("v1")}
	_, csSeed := newFaultyAdapter(t, newFakeUserClient(), kv)
	if err := csSeed.Save(ctx, cred); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// Now swap in a KV that fails Put but still serves Get from the same map.
	failKV := &updatePutFailKV{inner: kv}
	_, cs := newFaultyAdapter(t, newFakeUserClient(), failKV)
	cred.PublicKey = []byte("v2")
	if err := cs.Update(ctx, cred); !errors.Is(err, errKVFault) {
		t.Fatalf("expected put error on update, got %v", err)
	}
}

// updatePutFailKV serves Get from a shared fakeKV but always fails Put.
type updatePutFailKV struct {
	inner *fakeKV
}

func (f *updatePutFailKV) Put(ctx context.Context, key string, value []byte, opts ...qrdbtransport.WriteOption) error {
	return errKVFault
}

func (f *updatePutFailKV) Get(ctx context.Context, key string, opts ...qrdbtransport.ReadOption) ([]byte, error) {
	return f.inner.Get(ctx, key, opts...)
}

func (f *updatePutFailKV) Delete(ctx context.Context, key string, opts ...qrdbtransport.WriteOption) error {
	return f.inner.Delete(ctx, key, opts...)
}

func (f *updatePutFailKV) Scan(ctx context.Context, prefix string, opts ...qrdbtransport.ReadOption) (map[string][]byte, error) {
	return f.inner.Scan(ctx, prefix, opts...)
}

func (f *updatePutFailKV) List(ctx context.Context, prefix string, opts ...qrdbtransport.ReadOption) ([]string, error) {
	return f.inner.List(ctx, prefix, opts...)
}

func (f *updatePutFailKV) Exists(ctx context.Context, key string, opts ...qrdbtransport.ReadOption) (bool, error) {
	return f.inner.Exists(ctx, key, opts...)
}

// ----- credential Delete rewrites the index when peers remain -----

func TestQRDBAdapter_CredDelete_RewritesIndex(t *testing.T) {
	ctx := context.Background()
	us, cs, _, _ := newTestAdapter(t)
	user, err := us.Create(ctx, "multi@example.com", "Multi")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	for _, id := range []string{"a", "b", "c"} {
		if err := cs.Save(ctx, &Credential{ID: []byte(id), UserID: user.WebAuthnID()}); err != nil {
			t.Fatalf("save %s: %v", id, err)
		}
	}
	// Delete the middle one; the index must be rewritten (not removed).
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
			t.Fatal("deleted credential still present in index")
		}
	}
}

// ----- GetByEmail underlying (non-not-found) error -----

func TestQRDBAdapter_GetByEmail_MaterializeError(t *testing.T) {
	ctx := context.Background()
	inner := newFakeUserClient()
	u, err := inner.CreateUser(ctx, &qrdbtransport.CreateUserRequest{Username: "gbe@example.com", Email: "gbe@example.com", TenantID: "system"})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	kv := &faultyKV{
		inner:             newFakeKV(),
		getErr:            errKVFault,
		getFaultKeyPrefix: userCredSetKey(u.ID),
	}
	us, _ := newFaultyAdapter(t, inner, kv)
	if _, err := us.GetByEmail(ctx, "gbe@example.com"); !errors.Is(err, errKVFault) {
		t.Fatalf("expected materialize error via GetByEmail, got %v", err)
	}
}
