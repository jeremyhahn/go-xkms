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

	"github.com/go-webauthn/webauthn/webauthn"
)

// errBoom is a generic non-sentinel storage fault used to exercise the
// 500-class error branches of the service. It is deliberately NOT a
// not-found error so IsUserNotFound / IsCredentialNotFound return false.
var errBoom = errors.New("boom: backend unavailable")

// ----- configurable failing UserStore -----

// faultyUserStore wraps a real UserStore and selectively forces errors on
// individual methods, letting tests drive the service's error branches
// without touching production code.
type faultyUserStore struct {
	inner UserStore

	getByEmailErr error
	getByIDErr    error
	createErr     error
	saveErr       error
	deleteErr     error
}

func (s *faultyUserStore) GetByID(ctx context.Context, userID []byte) (User, error) {
	if s.getByIDErr != nil {
		return nil, s.getByIDErr
	}
	return s.inner.GetByID(ctx, userID)
}

func (s *faultyUserStore) GetByEmail(ctx context.Context, email string) (User, error) {
	if s.getByEmailErr != nil {
		return nil, s.getByEmailErr
	}
	return s.inner.GetByEmail(ctx, email)
}

func (s *faultyUserStore) Create(ctx context.Context, email, displayName string) (User, error) {
	if s.createErr != nil {
		return nil, s.createErr
	}
	return s.inner.Create(ctx, email, displayName)
}

func (s *faultyUserStore) Save(ctx context.Context, user User) error {
	if s.saveErr != nil {
		return s.saveErr
	}
	return s.inner.Save(ctx, user)
}

func (s *faultyUserStore) Delete(ctx context.Context, userID []byte) error {
	if s.deleteErr != nil {
		return s.deleteErr
	}
	return s.inner.Delete(ctx, userID)
}

// ----- configurable failing CredentialStore -----

type faultyCredStore struct {
	inner CredentialStore

	getByUserIDErr  error
	deleteByUserErr error
	saveErr         error
	getByCredIDErr  error
}

func (s *faultyCredStore) Save(ctx context.Context, cred *Credential) error {
	if s.saveErr != nil {
		return s.saveErr
	}
	return s.inner.Save(ctx, cred)
}

func (s *faultyCredStore) GetByUserID(ctx context.Context, userID []byte) ([]*Credential, error) {
	if s.getByUserIDErr != nil {
		return nil, s.getByUserIDErr
	}
	return s.inner.GetByUserID(ctx, userID)
}

func (s *faultyCredStore) GetByCredentialID(ctx context.Context, credID []byte) (*Credential, error) {
	if s.getByCredIDErr != nil {
		return nil, s.getByCredIDErr
	}
	return s.inner.GetByCredentialID(ctx, credID)
}

func (s *faultyCredStore) Update(ctx context.Context, cred *Credential) error {
	return s.inner.Update(ctx, cred)
}

func (s *faultyCredStore) Delete(ctx context.Context, credID []byte) error {
	return s.inner.Delete(ctx, credID)
}

func (s *faultyCredStore) DeleteByUserID(ctx context.Context, userID []byte) error {
	if s.deleteByUserErr != nil {
		return s.deleteByUserErr
	}
	return s.inner.DeleteByUserID(ctx, userID)
}

// ----- configurable failing SessionStore -----

type faultySessionStore struct {
	inner SessionStore

	saveErr error
	getErr  error
}

func (s *faultySessionStore) Save(ctx context.Context, data *webauthn.SessionData) (string, error) {
	if s.saveErr != nil {
		return "", s.saveErr
	}
	return s.inner.Save(ctx, data)
}

func (s *faultySessionStore) Get(ctx context.Context, sessionID string) (*webauthn.SessionData, error) {
	if s.getErr != nil {
		return nil, s.getErr
	}
	return s.inner.Get(ctx, sessionID)
}

// Take honours getErr: it is the fault injection point for "the ceremony
// session could not be fetched", which the service now reaches through the
// atomic claim rather than a plain Get.
func (s *faultySessionStore) Take(ctx context.Context, sessionID string) (*webauthn.SessionData, error) {
	if s.getErr != nil {
		return nil, s.getErr
	}
	return s.inner.Take(ctx, sessionID)
}

func (s *faultySessionStore) Delete(ctx context.Context, sessionID string) error {
	return s.inner.Delete(ctx, sessionID)
}

// newServiceWith builds a Service backed by the given (possibly faulty)
// stores using the same valid config as the rest of the suite. Registration
// is opened explicitly so the store-fault branches past the policy gate stay
// reachable.
func newServiceWith(t *testing.T, us UserStore, ss SessionStore, cs CredentialStore) *Service {
	t.Helper()
	cfg := validTestConfig()
	cfg.AllowPublicRegistration = openRegistration()
	svc, err := NewService(ServiceParams{
		Config:          cfg,
		UserStore:       us,
		SessionStore:    ss,
		CredentialStore: cs,
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return svc
}

// ----- BeginRegistration error branches -----

func TestService_BeginRegistration_GetByEmailError(t *testing.T) {
	users, creds := newTestStores(t)
	us := &faultyUserStore{inner: users, getByEmailErr: errBoom}
	svc := newServiceWith(t, us, NewMemorySessionStore(), creds)

	_, _, err := svc.BeginRegistration(context.Background(), "x@example.com", "X")
	if err == nil {
		t.Fatal("expected error when GetByEmail fails")
	}
	if !errors.Is(err, errBoom) {
		t.Fatalf("expected wrapped errBoom, got %v", err)
	}
	// A non-not-found store fault must NOT be swallowed as create path.
	if IsUserNotFound(err) {
		t.Fatal("store fault must not be classified as user-not-found")
	}
}

func TestService_BeginRegistration_CreateError(t *testing.T) {
	// GetByEmail returns not-found (memory store, no user), Create fails.
	users, creds := newTestStores(t)
	us := &faultyUserStore{inner: users, createErr: errBoom}
	svc := newServiceWith(t, us, NewMemorySessionStore(), creds)

	_, _, err := svc.BeginRegistration(context.Background(), "new@example.com", "New")
	if !errors.Is(err, errBoom) {
		t.Fatalf("expected create error, got %v", err)
	}
}

func TestService_BeginRegistration_GetCredentialsError(t *testing.T) {
	users, creds := newTestStores(t)
	cs := &faultyCredStore{inner: creds, getByUserIDErr: errBoom}
	svc := newServiceWith(t, users, NewMemorySessionStore(), cs)

	_, _, err := svc.BeginRegistration(context.Background(), "c@example.com", "C")
	if !errors.Is(err, errBoom) {
		t.Fatalf("expected get-credentials error, got %v", err)
	}
}

func TestService_BeginRegistration_SaveSessionError(t *testing.T) {
	users, creds := newTestStores(t)
	ss := &faultySessionStore{inner: NewMemorySessionStore(), saveErr: errBoom}
	svc := newServiceWith(t, users, ss, creds)

	_, _, err := svc.BeginRegistration(context.Background(), "s@example.com", "S")
	if !errors.Is(err, errBoom) {
		t.Fatalf("expected save-session error, got %v", err)
	}
}

// ----- FinishRegistration error branches -----

func TestService_FinishRegistration_GetSessionError(t *testing.T) {
	users, creds := newTestStores(t)
	ss := &faultySessionStore{inner: NewMemorySessionStore(), getErr: errBoom}
	svc := newServiceWith(t, users, ss, creds)

	_, _, err := svc.FinishRegistration(context.Background(), "missing", nil)
	if !errors.Is(err, errBoom) {
		t.Fatalf("expected get-session error, got %v", err)
	}
}

func TestService_FinishRegistration_GetUserError(t *testing.T) {
	ctx := context.Background()
	mem := NewMemorySessionStore()
	users, creds := newTestStores(t)
	us := &faultyUserStore{inner: users, getByIDErr: errBoom}
	svc := newServiceWith(t, us, mem, creds)

	// Stash a session so Get succeeds and we reach the GetByID branch.
	sessionID, err := mem.Save(ctx, &webauthn.SessionData{UserID: []byte("1")})
	if err != nil {
		t.Fatalf("seed session: %v", err)
	}

	_, _, err = svc.FinishRegistration(ctx, sessionID, nil)
	if !errors.Is(err, errBoom) {
		t.Fatalf("expected get-user error, got %v", err)
	}
}

// ----- BeginLogin error branches -----

func TestService_BeginLogin_GetUserError(t *testing.T) {
	users, creds := newTestStores(t)
	us := &faultyUserStore{inner: users, getByIDErr: errBoom}
	svc := newServiceWith(t, us, NewMemorySessionStore(), creds)

	_, _, err := svc.BeginLogin(context.Background(), []byte("1"))
	if !errors.Is(err, errBoom) {
		t.Fatalf("expected get-user error, got %v", err)
	}
}

func TestService_BeginLogin_GetCredentialsError(t *testing.T) {
	ctx := context.Background()
	users, creds := newTestStores(t)
	user, err := users.Create(ctx, "bl@example.com", "BL")
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	cs := &faultyCredStore{inner: creds, getByUserIDErr: errBoom}
	svc := newServiceWith(t, users, NewMemorySessionStore(), cs)

	_, _, err = svc.BeginLogin(ctx, user.WebAuthnID())
	if !errors.Is(err, errBoom) {
		t.Fatalf("expected get-credentials error, got %v", err)
	}
}

func TestService_BeginLogin_SaveSessionError_Discoverable(t *testing.T) {
	// Discoverable flow (nil userID) reaches session.Save directly.
	users, creds := newTestStores(t)
	ss := &faultySessionStore{inner: NewMemorySessionStore(), saveErr: errBoom}
	svc := newServiceWith(t, users, ss, creds)

	_, _, err := svc.BeginLogin(context.Background(), nil)
	if !errors.Is(err, errBoom) {
		t.Fatalf("expected save-session error, got %v", err)
	}
}

// ----- FinishLogin error branches -----

func TestService_FinishLogin_GetSessionError(t *testing.T) {
	users, creds := newTestStores(t)
	ss := &faultySessionStore{inner: NewMemorySessionStore(), getErr: errBoom}
	svc := newServiceWith(t, users, ss, creds)

	_, _, err := svc.FinishLogin(context.Background(), "missing", []byte("1"), nil)
	if !errors.Is(err, errBoom) {
		t.Fatalf("expected get-session error, got %v", err)
	}
}

func TestService_FinishLogin_GetUserError(t *testing.T) {
	ctx := context.Background()
	mem := NewMemorySessionStore()
	users, creds := newTestStores(t)
	us := &faultyUserStore{inner: users, getByIDErr: errBoom}
	svc := newServiceWith(t, us, mem, creds)

	sessionID, err := mem.Save(ctx, &webauthn.SessionData{UserID: []byte("1")})
	if err != nil {
		t.Fatalf("seed session: %v", err)
	}

	// User-identified flow (non-nil userID) reaches GetByID before validation.
	_, _, err = svc.FinishLogin(ctx, sessionID, []byte("1"), nil)
	if !errors.Is(err, errBoom) {
		t.Fatalf("expected get-user error, got %v", err)
	}
}

// ----- IsRegistered error branch -----

func TestService_IsRegistered_GetCredentialsError(t *testing.T) {
	users, creds := newTestStores(t)
	cs := &faultyCredStore{inner: creds, getByUserIDErr: errBoom}
	svc := newServiceWith(t, users, NewMemorySessionStore(), cs)

	ok, err := svc.IsRegistered(context.Background(), []byte("1"))
	if !errors.Is(err, errBoom) {
		t.Fatalf("expected get-credentials error, got %v", err)
	}
	if ok {
		t.Fatal("IsRegistered should be false on error")
	}
}

// ----- DeleteUser error branch -----

func TestService_DeleteUser_DeleteCredentialsError(t *testing.T) {
	users, creds := newTestStores(t)
	cs := &faultyCredStore{inner: creds, deleteByUserErr: errBoom}
	svc := newServiceWith(t, users, NewMemorySessionStore(), cs)
	user, err := users.Create(context.Background(), "alice@example.com", "Alice")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	err = svc.DeleteUser(context.Background(), user.WebAuthnID())
	if !errors.Is(err, errBoom) {
		t.Fatalf("expected delete-credentials error, got %v", err)
	}
}

// ----- discoverableUserHandler -----

func TestService_DiscoverableUserHandler(t *testing.T) {
	ctx := context.Background()
	users, creds := newTestStores(t)
	user, err := users.Create(ctx, "disc@example.com", "Disc")
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	svc := newServiceWith(t, users, NewMemorySessionStore(), creds)

	handler := svc.discoverableUserHandler(ctx)

	// Happy path: handle resolves to the user.
	got, err := handler(nil, user.WebAuthnID())
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if string(got.WebAuthnID()) != string(user.WebAuthnID()) {
		t.Fatalf("handler returned wrong user")
	}

	// Error path: unknown handle surfaces the store error.
	if _, err := handler(nil, []byte("does-not-exist")); err == nil {
		t.Fatal("expected error for unknown user handle")
	}
}

// ----- QRDBAdapterConfigError.Error() -----

func TestQRDBAdapterConfigError_Error(t *testing.T) {
	cases := []struct {
		name string
		err  *QRDBAdapterConfigError
		want string
	}{
		{
			name: "with field",
			err:  &QRDBAdapterConfigError{Field: "Users"},
			want: "webauthn: qrdb adapter: missing or invalid field: Users",
		},
		{
			name: "empty field",
			err:  &QRDBAdapterConfigError{},
			want: "webauthn: qrdb adapter: invalid configuration",
		},
		{
			name: "nil receiver",
			err:  nil,
			want: "webauthn: qrdb adapter: invalid configuration",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.err.Error(); got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		})
	}
}

// ----- VerifyToken nil public key -----

func TestDefaultJWTGenerator_VerifyToken_NoPublicKey(t *testing.T) {
	// Construct a generator that has a signer but no public key, mimicking a
	// signing-only key whose Public() is unavailable.
	gen := &DefaultJWTGenerator{
		issuer:   "go-xkms",
		audience: []string{"go-xkms"},
	}
	_, err := gen.VerifyToken("any.token.value")
	if err == nil {
		t.Fatal("expected error when public key is unavailable")
	}
	if err.Error() != "public key not available for verification" {
		t.Fatalf("unexpected error: %v", err)
	}
}
