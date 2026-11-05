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
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"

	"github.com/jeremyhahn/go-xkms/pkg/testutil"
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
	return copyUser(u), nil
}

// copyUser returns a copy of a stored record, as qrdb's transport decodes a
// fresh User per call; callers never share the fake's state.
func copyUser(u *qrdbtransport.User) *qrdbtransport.User {
	c := *u
	c.AuthMethods = slices.Clone(u.AuthMethods)
	return &c
}

func (f *fakeUserClient) GetUser(ctx context.Context, id uint64) (*qrdbtransport.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, ok := f.byID[id]
	if !ok {
		return nil, errFakeUserNotFound
	}
	return copyUser(u), nil
}

func (f *fakeUserClient) GetUserByUsername(ctx context.Context, tenantID, username string) (*qrdbtransport.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, ok := f.byUname[f.keyFor(tenantID, username)]
	if !ok {
		return nil, errFakeUserNotFound
	}
	return copyUser(u), nil
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
	return copyUser(u), nil
}

// setStanding rewrites the record's lifecycle and auth-method policy, the way
// an administrator's action on the qrdb account would.
func (f *fakeUserClient) setStanding(t *testing.T, tenantID, email string, state qrdbsdk.Lifecycle, methods []string) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	u, ok := f.byEmail[f.emailKeyFor(tenantID, email)]
	if !ok {
		t.Fatalf("setStanding: no account for %q", email)
	}
	u.Lifecycle = string(state)
	u.AuthMethods = methods
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
	if req.Username != "" && req.Username != u.Username {
		nk := f.keyFor(u.TenantID, req.Username)
		if _, taken := f.byUname[nk]; taken {
			return nil, errors.New("already exists")
		}
		delete(f.byUname, f.keyFor(u.TenantID, u.Username))
		u.Username = req.Username
		f.byUname[nk] = u
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
	return copyUser(u), nil
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
	if u.Email != "" {
		delete(f.byEmail, f.emailKeyFor(u.TenantID, u.Email))
	}
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

func (f *fakeUserClient) SuspendUser(ctx context.Context, id uint64) error {
	return nil
}

func (f *fakeUserClient) UnsuspendUser(ctx context.Context, id uint64) error {
	return nil
}

func (f *fakeUserClient) RemoveCertBinding(ctx context.Context, userID uint64, thumbprint string) (*qrdbtransport.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, ok := f.byID[userID]
	if !ok {
		return nil, errFakeUserNotFound
	}
	return copyUser(u), nil
}

func (f *fakeUserClient) AddCertBinding(ctx context.Context, userID uint64, thumbprint string, notAfterUnix int64) (*qrdbtransport.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, ok := f.byID[userID]
	if !ok {
		return nil, errFakeUserNotFound
	}
	return copyUser(u), nil
}

// ----- adapter tests -----

// newTestDAOFactory returns a DAO factory over a fresh in-process go-qrdb
// KV store, which supports the atomic conditional writes and secondary
// indexes the credential store relies on.
func newTestDAOFactory() *qrdbsdk.DAOFactory {
	kv := qrdbsdk.NewMemoryKVStore()
	return qrdbsdk.NewDAOFactory(func(uint64) qrdbsdk.KVStore { return kv })
}

// newTestStores returns a user and credential store pair over a fake qrdb
// user client and a real in-process DAO.
func newTestStores(t testing.TB) (UserStore, CredentialStore) {
	t.Helper()
	us, cs, _ := newTestAdapterWith(t, newTestDAOFactory())
	return us, cs
}

func newTestAdapter(t testing.TB) (UserStore, CredentialStore, *fakeUserClient) {
	t.Helper()
	return newTestAdapterWith(t, newTestDAOFactory())
}

func newTestAdapterWith(t testing.TB, factory *qrdbsdk.DAOFactory) (UserStore, CredentialStore, *fakeUserClient) {
	t.Helper()
	u := newFakeUserClient()
	us, cs, err := NewQRDBUserStoreAdapter(QRDBUserStoreOptions{
		Users: u, DAOFactory: factory, TenantID: "system", KV: testutil.NewQRDBFakeTransport(),
	})
	if err != nil {
		t.Fatalf("adapter: %v", err)
	}
	return us, cs, u
}

func TestQRDBAdapter_NewMissingFields(t *testing.T) {
	kv := testutil.NewQRDBFakeTransport()
	cases := []QRDBUserStoreOptions{
		{DAOFactory: newTestDAOFactory(), TenantID: "system", KV: kv},
		{Users: newFakeUserClient(), TenantID: "system", KV: kv},
		{Users: newFakeUserClient(), DAOFactory: newTestDAOFactory(), KV: kv},
		{Users: newFakeUserClient(), DAOFactory: newTestDAOFactory(), TenantID: "system"},
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

// plainKVClient carries only the KVClient verbs: embedding the interface hides the
// fake's guarded verbs, as a transport without conditional writes would.
type plainKVClient struct{ qrdbtransport.KVClient }

func TestQRDBAdapter_NewRejectsKVWithoutGuardedVerbs(t *testing.T) {
	_, _, err := NewQRDBUserStoreAdapter(QRDBUserStoreOptions{
		Users: newFakeUserClient(), DAOFactory: newTestDAOFactory(), TenantID: "system",
		KV: plainKVClient{testutil.NewQRDBFakeTransport()},
	})
	var unsupported *QRDBGuardedKVUnsupportedError
	if !errors.As(err, &unsupported) {
		t.Fatalf("expected *QRDBGuardedKVUnsupportedError, got %T (%v)", err, err)
	}
}

// raceCreate runs n Creates of one email from a common start and returns the
// users the winners got and the errors the losers got.
func raceCreate(t *testing.T, us UserStore, email string, n int) ([]User, []error) {
	t.Helper()
	var (
		wg    sync.WaitGroup
		mu    sync.Mutex
		start = make(chan struct{})
		won   []User
		lost  []error
	)
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			u, err := us.Create(context.Background(), email, "Racer")
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				lost = append(lost, err)
				return
			}
			won = append(won, u)
		}()
	}
	close(start)
	wg.Wait()
	return won, lost
}

// requireOneEnrolment asserts exactly one caller won the enrolment, holding a
// claim, and every other caller was told an enrolment is in progress.
func requireOneEnrolment(t *testing.T, won []User, lost []error) string {
	t.Helper()
	if len(won) != 1 {
		t.Fatalf("expected exactly one enrolment, got %d (losers: %v)", len(won), lost)
	}
	claimant, ok := won[0].(enrolmentClaimant)
	if !ok || claimant.EnrolmentClaim() == "" {
		t.Fatalf("the winner carries no enrolment claim: %T", won[0])
	}
	for _, err := range lost {
		var inProgress *EnrolmentInProgressError
		if !errors.As(err, &inProgress) {
			t.Fatalf("loser: expected *EnrolmentInProgressError, got %T (%v)", err, err)
		}
	}
	return claimant.EnrolmentClaim()
}

// claimKeyOf returns the store and the enrolment claim key for user.
func claimKeyOf(t *testing.T, us UserStore, user User) (*qrdbUserStore, string) {
	t.Helper()
	id, err := UserIDFromHandle(user.WebAuthnID())
	if err != nil {
		t.Fatalf("user id: %v", err)
	}
	store := us.(*qrdbUserStore)
	return store, store.claimKey(id)
}

func TestQRDBAdapter_Create_ConcurrentRegistrationsOneWinner(t *testing.T) {
	us, _ := newTestStores(t)
	won, lost := raceCreate(t, us, "race@example.com", 16)
	requireOneEnrolment(t, won, lost)
}

func TestQRDBAdapter_Create_LiveClaimRefusesRecovery(t *testing.T) {
	us, _ := newTestStores(t)
	ctx := context.Background()
	if _, err := us.Create(ctx, "live@example.com", "Live"); err != nil {
		t.Fatalf("create: %v", err)
	}
	_, err := us.Create(ctx, "live@example.com", "Live")
	var inProgress *EnrolmentInProgressError
	if !errors.As(err, &inProgress) {
		t.Fatalf("expected *EnrolmentInProgressError, got %T (%v)", err, err)
	}
}

func TestQRDBAdapter_Create_ExpiredClaimTakenOverByOne(t *testing.T) {
	us, _ := newTestStores(t)
	ctx := context.Background()
	first, err := us.Create(ctx, "stale@example.com", "Stale")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	store, key := claimKeyOf(t, us, first)
	if err := store.kv.Put(ctx, key, encodeEnrolmentClaim("abandoned", time.Now().Add(-time.Second))); err != nil {
		t.Fatalf("seed expired claim: %v", err)
	}
	won, lost := raceCreate(t, us, "stale@example.com", 16)
	if token := requireOneEnrolment(t, won, lost); token == "abandoned" {
		t.Fatal("the takeover kept the expired claim's token")
	}
}

func TestQRDBAdapter_ConsumeEnrolmentClaim(t *testing.T) {
	us, _ := newTestStores(t)
	ctx := context.Background()
	user, err := us.Create(ctx, "consume@example.com", "Consume")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	store, _ := claimKeyOf(t, us, user)
	var lostErr *EnrolmentClaimLostError
	if err := store.consumeEnrolmentClaim(ctx, user, "not-the-claim"); !errors.As(err, &lostErr) {
		t.Fatalf("foreign token: expected *EnrolmentClaimLostError, got %T (%v)", err, err)
	}
	token := user.(enrolmentClaimant).EnrolmentClaim()
	if err := store.consumeEnrolmentClaim(ctx, user, token); err != nil {
		t.Fatalf("consume: %v", err)
	}
	if err := store.consumeEnrolmentClaim(ctx, user, token); !errors.As(err, &lostErr) {
		t.Fatalf("second consume: expected *EnrolmentClaimLostError, got %T (%v)", err, err)
	}
}

func TestQRDBAdapter_ConsumeEnrolmentClaim_Expired(t *testing.T) {
	us, _ := newTestStores(t)
	ctx := context.Background()
	user, err := us.Create(ctx, "expired@example.com", "Expired")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	store, key := claimKeyOf(t, us, user)
	token := user.(enrolmentClaimant).EnrolmentClaim()
	if err := store.kv.Put(ctx, key, encodeEnrolmentClaim(token, time.Now().Add(-time.Second))); err != nil {
		t.Fatalf("expire claim: %v", err)
	}
	var lostErr *EnrolmentClaimLostError
	if err := store.consumeEnrolmentClaim(ctx, user, token); !errors.As(err, &lostErr) {
		t.Fatalf("expected *EnrolmentClaimLostError, got %T (%v)", err, err)
	}
}

func TestFinishRegistration_ConsumesEnrolmentClaim(t *testing.T) {
	f := newEnrollFixture(t, true)
	user, _ := f.enroll(t, "won@example.com")
	store, key := claimKeyOf(t, f.users, user)
	_, err := store.kv.Get(context.Background(), key)
	var notFound *qrdbtransport.KeyNotFoundError
	if !errors.As(err, &notFound) {
		t.Fatalf("expected the claim consumed, got %v", err)
	}
}

func TestFinishRegistration_LostClaimAddsNoCredential(t *testing.T) {
	f := newEnrollFixture(t, true)
	ctx := context.Background()
	options, sessionID, err := f.svc.BeginRegistration(ctx, "lost@example.com", "Lost")
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	user, err := f.users.GetByEmail(ctx, "lost@example.com")
	if err != nil {
		t.Fatalf("get user: %v", err)
	}
	store, key := claimKeyOf(t, f.users, user)
	if err := store.kv.Put(ctx, key, encodeEnrolmentClaim("taken-over", time.Now().Add(time.Minute))); err != nil {
		t.Fatalf("take the claim over: %v", err)
	}
	_, err = f.attest(t, options, sessionID, newEC2Credential(t))
	var lostErr *EnrolmentClaimLostError
	if !errors.As(err, &lostErr) {
		t.Fatalf("expected *EnrolmentClaimLostError, got %T (%v)", err, err)
	}
	creds, err := f.creds.GetByUserID(ctx, user.WebAuthnID())
	if err != nil {
		t.Fatalf("get credentials: %v", err)
	}
	if len(creds) != 0 {
		t.Fatalf("a lost claim added %d credential(s)", len(creds))
	}
}

// errCredentialSaveFailed is the fault saveGatedCredStore injects.
var errCredentialSaveFailed = errors.New("credential save failed")

// saveGatedCredStore runs gate before every Save; a gate error fails the
// save without storing the credential.
type saveGatedCredStore struct {
	CredentialStore
	gate func() error
}

func (s *saveGatedCredStore) Save(ctx context.Context, cred *Credential) error {
	if err := s.gate(); err != nil {
		return err
	}
	return s.CredentialStore.Save(ctx, cred)
}

// credentialCount returns how many credentials the account for email holds.
func credentialCount(t *testing.T, f *enrollFixture, email string) int {
	t.Helper()
	ctx := context.Background()
	user, err := f.users.GetByEmail(ctx, email)
	if err != nil {
		t.Fatalf("get user: %v", err)
	}
	creds, err := f.creds.GetByUserID(ctx, user.WebAuthnID())
	if err != nil {
		t.Fatalf("get credentials: %v", err)
	}
	return len(creds)
}

func TestFinishRegistration_FailedSaveLeavesEmailRegistrable(t *testing.T) {
	f := newEnrollFixture(t, true)
	ctx := context.Background()
	const email = "retry@example.com"
	failing := true
	f.svc.creds = &saveGatedCredStore{CredentialStore: f.creds, gate: func() error {
		if failing {
			return errCredentialSaveFailed
		}
		return nil
	}}

	options, sessionID, err := f.svc.BeginRegistration(ctx, email, "Retry")
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if _, err := f.attest(t, options, sessionID, newEC2Credential(t)); !errors.Is(err, errCredentialSaveFailed) {
		t.Fatalf("expected the injected save failure, got %v", err)
	}
	if n := credentialCount(t, f, email); n != 0 {
		t.Fatalf("a failed save left %d credential(s)", n)
	}

	failing = false
	options, sessionID, err = f.svc.BeginRegistration(ctx, email, "Retry")
	if err != nil {
		t.Fatalf("a registration after a failed save was refused: %v", err)
	}
	if _, err := f.attest(t, options, sessionID, newEC2Credential(t)); err != nil {
		t.Fatalf("finish after a failed save: %v", err)
	}
	if n := credentialCount(t, f, email); n != 1 {
		t.Fatalf("expected one credential, got %d", n)
	}
}

func TestFinishRegistration_SaveInFlightRefusesSecondEnrolment(t *testing.T) {
	f := newEnrollFixture(t, true)
	ctx := context.Background()
	const email = "inflight@example.com"
	entered := make(chan struct{})
	release := make(chan struct{})
	f.svc.creds = &saveGatedCredStore{CredentialStore: f.creds, gate: func() error {
		close(entered)
		<-release
		return nil
	}}

	options, sessionID, err := f.svc.BeginRegistration(ctx, email, "In Flight")
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	finished := make(chan error, 1)
	go func() {
		_, err := f.attest(t, options, sessionID, newEC2Credential(t))
		finished <- err
	}()
	<-entered

	// The first finish has consumed its claim and is saving its credential.
	if _, _, err := f.svc.BeginRegistration(ctx, email, "Second"); err == nil {
		t.Fatal("a second registration began while the first was saving its credential")
	}
	close(release)
	if err := <-finished; err != nil {
		t.Fatalf("finish: %v", err)
	}
	if _, _, err := f.svc.BeginRegistration(ctx, email, "Third"); err == nil {
		t.Fatal("a registration began for an account that holds a credential")
	}
	if n := credentialCount(t, f, email); n != 1 {
		t.Fatalf("expected one credential, got %d", n)
	}
}

// TestFinishRegistration_SaveStalledPastClaimTTLEnrolsOnePasskey stalls the
// first finish's credential save until its consumed claim has expired, lets
// a second public registration of the same email run to completion, then
// releases the first save: the account must still hold one credential.
func TestFinishRegistration_SaveStalledPastClaimTTLEnrolsOnePasskey(t *testing.T) {
	f := newEnrollFixture(t, true)
	ctx := context.Background()
	const email = "stalled@example.com"
	entered := make(chan struct{})
	release := make(chan struct{})
	// Only the first save takes the stall token; every later save runs.
	stall := make(chan struct{}, 1)
	stall <- struct{}{}
	f.svc.creds = &saveGatedCredStore{CredentialStore: f.creds, gate: func() error {
		select {
		case <-stall:
			close(entered)
			<-release
		default:
		}
		return nil
	}}

	options, sessionID, err := f.svc.BeginRegistration(ctx, email, "Stalled")
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	finished := make(chan error, 1)
	go func() {
		_, err := f.attest(t, options, sessionID, newEC2Credential(t))
		finished <- err
	}()
	<-entered

	// The first save outlives its consumed claim.
	user, err := f.users.GetByEmail(ctx, email)
	if err != nil {
		t.Fatalf("get user: %v", err)
	}
	store, key := claimKeyOf(t, f.users, user)
	current, found, err := store.readClaim(ctx, key)
	if err != nil || !found {
		t.Fatalf("read the consumed claim: found=%v err=%v", found, err)
	}
	held, _, _ := decodeEnrolmentClaim(current)
	if err := store.kv.Put(ctx, key, encodeEnrolmentClaim(held, time.Unix(0, 0))); err != nil {
		t.Fatalf("expire the consumed claim: %v", err)
	}

	secondErr := func() error {
		options, sessionID, err := f.svc.BeginRegistration(ctx, email, "Second")
		if err != nil {
			return err
		}
		_, err = f.attest(t, options, sessionID, newEC2Credential(t))
		return err
	}()
	close(release)
	firstErr := <-finished

	if n := credentialCount(t, f, email); n != 1 {
		t.Fatalf("expected one credential, got %d", n)
	}
	if secondErr == nil {
		t.Fatal("a second passkey enrolled while the first save was stalled past the claim TTL")
	}
	if firstErr != nil {
		t.Fatalf("the stalled finish: %v", firstErr)
	}
}

func TestFinishRegistration_EnrolmentRefusedForUserWithCredential(t *testing.T) {
	f := newEnrollFixture(t, true)
	ctx := context.Background()
	options, sessionID, err := f.svc.BeginRegistration(ctx, "held@example.com", "Held")
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	user, err := f.users.GetByEmail(ctx, "held@example.com")
	if err != nil {
		t.Fatalf("get user: %v", err)
	}
	held := &Credential{ID: []byte("pre-existing-credential"), UserID: user.WebAuthnID(), PublicKey: []byte{1}}
	if err := f.creds.Save(ctx, held); err != nil {
		t.Fatalf("seed credential: %v", err)
	}
	_, err = f.attest(t, options, sessionID, newEC2Credential(t))
	if !errors.Is(err, ErrRegistrationRefused) {
		t.Fatalf("expected ErrRegistrationRefused, got %v", err)
	}
	creds, err := f.creds.GetByUserID(ctx, user.WebAuthnID())
	if err != nil {
		t.Fatalf("get credentials: %v", err)
	}
	if len(creds) != 1 {
		t.Fatalf("expected only the held credential, got %d", len(creds))
	}
}

func TestQRDBAdapter_CreateAndGetByEmail(t *testing.T) {
	us, _, _ := newTestAdapter(t)
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

// TestQRDBAdapter_Create_UsernameIsUserID pins owner ruling 166
// (go-xkms#1468): the qrdb Username, the certificate CN, carries the qrdb
// user ID and never the email, while login still resolves by email.
func TestQRDBAdapter_Create_UsernameIsUserID(t *testing.T) {
	us, _, fake := newTestAdapter(t)
	ctx := context.Background()
	for _, email := range []string{"alice@example.com", "bob@example.com"} {
		user, err := us.Create(ctx, email, "")
		if err != nil {
			t.Fatalf("Create(%s): %v", email, err)
		}
		id, err := UserIDFromHandle(user.WebAuthnID())
		if err != nil {
			t.Fatalf("UserIDFromHandle: %v", err)
		}
		rec, err := fake.GetUser(ctx, id)
		if err != nil {
			t.Fatalf("GetUser(%d): %v", id, err)
		}
		if want := strconv.FormatUint(id, 10); rec.Username != want {
			t.Fatalf("Username = %q, want the user ID %q", rec.Username, want)
		}
		if rec.Email != email {
			t.Fatalf("Email = %q, want %q", rec.Email, email)
		}

		got, err := us.GetByEmail(ctx, email)
		if err != nil {
			t.Fatalf("GetByEmail(%s): %v", email, err)
		}
		if string(got.WebAuthnID()) != string(user.WebAuthnID()) {
			t.Fatalf("GetByEmail(%s) resolved a different user", email)
		}
	}
}

// TestQRDBAdapter_Create_DuplicateEmail checks a second registration of the
// same email is refused and leaves no extra record behind.
func TestQRDBAdapter_Create_DuplicateEmail(t *testing.T) {
	us, _, fake := newTestAdapter(t)
	ctx := context.Background()
	if _, err := us.Create(ctx, "alice@example.com", "Alice"); err != nil {
		t.Fatalf("first Create: %v", err)
	}
	if _, err := us.Create(ctx, "alice@example.com", "Alice"); err == nil {
		t.Fatal("second Create with the same email succeeded")
	}
	if n := len(fake.byID); n != 1 {
		t.Fatalf("records after a refused duplicate = %d, want 1", n)
	}
}

func TestQRDBAdapter_GetByEmail_NotFound(t *testing.T) {
	us, _, _ := newTestAdapter(t)
	_, err := us.GetByEmail(context.Background(), "nobody@example.com")
	if !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("expected ErrUserNotFound, got %v", err)
	}
}

func TestQRDBAdapter_GetByID(t *testing.T) {
	us, _, _ := newTestAdapter(t)
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
	us, _, _ := newTestAdapter(t)
	_, err := us.GetByID(context.Background(), nil)
	if !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("expected ErrUserNotFound, got %v", err)
	}
}

func TestQRDBAdapter_CredentialSaveAndGet(t *testing.T) {
	us, cs, _ := newTestAdapter(t)
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
	us, cs, _ := newTestAdapter(t)
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
	us, cs, _ := newTestAdapter(t)
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
	_, cs, _ := newTestAdapter(t)
	cred := &Credential{ID: []byte("missing"), UserID: []byte("1")}
	err := cs.Update(context.Background(), cred)
	if !errors.Is(err, ErrCredentialNotFound) {
		t.Fatalf("expected ErrCredentialNotFound, got %v", err)
	}
}

func TestQRDBAdapter_CredentialDelete(t *testing.T) {
	us, cs, _ := newTestAdapter(t)
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
	_, cs, _ := newTestAdapter(t)
	err := cs.Delete(context.Background(), []byte("nope"))
	if !errors.Is(err, ErrCredentialNotFound) {
		t.Fatalf("expected ErrCredentialNotFound, got %v", err)
	}
}

func TestQRDBAdapter_DeleteByUserID(t *testing.T) {
	us, cs, _ := newTestAdapter(t)
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
	us, cs, _ := newTestAdapter(t)
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
	_, cs, _ := newTestAdapter(t)
	if err := cs.Save(context.Background(), nil); err == nil {
		t.Fatalf("expected error for nil credential")
	}
}

func TestQRDBAdapter_SaveCredential_EmptyID(t *testing.T) {
	_, cs, _ := newTestAdapter(t)
	err := cs.Save(context.Background(), &Credential{UserID: []byte("1")})
	if !errors.Is(err, ErrInvalidCredential) {
		t.Fatalf("expected ErrInvalidCredential, got %v", err)
	}
}

func TestQRDBAdapter_SaveUser_NilArg(t *testing.T) {
	us, _, _ := newTestAdapter(t)
	if err := us.Save(context.Background(), nil); err == nil {
		t.Fatalf("expected error for nil user")
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
