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
	"encoding/json"
	"errors"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"

	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeLegacyKV is an in-memory qrdb KV client holding the legacy shared
// keyspace. scanErr, listErr and deleteErr inject the failures a sealed
// barrier or a transport fault produces.
type fakeLegacyKV struct {
	mu        sync.Mutex
	data      map[string][]byte
	scanErr   error
	listErr   error
	deleteErr map[string]error
}

func newFakeLegacyKV() *fakeLegacyKV {
	return &fakeLegacyKV{data: make(map[string][]byte), deleteErr: make(map[string]error)}
}

func (f *fakeLegacyKV) Put(_ context.Context, key string, value []byte, _ ...qrdbtransport.WriteOption) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.data[key] = value
	return nil
}

func (f *fakeLegacyKV) Get(_ context.Context, key string, _ ...qrdbtransport.ReadOption) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.data[key]
	if !ok {
		return nil, &qrdbtransport.KeyNotFoundError{Key: key}
	}
	return v, nil
}

func (f *fakeLegacyKV) Delete(_ context.Context, key string, _ ...qrdbtransport.WriteOption) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.deleteErr[key]; err != nil {
		return err
	}
	if _, ok := f.data[key]; !ok {
		return &qrdbtransport.KeyNotFoundError{Key: key}
	}
	delete(f.data, key)
	return nil
}

func (f *fakeLegacyKV) List(_ context.Context, prefix string, _ ...qrdbtransport.ReadOption) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.listErr != nil {
		return nil, f.listErr
	}
	keys := make([]string, 0, len(f.data))
	for k := range f.data {
		if strings.HasPrefix(k, prefix) {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	return keys, nil
}

func (f *fakeLegacyKV) Scan(_ context.Context, prefix string, _ ...qrdbtransport.ReadOption) (map[string][]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.scanErr != nil {
		return nil, f.scanErr
	}
	out := make(map[string][]byte)
	for k, v := range f.data {
		if strings.HasPrefix(k, prefix) {
			out[k] = v
		}
	}
	return out, nil
}

func (f *fakeLegacyKV) Exists(_ context.Context, key string, _ ...qrdbtransport.ReadOption) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.data[key]
	return ok, nil
}

func (f *fakeLegacyKV) has(key string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.data[key]
	return ok
}

// failingCredentialStore is a target store whose Save fails.
type failingCredentialStore struct {
	CredentialStore
	saveErr error
}

func (s *failingCredentialStore) Save(context.Context, *Credential) error { return s.saveErr }

// legacyCredKey and legacyIndexKey spell the pre-v0.46 layout out literally,
// so a test fails if the migrator ever reads a different keyspace.
func legacyCredKey(credID []byte) string {
	return "__xkms:webauthn/credentials/" + encodeID(credID)
}

func legacyIndexKey(userID uint64) string {
	return "__xkms:webauthn/users/" + strconv.FormatUint(userID, 10) + "/credentials"
}

// seedLegacyCredential writes cred in the legacy layout: the JSON record and
// the owner's credential-ID index, as the pre-v0.46 store did.
func seedLegacyCredential(t *testing.T, kv *fakeLegacyKV, cred *Credential) {
	t.Helper()
	blob, err := json.Marshal(cred)
	require.NoError(t, err)
	kv.data[legacyCredKey(cred.ID)] = blob
	uid, err := UserIDFromHandle(cred.UserID)
	require.NoError(t, err)
	var ids []string
	if raw, ok := kv.data[legacyIndexKey(uid)]; ok {
		require.NoError(t, json.Unmarshal(raw, &ids))
	}
	idx, err := json.Marshal(append(ids, encodeID(cred.ID)))
	require.NoError(t, err)
	kv.data[legacyIndexKey(uid)] = idx
}

func createTenantUser(t *testing.T, users *fakeUserClient, tenantID, email string) []byte {
	t.Helper()
	u, err := users.CreateUser(context.Background(), &qrdbtransport.CreateUserRequest{
		Username: email, Email: email, TenantID: tenantID,
	})
	require.NoError(t, err)
	return HandleFromUserID(u.ID)
}

func legacyCred(id string, owner []byte) *Credential {
	return &Credential{ID: []byte(id), UserID: owner, PublicKey: []byte("pk-" + id), AttestationType: "none"}
}

type migrationFixture struct {
	kv    *fakeLegacyKV
	users *fakeUserClient
	store *daoCredentialStore
	alice []byte // tenant-a, two credentials
	bob   []byte // tenant-b, one credential
}

func newMigrationFixture(t *testing.T) *migrationFixture {
	t.Helper()
	f := &migrationFixture{
		kv:    newFakeLegacyKV(),
		users: newFakeUserClient(),
		store: newTestCredentialStore(t, newTestDAOFactory()),
	}
	f.alice = createTenantUser(t, f.users, "tenant-a", "alice@example.com")
	f.bob = createTenantUser(t, f.users, "tenant-b", "bob@example.com")
	// The raw credential ID is arbitrary bytes, not valid UTF-8.
	seedLegacyCredential(t, f.kv, legacyCred("alice-1\xff", f.alice))
	seedLegacyCredential(t, f.kv, legacyCred("alice-2", f.alice))
	seedLegacyCredential(t, f.kv, legacyCred("bob-1", f.bob))
	return f
}

func (f *migrationFixture) migration(store CredentialStore) LegacyCredentialMigration {
	return LegacyCredentialMigration{Legacy: f.kv, Users: f.users, TenantID: "tenant-a", Store: store}
}

func uidOf(t *testing.T, handle []byte) uint64 {
	t.Helper()
	id, err := UserIDFromHandle(handle)
	require.NoError(t, err)
	return id
}

func TestMigrateLegacyCredentials_MovesOldLayoutToTenantStore(t *testing.T) {
	f := newMigrationFixture(t)

	report, err := MigrateLegacyCredentials(context.Background(), f.migration(f.store))
	require.NoError(t, err)
	assert.Equal(t, CredentialMigrationReport{Migrated: 2, Skipped: 1}, report)

	creds, err := f.store.GetByUserID(context.Background(), f.alice)
	require.NoError(t, err)
	require.Len(t, creds, 2)
	got, err := f.store.GetByCredentialID(context.Background(), []byte("alice-1\xff"))
	require.NoError(t, err)
	assert.Equal(t, []byte("pk-alice-1\xff"), got.PublicKey)
	assert.Equal(t, f.alice, got.UserID)

	assert.False(t, f.kv.has(legacyCredKey([]byte("alice-1\xff"))))
	assert.False(t, f.kv.has(legacyCredKey([]byte("alice-2"))))
	assert.False(t, f.kv.has(legacyIndexKey(uidOf(t, f.alice))), "the owner's index goes with its last credential")

	// Another tenant's credential is left for that tenant's store open.
	assert.True(t, f.kv.has(legacyCredKey([]byte("bob-1"))))
	assert.True(t, f.kv.has(legacyIndexKey(uidOf(t, f.bob))))
	_, err = f.store.GetByCredentialID(context.Background(), []byte("bob-1"))
	assert.ErrorIs(t, err, ErrCredentialNotFound)
}

func TestMigrateLegacyCredentials_SecondRunMigratesNothing(t *testing.T) {
	f := newMigrationFixture(t)
	_, err := MigrateLegacyCredentials(context.Background(), f.migration(f.store))
	require.NoError(t, err)

	report, err := MigrateLegacyCredentials(context.Background(), f.migration(f.store))
	require.NoError(t, err)
	assert.Equal(t, 0, report.Migrated)
	assert.Equal(t, 0, report.Failed)
	assert.Equal(t, 1, report.Skipped)

	creds, err := f.store.GetByUserID(context.Background(), f.alice)
	require.NoError(t, err)
	assert.Len(t, creds, 2)
}

func TestMigrateLegacyCredentials_EmptyStore(t *testing.T) {
	m := LegacyCredentialMigration{
		Legacy:   newFakeLegacyKV(),
		Users:    newFakeUserClient(),
		TenantID: "tenant-a",
		Store:    newTestCredentialStore(t, newTestDAOFactory()),
	}
	report, err := MigrateLegacyCredentials(context.Background(), m)
	require.NoError(t, err)
	assert.Equal(t, CredentialMigrationReport{}, report)
}

func TestMigrateLegacyCredentials_LeavesKeysThatAreNotAnIndex(t *testing.T) {
	kv := newFakeLegacyKV()
	others := []string{
		"__xkms:webauthn/users/not-a-number/credentials",
		"__xkms:webauthn/users/7/profile",
	}
	for _, key := range others {
		kv.data[key] = []byte("{}")
	}
	m := LegacyCredentialMigration{
		Legacy: kv, Users: newFakeUserClient(), TenantID: "tenant-a",
		Store: newTestCredentialStore(t, newTestDAOFactory()),
	}

	_, err := MigrateLegacyCredentials(context.Background(), m)
	require.NoError(t, err)
	for _, key := range others {
		assert.True(t, kv.has(key), key)
	}
}

func TestMigrateLegacyCredentials_FailedSaveKeepsOldKey(t *testing.T) {
	f := newMigrationFixture(t)
	saveErr := errors.New("raft: no leader")

	report, err := MigrateLegacyCredentials(context.Background(),
		f.migration(&failingCredentialStore{CredentialStore: f.store, saveErr: saveErr}))

	var incomplete *CredentialMigrationIncompleteError
	require.ErrorAs(t, err, &incomplete)
	assert.Equal(t, 0, report.Migrated)
	assert.Equal(t, 2, report.Failed)
	assert.Len(t, report.Failures, 2)
	var move *CredentialMoveError
	require.ErrorAs(t, err, &move)
	assert.Equal(t, "save", move.Op)
	assert.ErrorIs(t, err, saveErr)

	assert.True(t, f.kv.has(legacyCredKey([]byte("alice-1\xff"))))
	assert.True(t, f.kv.has(legacyCredKey([]byte("alice-2"))))
	assert.True(t, f.kv.has(legacyIndexKey(uidOf(t, f.alice))))
}

func TestMigrateLegacyCredentials_CorruptRecords(t *testing.T) {
	cases := map[string][]byte{
		"undecodable":   []byte("{not json"),
		"empty id":      []byte(`{"id":"","user_id":"AAAAAAAAAAE="}`),
		"key mismatch":  []byte(`{"id":"b3RoZXI=","user_id":"AAAAAAAAAAE="}`),
		"sealed binary": {0x00, 0x9f, 0x31, 0x7a},
	}
	for name, blob := range cases {
		t.Run(name, func(t *testing.T) {
			kv := newFakeLegacyKV()
			key := legacyCredKey([]byte("corrupt"))
			kv.data[key] = blob
			m := LegacyCredentialMigration{
				Legacy: kv, Users: newFakeUserClient(), TenantID: "tenant-a",
				Store: newTestCredentialStore(t, newTestDAOFactory()),
			}

			report, err := MigrateLegacyCredentials(context.Background(), m)

			var corrupt *LegacyCredentialCorruptError
			require.ErrorAs(t, err, &corrupt)
			assert.Equal(t, key, corrupt.Key)
			assert.Equal(t, 1, report.Failed)
			assert.True(t, kv.has(key), "a corrupt record is never deleted")
		})
	}
}

func TestMigrateLegacyCredentials_CorruptRecordKeepsEveryIndex(t *testing.T) {
	kv := newFakeLegacyKV()
	users := newFakeUserClient()
	store := newTestCredentialStore(t, newTestDAOFactory())
	carol := createTenantUser(t, users, "tenant-a", "carol@example.com")
	dave := createTenantUser(t, users, "tenant-a", "dave@example.com")
	seedLegacyCredential(t, kv, legacyCred("carol-1", carol))
	seedLegacyCredential(t, kv, legacyCred("dave-1", dave))
	// Carol's only credential is corrupt: its blob no longer names her.
	carolKey := legacyCredKey([]byte("carol-1"))
	kv.data[carolKey] = []byte("{not json")
	m := LegacyCredentialMigration{Legacy: kv, Users: users, TenantID: "tenant-a", Store: store}

	report, err := MigrateLegacyCredentials(context.Background(), m)

	var corrupt *LegacyCredentialCorruptError
	require.ErrorAs(t, err, &corrupt)
	assert.Equal(t, carolKey, corrupt.Key)
	assert.Equal(t, 1, report.Migrated)
	assert.Equal(t, 1, report.Failed)
	assert.True(t, kv.has(carolKey), "a corrupt record is never deleted")
	assert.True(t, kv.has(legacyIndexKey(uidOf(t, carol))), "the index of a record with an unknown owner stays")
	assert.True(t, kv.has(legacyIndexKey(uidOf(t, dave))), "no index is deleted while an owner is unknown")
	assert.False(t, kv.has(legacyCredKey([]byte("dave-1"))))
	_, err = store.GetByCredentialID(context.Background(), []byte("dave-1"))
	require.NoError(t, err)

	// Once the blob is repaired, the next run moves it and cleans up.
	blob, err := json.Marshal(legacyCred("carol-1", carol))
	require.NoError(t, err)
	kv.data[carolKey] = blob

	report, err = MigrateLegacyCredentials(context.Background(), m)
	require.NoError(t, err)
	assert.Equal(t, CredentialMigrationReport{Migrated: 1}, report)
	assert.False(t, kv.has(carolKey))
	assert.False(t, kv.has(legacyIndexKey(uidOf(t, carol))))
	assert.False(t, kv.has(legacyIndexKey(uidOf(t, dave))))
	got, err := store.GetByCredentialID(context.Background(), []byte("carol-1"))
	require.NoError(t, err)
	assert.Equal(t, carol, got.UserID)
}

func TestMigrateLegacyCredentials_UnresolvableOwner(t *testing.T) {
	users := newFakeUserClient()
	noTenant := createTenantUser(t, users, "", "orphan@example.com")
	cases := map[string]struct {
		owner []byte
		cause error
	}{
		"bad handle":   {owner: []byte("short")},
		"deleted user": {owner: HandleFromUserID(9999)},
		"no tenant":    {owner: noTenant, cause: ErrCredentialOwnerHasNoTenant},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			kv := newFakeLegacyKV()
			cred := legacyCred("c-"+name, tc.owner)
			blob, err := json.Marshal(cred)
			require.NoError(t, err)
			kv.data[legacyCredKey(cred.ID)] = blob
			m := LegacyCredentialMigration{
				Legacy: kv, Users: users, TenantID: "tenant-a",
				Store: newTestCredentialStore(t, newTestDAOFactory()),
			}

			report, err := MigrateLegacyCredentials(context.Background(), m)

			var unresolved *CredentialOwnerUnresolvedError
			require.ErrorAs(t, err, &unresolved)
			assert.Equal(t, legacyCredKey(cred.ID), unresolved.Key)
			if tc.cause != nil {
				assert.ErrorIs(t, err, tc.cause)
			}
			assert.Equal(t, CredentialMigrationReport{Failed: 1, Failures: report.Failures}, report)
			assert.True(t, kv.has(legacyCredKey(cred.ID)))
		})
	}
}

func TestMigrateLegacyCredentials_CompletesAnInterruptedMove(t *testing.T) {
	f := newMigrationFixture(t)
	// An earlier run stored alice-2 but crashed before deleting its old key.
	require.NoError(t, f.store.Save(context.Background(), legacyCred("alice-2", f.alice)))

	report, err := MigrateLegacyCredentials(context.Background(), f.migration(f.store))
	require.NoError(t, err)
	assert.Equal(t, 2, report.Migrated)
	assert.False(t, f.kv.has(legacyCredKey([]byte("alice-2"))))
}

func TestMigrateLegacyCredentials_TargetOwnedByAnotherUser(t *testing.T) {
	f := newMigrationFixture(t)
	require.NoError(t, f.store.Save(context.Background(), legacyCred("alice-2", f.bob)))

	report, err := MigrateLegacyCredentials(context.Background(), f.migration(f.store))

	assert.ErrorIs(t, err, ErrCredentialOwnerMismatch)
	assert.Equal(t, 1, report.Migrated)
	assert.Equal(t, 1, report.Failed)
	assert.True(t, f.kv.has(legacyCredKey([]byte("alice-2"))))
	assert.True(t, f.kv.has(legacyIndexKey(uidOf(t, f.alice))), "the index stays while a credential is left")
}

func TestMigrateLegacyCredentials_FailedDeleteIsFinishedByTheNextRun(t *testing.T) {
	f := newMigrationFixture(t)
	key := legacyCredKey([]byte("alice-2"))
	f.kv.deleteErr[key] = errors.New("raft: timeout")

	report, err := MigrateLegacyCredentials(context.Background(), f.migration(f.store))
	var move *CredentialMoveError
	require.ErrorAs(t, err, &move)
	assert.Equal(t, "delete legacy key", move.Op)
	assert.Equal(t, 1, report.Migrated)
	assert.True(t, f.kv.has(key))
	_, err = f.store.GetByCredentialID(context.Background(), []byte("alice-2"))
	require.NoError(t, err, "the new record is in place before the old key is deleted")

	delete(f.kv.deleteErr, key)
	report, err = MigrateLegacyCredentials(context.Background(), f.migration(f.store))
	require.NoError(t, err)
	assert.Equal(t, 1, report.Migrated)
	assert.False(t, f.kv.has(key))
	assert.False(t, f.kv.has(legacyIndexKey(uidOf(t, f.alice))))
}

func TestMigrateLegacyCredentials_IndexCleanupFailures(t *testing.T) {
	t.Run("list", func(t *testing.T) {
		f := newMigrationFixture(t)
		f.kv.listErr = errors.New("barrier sealed")
		report, err := MigrateLegacyCredentials(context.Background(), f.migration(f.store))
		var scan *LegacyCredentialScanError
		require.ErrorAs(t, err, &scan)
		assert.Equal(t, "__xkms:webauthn/users/", scan.Prefix)
		assert.Equal(t, 2, report.Migrated)
	})
	t.Run("delete", func(t *testing.T) {
		f := newMigrationFixture(t)
		idx := legacyIndexKey(uidOf(t, f.alice))
		f.kv.deleteErr[idx] = errors.New("raft: timeout")
		report, err := MigrateLegacyCredentials(context.Background(), f.migration(f.store))
		var move *CredentialMoveError
		require.ErrorAs(t, err, &move)
		assert.Equal(t, idx, move.Key)
		assert.Equal(t, 2, report.Migrated)

		delete(f.kv.deleteErr, idx)
		report, err = MigrateLegacyCredentials(context.Background(), f.migration(f.store))
		require.NoError(t, err)
		assert.Equal(t, 0, report.Migrated)
		assert.False(t, f.kv.has(idx), "a later run removes an index left behind")
	})
}

func TestMigrateLegacyCredentials_ScanFailure(t *testing.T) {
	f := newMigrationFixture(t)
	f.kv.scanErr = errors.New("barrier sealed")

	report, err := MigrateLegacyCredentials(context.Background(), f.migration(f.store))

	var scan *LegacyCredentialScanError
	require.ErrorAs(t, err, &scan)
	assert.Equal(t, "__xkms:webauthn/credentials/", scan.Prefix)
	assert.Equal(t, CredentialMigrationReport{}, report)
}

func TestMigrateLegacyCredentials_ContextCanceled(t *testing.T) {
	f := newMigrationFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	report, err := MigrateLegacyCredentials(ctx, f.migration(f.store))

	assert.ErrorIs(t, err, context.Canceled)
	assert.Equal(t, 0, report.Migrated)
	assert.True(t, f.kv.has(legacyCredKey([]byte("alice-2"))))
}

func TestMigrateLegacyCredentials_InvalidConfig(t *testing.T) {
	f := newMigrationFixture(t)
	valid := f.migration(f.store)
	cases := map[string]func(m *LegacyCredentialMigration){
		"Legacy":   func(m *LegacyCredentialMigration) { m.Legacy = nil },
		"Users":    func(m *LegacyCredentialMigration) { m.Users = nil },
		"TenantID": func(m *LegacyCredentialMigration) { m.TenantID = "" },
		"Store":    func(m *LegacyCredentialMigration) { m.Store = nil },
	}
	for field, mutate := range cases {
		t.Run(field, func(t *testing.T) {
			m := valid
			mutate(&m)
			_, err := MigrateLegacyCredentials(context.Background(), m)
			var cfg *CredentialMigrationConfigError
			require.ErrorAs(t, err, &cfg)
			assert.Equal(t, field, cfg.Field)
		})
	}
}

func TestCredentialMigrationErrors_Messages(t *testing.T) {
	cause := errors.New("boom")
	cases := []struct {
		err  error
		want string
	}{
		{&CredentialMigrationConfigError{Field: "Store"}, "webauthn: credential migration: missing field: Store"},
		{&LegacyCredentialScanError{Prefix: "p/", Err: cause}, "webauthn: credential migration: read legacy keyspace p/: boom"},
		{&LegacyCredentialCorruptError{Key: "k", Err: cause}, "webauthn: credential migration: corrupt legacy record k: boom"},
		{&CredentialOwnerUnresolvedError{Key: "k", Err: cause}, "webauthn: credential migration: owner of k unresolved: boom"},
		{&CredentialMoveError{Key: "k", Op: "save", Err: cause}, "webauthn: credential migration: save k: boom"},
		{&CredentialMigrationIncompleteError{Failures: []error{cause, cause}}, "webauthn: credential migration: 2 legacy records not migrated"},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, tc.err.Error())
	}
	assert.ErrorIs(t, &CredentialMigrationIncompleteError{Failures: []error{cause}}, cause)
}
