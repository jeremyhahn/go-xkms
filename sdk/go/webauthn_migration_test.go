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

package xkms_test

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var errMigrationUserNotFound = errors.New("user not found")

// migrationKV is the shared legacy keyspace. The embedded interface is nil:
// the migrator only scans, lists and deletes.
type migrationKV struct {
	qrdbtransport.KVClient
	data map[string][]byte
}

func (kv *migrationKV) Scan(_ context.Context, prefix string, _ ...qrdbtransport.ReadOption) (map[string][]byte, error) {
	out := make(map[string][]byte)
	for key, value := range kv.data {
		if strings.HasPrefix(key, prefix) {
			out[key] = value
		}
	}
	return out, nil
}

func (kv *migrationKV) List(ctx context.Context, prefix string, opts ...qrdbtransport.ReadOption) ([]string, error) {
	records, err := kv.Scan(ctx, prefix, opts...)
	keys := make([]string, 0, len(records))
	for key := range records {
		keys = append(keys, key)
	}
	return keys, err
}

func (kv *migrationKV) Delete(_ context.Context, key string, _ ...qrdbtransport.WriteOption) error {
	delete(kv.data, key)
	return nil
}

// migrationUsers resolves a credential's owner; the migrator only reads users.
type migrationUsers struct {
	qrdbtransport.UserClient
	byID map[uint64]*qrdbtransport.User
}

func (u *migrationUsers) GetUser(_ context.Context, id uint64) (*qrdbtransport.User, error) {
	user, ok := u.byID[id]
	if !ok {
		return nil, errMigrationUserNotFound
	}
	return user, nil
}

func migrationHandle(userID uint64) []byte {
	return binary.BigEndian.AppendUint64(nil, userID)
}

func putLegacyCredential(t *testing.T, kv *migrationKV, id string, owner uint64) {
	t.Helper()
	blob, err := json.Marshal(xkms.WebAuthnCredential{
		ID:        []byte(id),
		UserID:    migrationHandle(owner),
		PublicKey: []byte("pk-" + id),
	})
	require.NoError(t, err)
	kv.data["__xkms:webauthn/credentials/"+base64.RawURLEncoding.EncodeToString([]byte(id))] = blob
}

// A consumer opening tenant-a's store through the SDK moves tenant-a's
// credentials into it, leaves tenant-b's in place, and a second open moves
// nothing.
func TestMigrateWebAuthnLegacyCredentials_MovesTheTenantsCredentials(t *testing.T) {
	ctx := context.Background()
	kv := &migrationKV{data: make(map[string][]byte)}
	putLegacyCredential(t, kv, "alice-1", 1)
	putLegacyCredential(t, kv, "bob-1", 2)
	users := &migrationUsers{byID: map[uint64]*qrdbtransport.User{
		1: {ID: 1, TenantID: "tenant-a"},
		2: {ID: 2, TenantID: "tenant-b"},
	}}
	memory := qrdbsdk.NewMemoryKVStore()
	_, store, err := xkms.NewWebAuthnQRDBUserStoreAdapter(xkms.WebAuthnQRDBUserStoreOptions{
		Users:      users,
		DAOFactory: qrdbsdk.NewDAOFactory(func(uint64) qrdbsdk.KVStore { return memory }),
		TenantID:   "tenant-a",
	})
	require.NoError(t, err)
	migration := xkms.WebAuthnLegacyCredentialMigration{
		Legacy: kv, Users: users, TenantID: "tenant-a", Store: store,
	}

	report, err := xkms.MigrateWebAuthnLegacyCredentials(ctx, migration)
	require.NoError(t, err)
	assert.Equal(t, xkms.WebAuthnCredentialMigrationReport{Migrated: 1, Skipped: 1}, report)
	got, err := store.GetByCredentialID(ctx, []byte("alice-1"))
	require.NoError(t, err)
	assert.Equal(t, []byte("pk-alice-1"), got.PublicKey)
	assert.Len(t, kv.data, 1, "only tenant-b's credential stays in the legacy keyspace")

	report, err = xkms.MigrateWebAuthnLegacyCredentials(ctx, migration)
	require.NoError(t, err)
	assert.Equal(t, 0, report.Migrated)
}

// An unresolvable record surfaces as the SDK's typed errors and stays put.
func TestMigrateWebAuthnLegacyCredentials_ReportsUnresolvedOwner(t *testing.T) {
	kv := &migrationKV{data: make(map[string][]byte)}
	putLegacyCredential(t, kv, "orphan", 9)
	users := &migrationUsers{byID: map[uint64]*qrdbtransport.User{}}
	memory := qrdbsdk.NewMemoryKVStore()
	_, store, err := xkms.NewWebAuthnQRDBUserStoreAdapter(xkms.WebAuthnQRDBUserStoreOptions{
		Users:      users,
		DAOFactory: qrdbsdk.NewDAOFactory(func(uint64) qrdbsdk.KVStore { return memory }),
		TenantID:   "tenant-a",
	})
	require.NoError(t, err)

	report, err := xkms.MigrateWebAuthnLegacyCredentials(context.Background(), xkms.WebAuthnLegacyCredentialMigration{
		Legacy: kv, Users: users, TenantID: "tenant-a", Store: store,
	})

	var incomplete *xkms.WebAuthnCredentialMigrationIncompleteError
	require.ErrorAs(t, err, &incomplete)
	var unresolved *xkms.WebAuthnCredentialOwnerUnresolvedError
	require.ErrorAs(t, err, &unresolved)
	assert.Equal(t, uint64(9), unresolved.UserID)
	assert.ErrorIs(t, err, errMigrationUserNotFound)
	assert.Equal(t, 1, report.Failed)
	assert.Len(t, kv.data, 1, "an unresolved record is never dropped")
}

func TestMigrateWebAuthnLegacyCredentials_MissingField(t *testing.T) {
	_, err := xkms.MigrateWebAuthnLegacyCredentials(context.Background(), xkms.WebAuthnLegacyCredentialMigration{})
	var cfg *xkms.WebAuthnCredentialMigrationConfigError
	require.ErrorAs(t, err, &cfg)
	assert.Equal(t, "Legacy", cfg.Field)
}
