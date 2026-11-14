// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

// Package migrate moves the SSH stores' records from the pre-DAO sealed-KV
// layout into the DAO catalogs.
//
// The old stores kept JSON values in a storage.Backend, sealed by the
// caller's sealed backend, under these keys, where the optional "{tenant}/"
// prefix is the tenant partition:
//
//	[{tenant}/]ssh/{shared|users/<o>|services/<o>}/keys/<name>
//	[{tenant}/]ssh/{shared|users/<o>|services/<o>}/known_hosts/<host>
//	[{tenant}/]ssh/{shared|users/<o>|services/<o>}/authorized_keys/<name>
//	ssh/sessions/<id>
//	ssh/profiles/<id>.json
//	ssh/profiles/__folders__/<path>
//
// Run imports each record through the owning store's ImportLegacy and
// deletes the old key only after the import succeeds, so a failed record
// stays where it was and a later run retries it.
package migrate

import (
	"context"
	"errors"
	"strings"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/ssh/authorized"
	"github.com/jeremyhahn/go-xkms/pkg/ssh/keys"
	"github.com/jeremyhahn/go-xkms/pkg/ssh/known_hosts"
	"github.com/jeremyhahn/go-xkms/pkg/ssh/profile"
	"github.com/jeremyhahn/go-xkms/pkg/ssh/scope"
	"github.com/jeremyhahn/go-xkms/pkg/ssh/sessions"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
)

const (
	sshPrefix      = "ssh/"
	sessionsPrefix = "ssh/sessions/"
	profilesPrefix = "ssh/profiles/"
	foldersPrefix  = "ssh/profiles/__folders__/"
	profileSuffix  = ".json"
)

// ErrPartitionedSource reports a legacy backend that is a tenant-scoped
// storage.PrefixBackend view. Its keys come back without the tenant prefix,
// so Run would move that tenant's records into the system tenant.
var ErrPartitionedSource = errors.New("ssh/migrate: legacy backend is a tenant-prefixed view; pass the unpartitioned backend")

// Report counts what one Run did with the old store's SSH records. Keys
// outside the SSH layout are not counted.
type Report struct {
	// Migrated records were imported and their old keys deleted.
	Migrated int
	// Skipped records were left in place on purpose: tenant-prefixed
	// sessions and profiles, whose catalogs have no tenant partition, and
	// keys under ssh/ that match no store's layout.
	Skipped int
	// Failed records were left in place because reading, importing or
	// deleting them failed; the returned *RecordsFailedError lists them.
	Failed int
}

// importFunc imports one old record. tenant is the old key's tenant prefix
// without the slash ("" for none) and rel the key below it.
type importFunc func(ctx context.Context, tenant, rel string, data []byte) error

// legacyImporter is a store that imports old records by their key below
// the tenant root.
type legacyImporter interface {
	ImportLegacy(ctx context.Context, rel string, data []byte) error
}

// migrator holds the DAO stores one Run imports into.
type migrator struct {
	scoped   map[scope.Kind]importFunc
	sessions *sessions.DAOStore
	profiles *profile.DAOStore
}

// Run moves every SSH record in legacy into the DAO catalogs of daos and
// reports the counts. It is idempotent: a second run over the same stores
// finds nothing left to migrate and reports zero. A record that fails is
// left in legacy and reported in a *RecordsFailedError beside the counts;
// the other records still migrate. Run stops early, returning ctx's error,
// when ctx is done.
//
// legacy must be the unpartitioned backend the old stores wrote through,
// with every tenant's "{tenant}/" prefix in its keys. A tenant-scoped
// *storage.PrefixBackend is refused with ErrPartitionedSource before
// anything is listed.
func Run(ctx context.Context, legacy storage.Backend, daos *qrdbsdk.DAOFactory) (Report, error) {
	if legacy == nil {
		return Report{}, &NilInputError{Field: "legacy"}
	}
	if _, ok := legacy.(*storage.PrefixBackend); ok {
		return Report{}, ErrPartitionedSource
	}
	if daos == nil {
		return Report{}, &NilInputError{Field: "daos"}
	}
	m, err := open(daos)
	if err != nil {
		return Report{}, err
	}
	all, err := legacy.List(ctx, "")
	if err != nil {
		return Report{}, &ListError{Err: err}
	}

	var report Report
	var failed []error
	for _, key := range all {
		if err := ctx.Err(); err != nil {
			return report, err
		}
		tenant, rel, ok := split(key)
		if !ok {
			continue
		}
		imp := m.importer(tenant, rel)
		if imp == nil {
			report.Skipped++
			continue
		}
		if err := migrateRecord(ctx, legacy, key, tenant, rel, imp); err != nil {
			report.Failed++
			failed = append(failed, err)
			continue
		}
		report.Migrated++
	}
	if len(failed) > 0 {
		return report, &RecordsFailedError{Errs: failed}
	}
	return report, nil
}

// open builds the five DAO stores.
func open(daos *qrdbsdk.DAOFactory) (*migrator, error) {
	keyStore, err := keys.NewDAOStore(daos)
	if err != nil {
		return nil, &OpenError{Store: "keys", Err: err}
	}
	pinStore, err := known_hosts.NewDAOStore(daos)
	if err != nil {
		return nil, &OpenError{Store: "known_hosts", Err: err}
	}
	entryStore, err := authorized.NewDAOStore(daos)
	if err != nil {
		return nil, &OpenError{Store: "authorized_keys", Err: err}
	}
	sessionStore, err := sessions.NewStore(daos)
	if err != nil {
		return nil, &OpenError{Store: "sessions", Err: err}
	}
	profileStore, err := profile.NewStore(daos)
	if err != nil {
		return nil, &OpenError{Store: "profiles", Err: err}
	}
	return &migrator{
		scoped: map[scope.Kind]importFunc{
			scope.KindKeys:           partitioned(keyStore.Partition),
			scope.KindKnownHosts:     partitioned(pinStore.Partition),
			scope.KindAuthorizedKeys: partitioned(entryStore.Partition),
		},
		sessions: sessionStore,
		profiles: profileStore,
	}, nil
}

// partitioned imports through the tenant's partition of a scoped store.
func partitioned[S legacyImporter](partition func(tenantID string) (S, error)) importFunc {
	return func(ctx context.Context, tenant, rel string, data []byte) error {
		store, err := partition(tenant)
		if err != nil {
			return err
		}
		return store.ImportLegacy(ctx, rel, data)
	}
}

// importer returns the import step for the record at rel under tenant, or
// nil when the record is skipped.
func (m *migrator) importer(tenant, rel string) importFunc {
	switch {
	case strings.HasPrefix(rel, sessionsPrefix):
		if tenant != "" {
			return nil
		}
		return m.importSession
	case strings.HasPrefix(rel, foldersPrefix):
		if tenant != "" {
			return nil
		}
		return m.importFolder
	case strings.HasPrefix(rel, profilesPrefix):
		if tenant != "" || !strings.HasSuffix(rel, profileSuffix) {
			return nil
		}
		return m.importProfile
	}
	segments := strings.Split(rel, "/")
	if len(segments) < 4 {
		return nil
	}
	return m.scoped[scope.Kind(segments[len(segments)-2])]
}

func (m *migrator) importSession(ctx context.Context, _, rel string, data []byte) error {
	return m.sessions.ImportLegacy(ctx, strings.TrimPrefix(rel, sessionsPrefix), data)
}

func (m *migrator) importProfile(ctx context.Context, _, rel string, data []byte) error {
	id := strings.TrimSuffix(strings.TrimPrefix(rel, profilesPrefix), profileSuffix)
	return m.profiles.ImportLegacy(ctx, id, data)
}

// importFolder records the folder a marker names; the marker's value is an
// empty JSON object and carries nothing.
func (m *migrator) importFolder(ctx context.Context, _, rel string, _ []byte) error {
	return m.profiles.ImportLegacyFolder(ctx, strings.TrimPrefix(rel, foldersPrefix))
}

// split separates an old key into its tenant prefix and the SSH key below
// it. ok is false for keys outside the SSH layout.
func split(key string) (tenant, rel string, ok bool) {
	// The tenant form comes first: tenant ID "ssh" is valid, and the
	// unprefixed layout has no "ssh/ssh/" branch to confuse it with.
	tenant, rel, found := strings.Cut(key, "/")
	if found && tenant != "" && strings.HasPrefix(rel, sshPrefix) {
		return tenant, rel, true
	}
	if strings.HasPrefix(key, sshPrefix) {
		return "", key, true
	}
	return "", "", false
}

// migrateRecord reads the record at key, imports it and deletes the old key
// only after the import succeeds. The read value, which may hold private key
// material, is wiped once imported.
func migrateRecord(ctx context.Context, legacy storage.Backend, key, tenant, rel string, imp importFunc) error {
	data, err := legacy.Get(ctx, key)
	if err != nil {
		return &RecordError{Path: key, Op: "read", Err: err}
	}
	err = imp(ctx, tenant, rel, data)
	secure.Wipe(data)
	if err != nil {
		return &RecordError{Path: key, Op: "import", Err: err}
	}
	if err := legacy.Delete(ctx, key); err != nil {
		return &RecordError{Path: key, Op: "delete", Err: err}
	}
	return nil
}
