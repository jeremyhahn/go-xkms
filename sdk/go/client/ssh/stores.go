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

package ssh

import (
	"context"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	pkgauthorized "github.com/jeremyhahn/go-xkms/pkg/ssh/authorized"
	pkgkeys "github.com/jeremyhahn/go-xkms/pkg/ssh/keys"
	pkgknownhosts "github.com/jeremyhahn/go-xkms/pkg/ssh/known_hosts"
	"github.com/jeremyhahn/go-xkms/pkg/ssh/migrate"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// Stores holds the persistent stores an embedded Client works over: SSH
// keys, host-key pins and authorized_keys entries, each kept as go-qrdb
// DAO entities.
type Stores struct {
	Keys       *pkgkeys.DAOStore
	KnownHosts *pkgknownhosts.DAOStore
	Authorized *pkgauthorized.DAOStore
}

// NewStores builds the platform-partition Stores over the DAOs daos builds.
func NewStores(daos *qrdbsdk.DAOFactory) (*Stores, error) {
	if daos == nil {
		return nil, &NilInputError{Field: "daos"}
	}
	keys, err := pkgkeys.NewDAOStore(daos)
	if err != nil {
		return nil, err
	}
	hosts, err := pkgknownhosts.NewDAOStore(daos)
	if err != nil {
		return nil, err
	}
	authorized, err := pkgauthorized.NewDAOStore(daos)
	if err != nil {
		return nil, err
	}
	return &Stores{Keys: keys, KnownHosts: hosts, Authorized: authorized}, nil
}

// MigrateReport counts what MigrateLegacyStores did: records migrated,
// records skipped on purpose and records that failed and stayed in place.
type MigrateReport = migrate.Report

// MigrateRecordError reports one old record that failed to migrate and was
// left in the old store.
type MigrateRecordError = migrate.RecordError

// MigrateRecordsFailedError collects every *MigrateRecordError of one
// MigrateLegacyStores call; errors.As reaches each of them.
type MigrateRecordsFailedError = migrate.RecordsFailedError

// ErrMigratePartitionedSource reports a legacy backend that is a
// tenant-scoped storage.PrefixBackend view, which MigrateLegacyStores
// refuses.
var ErrMigratePartitionedSource = migrate.ErrPartitionedSource

// MigrateLegacyStores moves the SSH records the pre-DAO stores kept in the
// sealed-KV backend legacy into the DAO catalogs of daos: keys, known_hosts,
// authorized_keys, sessions and profiles. The consumer calls it at store
// open, with the backend the old stores used and before NewStores or the
// session and profile stores serve requests.
//
// legacy must be the unpartitioned backend, whose keys keep each tenant's
// "{tenant}/" prefix. A tenant-scoped *storage.PrefixBackend (the view the
// old tenancy client wrote through) lists keys without that prefix, so it
// is refused with ErrMigratePartitionedSource before anything moves.
//
// Each record is imported first and its old key deleted only after the
// import succeeds. The call is idempotent: once everything has moved, a
// second call migrates nothing and reports zero. A record that fails stays
// in legacy and is reported in a *MigrateRecordsFailedError beside the
// counts, so a later call retries it. Sessions and profiles under a tenant
// prefix are skipped and left in place, because their catalogs have no
// tenant partition.
func MigrateLegacyStores(ctx context.Context, legacy storage.Backend, daos *qrdbsdk.DAOFactory) (MigrateReport, error) {
	return migrate.Run(ctx, legacy, daos)
}

// Partition returns the view of s through tenantID's partition ("" is the
// platform partition). The views share s's DAOs.
func (s *Stores) Partition(tenantID string) (*Stores, error) {
	keys, err := s.Keys.Partition(tenantID)
	if err != nil {
		return nil, err
	}
	hosts, err := s.KnownHosts.Partition(tenantID)
	if err != nil {
		return nil, err
	}
	authorized, err := s.Authorized.Partition(tenantID)
	if err != nil {
		return nil, err
	}
	return &Stores{Keys: keys, KnownHosts: hosts, Authorized: authorized}, nil
}
