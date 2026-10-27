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
	"encoding/json"
	"errors"
	"sort"
	"strconv"
	"strings"

	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
)

// The legacy layout is the shared qrdb KV keyspace the credential store used
// before go-qrdb v0.46 (go-xkms#1428). It has no tenant segment:
//
//	__xkms:webauthn/credentials/<base64url credential ID>  JSON Credential
//	__xkms:webauthn/users/<decimal qrdb user ID>/credentials  JSON []string of credential IDs
//
// The records carry no xkms-level seal: they are plain JSON, protected at
// rest by the qrdb barrier the KV client reads through.
const (
	legacyCredentialPrefix = "__xkms:webauthn/credentials/"
	legacyUserIndexPrefix  = "__xkms:webauthn/users/"
	legacyUserIndexSuffix  = "/credentials"
)

// ErrCredentialOwnerHasNoTenant is the cause of a CredentialOwnerUnresolvedError
// when the credential's user exists but carries no tenant.
var ErrCredentialOwnerHasNoTenant = errors.New("webauthn: credential owner has no tenant")

// LegacyCredentialMigration names the source, the owner lookup and the
// target of MigrateLegacyCredentials. Every field is required.
type LegacyCredentialMigration struct {
	// Legacy is the qrdb KV client holding the shared legacy keyspace.
	Legacy qrdbtransport.KVClient

	// Users resolves a credential's owner, and through it the owner's tenant.
	Users qrdbtransport.UserClient

	// TenantID is the tenant whose store is being opened. Only credentials
	// whose owner belongs to this tenant are moved.
	TenantID string

	// Store is the tenant's credential store, the one NewQRDBUserStoreAdapter
	// returned for TenantID.
	Store CredentialStore
}

// CredentialMigrationReport counts what one MigrateLegacyCredentials run did.
type CredentialMigrationReport struct {
	// Migrated is the number of credentials moved into the tenant store.
	Migrated int

	// Skipped is the number of credentials owned by another tenant, left in
	// the legacy keyspace for that tenant's store open.
	Skipped int

	// Failed is len(Failures).
	Failed int

	// Failures holds one typed error per legacy key left in place:
	// *LegacyCredentialCorruptError, *CredentialOwnerUnresolvedError,
	// *CredentialMoveError or *LegacyCredentialScanError.
	Failures []error
}

func (r *CredentialMigrationReport) fail(err error) {
	r.Failures = append(r.Failures, err)
	r.Failed = len(r.Failures)
}

// MigrateLegacyCredentials moves the WebAuthn credentials of m.TenantID's
// users out of the shared legacy keyspace into m.Store, the tenant's
// credential store. The consumer calls it each time it opens a tenant's
// credential store, before serving a ceremony from it.
//
// Each credential's tenant is its owner's: the user handle is decoded to the
// qrdb user ID and the user's TenantID read through m.Users. A credential of
// another tenant is counted as skipped and left in place. The legacy key is
// deleted only after the credential is saved to m.Store, so a failed save
// keeps it; a credential already in m.Store for the same user (a run
// interrupted between the save and the delete) only has its legacy key
// deleted. A user's legacy credential-ID index is deleted once none of the
// user's legacy credentials remain.
//
// The migration is idempotent: a second run finds nothing of the tenant's
// left and reports zero migrated. A record that cannot be moved is never
// dropped: it stays in the legacy keyspace and is reported in
// CredentialMigrationReport.Failures, and the run then returns a
// *CredentialMigrationIncompleteError alongside the report. A legacy
// keyspace that cannot be read (a sealed barrier, a transport fault) returns
// a *LegacyCredentialScanError and moves nothing.
func MigrateLegacyCredentials(ctx context.Context, m LegacyCredentialMigration) (CredentialMigrationReport, error) {
	var report CredentialMigrationReport
	if err := m.validate(); err != nil {
		return report, err
	}
	if err := ctx.Err(); err != nil {
		return report, WrapError("migrate legacy credentials", err)
	}
	records, err := m.Legacy.Scan(ctx, legacyCredentialPrefix)
	if err != nil {
		return report, &LegacyCredentialScanError{Prefix: legacyCredentialPrefix, Err: err}
	}

	keys := make([]string, 0, len(records))
	for key := range records {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	// remaining holds the owners that still have a legacy credential after
	// this run; their credential-ID index must stay.
	remaining := make(map[uint64]bool)
	for _, key := range keys {
		if err := ctx.Err(); err != nil {
			return report, WrapError("migrate legacy credentials", err)
		}
		owner, moved, err := m.migrateOne(ctx, key, records[key])
		switch {
		case err != nil:
			report.fail(err)
			remaining[owner] = true
		case moved:
			report.Migrated++
		default:
			report.Skipped++
			remaining[owner] = true
		}
	}
	m.deleteOrphanIndexes(ctx, remaining, &report)

	if report.Failed > 0 {
		return report, &CredentialMigrationIncompleteError{Failures: report.Failures}
	}
	return report, nil
}

func (m *LegacyCredentialMigration) validate() error {
	switch {
	case m.Legacy == nil:
		return &CredentialMigrationConfigError{Field: "Legacy"}
	case m.Users == nil:
		return &CredentialMigrationConfigError{Field: "Users"}
	case m.TenantID == "":
		return &CredentialMigrationConfigError{Field: "TenantID"}
	case m.Store == nil:
		return &CredentialMigrationConfigError{Field: "Store"}
	}
	return nil
}

// migrateOne moves the legacy record at key when its owner belongs to
// m.TenantID. It returns the owner's qrdb user ID (zero when undecodable) and
// whether the record moved; moved false with a nil error is a skip.
func (m *LegacyCredentialMigration) migrateOne(ctx context.Context, key string, blob []byte) (uint64, bool, error) {
	cred, err := decodeLegacyCredential(key, blob)
	if err != nil {
		return 0, false, err
	}
	owner, err := UserIDFromHandle(cred.UserID)
	if err != nil {
		return 0, false, &CredentialOwnerUnresolvedError{Key: key, Err: err}
	}
	user, err := m.Users.GetUser(ctx, owner)
	if err != nil {
		return owner, false, &CredentialOwnerUnresolvedError{Key: key, UserID: owner, Err: err}
	}
	if user.TenantID == "" {
		return owner, false, &CredentialOwnerUnresolvedError{Key: key, UserID: owner, Err: ErrCredentialOwnerHasNoTenant}
	}
	if user.TenantID != m.TenantID {
		return owner, false, nil
	}
	if err := m.save(ctx, key, cred); err != nil {
		return owner, false, err
	}
	if err := m.Legacy.Delete(ctx, key); err != nil {
		return owner, false, &CredentialMoveError{Key: key, Op: "delete legacy key", Err: err}
	}
	return owner, true, nil
}

// save stores cred in the tenant store. A credential already there for the
// same user is the result of an interrupted earlier run and counts as saved.
func (m *LegacyCredentialMigration) save(ctx context.Context, key string, cred *Credential) error {
	err := m.Store.Save(ctx, cred)
	if err == nil {
		return nil
	}
	if !errors.Is(err, ErrCredentialAlreadyExists) {
		return &CredentialMoveError{Key: key, Op: "save", Err: err}
	}
	existing, gErr := m.Store.GetByCredentialID(ctx, cred.ID)
	if gErr != nil {
		return &CredentialMoveError{Key: key, Op: "read existing", Err: gErr}
	}
	if !bytes.Equal(existing.UserID, cred.UserID) {
		return &CredentialMoveError{Key: key, Op: "save", Err: ErrCredentialOwnerMismatch}
	}
	return nil
}

// deleteOrphanIndexes deletes every legacy credential-ID index whose user has
// no legacy credential left. The tenant store does not read the index, so
// one left by a failed delete is retried by the next run.
func (m *LegacyCredentialMigration) deleteOrphanIndexes(ctx context.Context, remaining map[uint64]bool, report *CredentialMigrationReport) {
	keys, err := m.Legacy.List(ctx, legacyUserIndexPrefix)
	if err != nil {
		report.fail(&LegacyCredentialScanError{Prefix: legacyUserIndexPrefix, Err: err})
		return
	}
	for _, key := range keys {
		owner, ok := legacyIndexOwner(key)
		if !ok || remaining[owner] {
			continue
		}
		if err := m.Legacy.Delete(ctx, key); err != nil {
			report.fail(&CredentialMoveError{Key: key, Op: "delete legacy index", Err: err})
		}
	}
}

// decodeLegacyCredential decodes a legacy record and checks that it is the
// credential its key names.
func decodeLegacyCredential(key string, blob []byte) (*Credential, error) {
	var cred Credential
	if err := json.Unmarshal(blob, &cred); err != nil {
		return nil, &LegacyCredentialCorruptError{Key: key, Err: err}
	}
	if len(cred.ID) == 0 {
		return nil, &LegacyCredentialCorruptError{Key: key, Err: ErrInvalidCredential}
	}
	if encodeID(cred.ID) != strings.TrimPrefix(key, legacyCredentialPrefix) {
		return nil, &LegacyCredentialCorruptError{Key: key, Err: ErrLegacyCredentialKeyMismatch}
	}
	return &cred, nil
}

// legacyIndexOwner parses the qrdb user ID out of a legacy index key.
func legacyIndexOwner(key string) (uint64, bool) {
	segment, ok := strings.CutPrefix(key, legacyUserIndexPrefix)
	if !ok {
		return 0, false
	}
	segment, ok = strings.CutSuffix(segment, legacyUserIndexSuffix)
	if !ok {
		return 0, false
	}
	id, err := strconv.ParseUint(segment, 10, 64)
	if err != nil {
		return 0, false
	}
	return id, true
}
