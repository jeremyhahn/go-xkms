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

package staticpw

import (
	"context"
	"encoding/json"
	"regexp"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/errs"
	"github.com/jeremyhahn/go-xkms/pkg/scope"
)

const defaultKeyPrefix = Feature + "/"

// Feature is the password manager's feature segment in the xkms keyspace
// (pkg/scope): shared entries live under "{tenant}/staticpw/shared/" and a
// user's personal entries under "{tenant}/staticpw/users/{subject}/".
const Feature = "staticpw"

// maxTenantIDLength is the maximum allowed length for a tenant identifier.
const maxTenantIDLength = 64

// maxUserIDLength is the maximum allowed length for a user identifier.
const maxUserIDLength = 128

// tenantIDPattern matches alphanumeric characters, hyphens, and underscores.
var tenantIDPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]*$`)

// userIDPattern matches alphanumeric characters, hyphens, underscores, dots,
// and the @ sign (for email-style user IDs).
var userIDPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.@-]*$`)

// Store defines the interface for static password persistence.
type Store interface {
	// Add stores a new static password entry.
	Add(pw *StaticPassword) error

	// Get retrieves a static password by ID or name (case-insensitive).
	Get(idOrName string) (*StaticPassword, error)

	// List returns all stored static passwords sorted by name.
	List() ([]*StaticPassword, error)

	// Update modifies an existing static password entry.
	Update(pw *StaticPassword) error

	// Delete removes a static password by ID or name (case-insensitive).
	// Returns ErrPasswordReadOnly for read-only entries.
	Delete(idOrName string) error

	// ForceDelete removes a static password by ID or name, bypassing the
	// read-only check. Used for administrative cleanup operations.
	ForceDelete(idOrName string) error

	// ListByFolder returns all entries within the given folder path and its
	// subfolders. An empty folderPath returns all entries.
	ListByFolder(folderPath string) ([]*StaticPassword, error)

	// ListByFolderDirect returns only entries directly in the specified folder,
	// excluding entries in subfolders. An empty folderPath returns root-level entries.
	ListByFolderDirect(folderPath string) ([]*StaticPassword, error)

	// ListFolders returns all unique folder paths sorted alphabetically,
	// including parent paths derived from nested folders.
	ListFolders() ([]string, error)

	// MoveToFolder moves an entry to a new folder, regenerating its ID.
	MoveToFolder(idOrName string, folderPath string) error

	// CreateFolder persists an empty folder marker so the folder survives
	// across restarts even without entries.
	CreateFolder(path string) error

	// RemoveFolder removes a persisted folder marker. Does not affect
	// entries within the folder.
	RemoveFolder(path string) error

	// Close releases resources held by the store.
	Close() error
}

// DAOStore implements Store over the go-qrdb password record table. Its
// records -- entries, folder markers and aliases -- are filed under the
// store's prefix, so the system store, a tenant's shared store and each
// user's personal store share one table without seeing each other.
//
// Every write is a guarded go-qrdb DAO write: a create never overwrites, and
// an update or delete applies only to the record it read, so concurrent
// writers never lose each other's changes silently.
type DAOStore struct {
	records  *records
	tenantID string
	prefix   string
	names    entryNames
	sealer   sealer
	closed   atomic.Bool
}

// NewStore returns the platform's password store (no tenant) over the
// staticpw database of daos.
func NewStore(daos *qrdbsdk.DAOFactory) (*DAOStore, error) {
	t, err := openRecords(daos)
	if err != nil {
		return nil, err
	}
	return &DAOStore{records: t, prefix: defaultKeyPrefix}, nil
}

// NewTenantStore returns tenantID's password store, filed under the
// tenant's feature root "{tenantID}/staticpw/" (scope.Root). The tenantID
// must be non-empty, at most 64 characters, start with an alphanumeric
// character, and contain only alphanumeric characters, hyphens, and
// underscores.
func NewTenantStore(daos *qrdbsdk.DAOFactory, tenantID string) (*DAOStore, error) {
	if !isValidTenantID(tenantID) {
		return nil, ErrInvalidTenantID
	}
	root, err := scope.Root(tenantID, Feature)
	if err != nil {
		return nil, &errs.Detail{Err: ErrInvalidTenantID, Detail: err.Error()}
	}
	return newTenantStore(daos, tenantID, root)
}

// NewSharedTenantStore returns the store of tenantID's shared passwords,
// filed under "{tenantID}/staticpw/shared/" (scope.SharedPrefix).
func NewSharedTenantStore(daos *qrdbsdk.DAOFactory, tenantID string) (*DAOStore, error) {
	if !isValidTenantID(tenantID) {
		return nil, ErrInvalidTenantID
	}
	prefix, err := scope.SharedPrefix(tenantID, Feature)
	if err != nil {
		return nil, &errs.Detail{Err: ErrInvalidTenantID, Detail: err.Error()}
	}
	return newTenantStore(daos, tenantID, prefix)
}

// NewPersonalTenantStore returns the store of userID's personal passwords
// in tenantID, filed under "{tenantID}/staticpw/users/{userID}/"
// (scope.PersonalPrefix). It neither names nor seals its records with a
// user key: the TenantPasswordStoreManager serves a user's vault-sealed
// personal store.
func NewPersonalTenantStore(daos *qrdbsdk.DAOFactory, tenantID, userID string) (*DAOStore, error) {
	if !isValidTenantID(tenantID) {
		return nil, ErrInvalidTenantID
	}
	if !isValidUserID(userID) {
		return nil, ErrInvalidUserID
	}
	prefix, err := scope.PersonalPrefix(tenantID, Feature, userID)
	if err != nil {
		return nil, &errs.Detail{Err: ErrInvalidUserID, Detail: err.Error()}
	}
	return newTenantStore(daos, tenantID, prefix)
}

// newSealedPersonalStore returns userID's personal store in tenantID with
// every record named and sealed with keys of session's DEK. The store reads
// and writes nothing once the session ends.
func newSealedPersonalStore(daos *qrdbsdk.DAOFactory, tenantID, userID string, session *userSession) (*DAOStore, error) {
	s, err := NewPersonalTenantStore(daos, tenantID, userID)
	if err != nil {
		return nil, err
	}
	s.names = session.names
	s.sealer = sealer{session: session}
	return s, nil
}

// newTenantStore returns tenantID's store filed under prefix.
func newTenantStore(daos *qrdbsdk.DAOFactory, tenantID, prefix string) (*DAOStore, error) {
	t, err := openRecords(daos)
	if err != nil {
		return nil, err
	}
	return &DAOStore{records: t, tenantID: tenantID, prefix: prefix}, nil
}

// TenantID returns the tenant identifier for this store, or an empty string
// for the platform's store.
func (s *DAOStore) TenantID() string {
	return s.tenantID
}

// Add stores a new static password entry. It validates the password and
// derives the entry's ID from its name and folder path; names are
// case-insensitive, so an entry of the same name in the same folder is
// ErrPasswordExists.
func (s *DAOStore) Add(pw *StaticPassword) error {
	if s.closed.Load() {
		return ErrStoreClosed
	}
	if err := pw.Validate(); err != nil {
		return err
	}

	pw.ID = s.names.entryID(pw.Name, pw.FolderPath)
	now := time.Now()
	pw.CreatedAt = now
	pw.UpdatedAt = now

	next, err := s.entryRecord(pw)
	if err != nil {
		return err
	}
	stored, err := s.records.create(context.Background(), next)
	if err != nil {
		return err
	}
	if !stored {
		return ErrPasswordExists
	}
	return nil
}

// Get retrieves a static password by ID or name. It first looks idOrName up
// as an ID, then as the name of a root-level entry, and finally scans for a
// case-insensitive name match in any folder.
func (s *DAOStore) Get(idOrName string) (*StaticPassword, error) {
	if s.closed.Load() {
		return nil, ErrStoreClosed
	}
	_, pw, err := s.find(context.Background(), idOrName)
	return pw, err
}

// List returns all stored static passwords sorted by name (case-insensitive).
func (s *DAOStore) List() ([]*StaticPassword, error) {
	if s.closed.Load() {
		return nil, ErrStoreClosed
	}
	_, passwords, err := s.entries(context.Background())
	if err != nil {
		return nil, err
	}
	sort.Slice(passwords, func(i, j int) bool {
		return strings.ToLower(passwords[i].Name) < strings.ToLower(passwords[j].Name)
	})
	return passwords, nil
}

// Update modifies an existing static password entry. The entry must already
// exist by its ID. The UpdatedAt timestamp is refreshed automatically.
// Read-only entries cannot be updated. If the name or folder changes, the
// entry moves to its new ID; ErrPasswordExists reports that ID taken.
func (s *DAOStore) Update(pw *StaticPassword) error {
	if s.closed.Load() {
		return ErrStoreClosed
	}
	if err := pw.Validate(); err != nil {
		return err
	}

	ctx := context.Background()
	oldPath := s.entryPath(pw.ID)
	for range maxAttempts {
		current, err := s.records.load(ctx, oldPath)
		if err != nil {
			return err
		}
		if current == nil {
			return ErrPasswordNotFound
		}
		existing, err := s.decodeEntry(current)
		if err != nil {
			return err
		}
		if existing.ReadOnly {
			return ErrPasswordReadOnly
		}

		updated := *pw
		updated.CreatedAt = existing.CreatedAt
		updated.UpdatedAt = time.Now()
		updated.ID = s.names.entryID(pw.Name, pw.FolderPath)
		next, err := s.entryRecord(&updated)
		if err != nil {
			return err
		}

		if next.Path != current.Path {
			if err := s.records.rename(ctx, current, next); err != nil {
				return err
			}
			*pw = updated
			return nil
		}
		swapped, err := s.records.swap(ctx, current, next)
		if err != nil {
			return err
		}
		if swapped {
			*pw = updated
			return nil
		}
	}
	return &ConflictError{Op: "update", Key: oldPath}
}

// Delete removes a static password by ID or name, looked up as Get does.
// Read-only entries cannot be deleted.
func (s *DAOStore) Delete(idOrName string) error {
	return s.delete(idOrName, false)
}

// ForceDelete removes a static password by ID or name, bypassing the
// read-only check. Used for administrative cleanup operations.
func (s *DAOStore) ForceDelete(idOrName string) error {
	return s.delete(idOrName, true)
}

// delete removes the entry idOrName names, refusing a read-only entry
// unless force is set.
func (s *DAOStore) delete(idOrName string, force bool) error {
	if s.closed.Load() {
		return ErrStoreClosed
	}
	ctx := context.Background()
	for range maxAttempts {
		current, pw, err := s.find(ctx, idOrName)
		if err != nil {
			return err
		}
		if pw.ReadOnly && !force {
			return ErrPasswordReadOnly
		}
		deleted, err := s.records.removeIfMatch(ctx, current)
		if err != nil || deleted {
			return err
		}
	}
	return &ConflictError{Op: "delete", Key: idOrName}
}

// ListByFolder returns all entries within the given folder path and its subfolders.
// This supports hierarchical folder navigation: querying "Work" returns passwords
// in "Work", "Work/Email", "Work/Email/Personal", etc.
// An empty folderPath returns all entries (root includes everything).
func (s *DAOStore) ListByFolder(folderPath string) ([]*StaticPassword, error) {
	all, err := s.List()
	if err != nil {
		return nil, err
	}

	result := make([]*StaticPassword, 0)
	for _, pw := range all {
		if folderPath == "" || pw.FolderPath == folderPath || strings.HasPrefix(pw.FolderPath, folderPath+"/") {
			result = append(result, pw)
		}
	}
	return result, nil
}

// ListByFolderDirect returns entries that are directly in the specified folder,
// excluding entries in subfolders. This is useful for displaying only immediate
// children of a folder without nested content.
// An empty folderPath returns only root-level entries (entries with no folder).
func (s *DAOStore) ListByFolderDirect(folderPath string) ([]*StaticPassword, error) {
	all, err := s.List()
	if err != nil {
		return nil, err
	}

	result := make([]*StaticPassword, 0)
	for _, pw := range all {
		if pw.FolderPath == folderPath {
			result = append(result, pw)
		}
	}
	return result, nil
}

// ListFolders returns all unique folder paths sorted alphabetically.
// Parent paths are derived from nested folders (e.g. "Work/Email" also
// yields "Work"). Persisted folder markers are merged with implicit
// folders derived from entry FolderPath fields.
func (s *DAOStore) ListFolders() ([]string, error) {
	all, err := s.List()
	if err != nil {
		return nil, err
	}

	unique := make(map[string]struct{})
	for _, pw := range all {
		if pw.FolderPath == "" {
			continue
		}
		// Add the full path and all parent segments.
		parts := strings.Split(pw.FolderPath, "/")
		for i := range parts {
			unique[strings.Join(parts[:i+1], "/")] = struct{}{}
		}
	}

	markers, err := s.records.list(context.Background(), s.dir(nameKindFolder))
	if err != nil {
		return nil, err
	}
	for _, marker := range markers {
		folder, err := s.sealer.open(marker.Path, marker.Body)
		if err != nil {
			return nil, err
		}
		unique[string(folder)] = struct{}{}
	}

	folders := make([]string, 0, len(unique))
	for f := range unique {
		folders = append(folders, f)
	}
	sort.Strings(folders)
	return folders, nil
}

// MoveToFolder moves an entry to a new folder, regenerating its ID.
// Read-only entries cannot be moved; ErrPasswordExists reports an entry of
// the same name in the destination.
func (s *DAOStore) MoveToFolder(idOrName string, folderPath string) error {
	if s.closed.Load() {
		return ErrStoreClosed
	}

	ctx := context.Background()
	current, pw, err := s.find(ctx, idOrName)
	if err != nil {
		return err
	}
	if pw.ReadOnly {
		return ErrPasswordReadOnly
	}
	if pw.FolderPath == folderPath {
		return ErrMoveToSameFolder
	}

	pw.FolderPath = folderPath
	pw.ID = s.names.entryID(pw.Name, pw.FolderPath)
	pw.UpdatedAt = time.Now()
	next, err := s.entryRecord(pw)
	if err != nil {
		return err
	}
	return s.records.rename(ctx, current, next)
}

// CreateFolder persists an empty folder marker so the folder survives
// across restarts even without entries. Creating an existing folder is not
// an error.
func (s *DAOStore) CreateFolder(path string) error {
	if s.closed.Load() {
		return ErrStoreClosed
	}
	if path == "" {
		return ErrFolderEmpty
	}
	marker, err := s.markerRecord(nameKindFolder, path, path)
	if err != nil {
		return err
	}
	_, err = s.records.create(context.Background(), marker)
	return err
}

// RemoveFolder removes a persisted folder marker. Does not affect
// entries within the folder. The operation is idempotent; removing a
// non-existent folder is not an error.
func (s *DAOStore) RemoveFolder(path string) error {
	if s.closed.Load() {
		return ErrStoreClosed
	}
	if path == "" {
		return ErrFolderEmpty
	}
	_, err := s.records.remove(context.Background(), s.markerPath(nameKindFolder, path))
	return err
}

// SetAlias persists a name -> folder-path mapping so a caller-defined alias
// (e.g. a freedesktop Secret Service collection alias) can point at an
// arbitrary folder and survive restarts. An empty folderPath removes the
// alias instead of storing one, matching the Secret Service SetAlias
// contract where unsetting an alias is a valid call.
//
// This is not part of the Store interface: it is a capability of DAOStore,
// probed via a local interface assertion by callers that need it (see
// xkey/pkg/secretservice), so the composite ScopedStore is not forced to
// carry alias bookkeeping it has no caller for.
func (s *DAOStore) SetAlias(name string, folderPath string) error {
	if s.closed.Load() {
		return ErrStoreClosed
	}
	if name == "" {
		return ErrAliasNameEmpty
	}
	ctx := context.Background()
	if folderPath == "" {
		_, err := s.records.remove(ctx, s.markerPath(nameKindAlias, name))
		return err
	}
	alias, err := s.markerRecord(nameKindAlias, name, folderPath)
	if err != nil {
		return err
	}
	return s.records.put(ctx, alias)
}

// GetAlias returns the folder path persisted for name, and false if no
// alias with that name has been set.
func (s *DAOStore) GetAlias(name string) (string, bool, error) {
	if s.closed.Load() {
		return "", false, ErrStoreClosed
	}
	if name == "" {
		return "", false, ErrAliasNameEmpty
	}
	alias, err := s.records.load(context.Background(), s.markerPath(nameKindAlias, name))
	if err != nil || alias == nil {
		return "", false, err
	}
	folderPath, err := s.sealer.open(alias.Path, alias.Body)
	if err != nil {
		return "", false, err
	}
	return string(folderPath), true, nil
}

// Close marks the store as closed. The DAO factory belongs to the
// composition root that injected it, so nothing else is released.
func (s *DAOStore) Close() error {
	s.closed.Store(true)
	return nil
}

// dir returns the directory the store files records of kind under.
func (s *DAOStore) dir(kind string) string {
	return s.prefix + kind + "/"
}

// entryPath returns the path of the entry with the given ID.
func (s *DAOStore) entryPath(id string) string {
	return s.dir(nameKindEntry) + id
}

// markerPath returns the path of the marker of kind named name.
func (s *DAOStore) markerPath(kind, name string) string {
	return s.dir(kind) + s.names.segment(kind, name)
}

// entryRecord returns the record storing pw at its ID.
func (s *DAOStore) entryRecord(pw *StaticPassword) (*record, error) {
	data, err := json.Marshal(pw) // #nosec G117 -- staticpw IS the password store; Password is the stored secret, persisted to the encrypted backend
	if err != nil {
		return nil, &errs.Detail{Err: ErrMarshalFailed, Detail: err.Error()}
	}
	return s.newRecord(nameKindEntry, s.entryPath(pw.ID), data)
}

// markerRecord returns the record of the marker of kind named name,
// storing value.
func (s *DAOStore) markerRecord(kind, name, value string) (*record, error) {
	return s.newRecord(kind, s.markerPath(kind, name), []byte(value))
}

// newRecord returns the record of kind at path holding body, sealed for
// the store.
func (s *DAOStore) newRecord(kind, path string, body []byte) (*record, error) {
	sealed, err := s.sealer.seal(path, body)
	if err != nil {
		return nil, err
	}
	return &record{Path: path, Dir: s.dir(kind), Body: sealed}, nil
}

// decodeEntry returns the password r stores.
func (s *DAOStore) decodeEntry(r *record) (*StaticPassword, error) {
	data, err := s.sealer.open(r.Path, r.Body)
	if err != nil {
		return nil, err
	}
	return unmarshalPassword(data)
}

// entries returns every entry record of the store with the password each
// holds, in the same order.
func (s *DAOStore) entries(ctx context.Context) ([]*record, []*StaticPassword, error) {
	all, err := s.records.list(ctx, s.dir(nameKindEntry))
	if err != nil {
		return nil, nil, err
	}
	passwords := make([]*StaticPassword, 0, len(all))
	for _, r := range all {
		pw, err := s.decodeEntry(r)
		if err != nil {
			return nil, nil, err
		}
		passwords = append(passwords, pw)
	}
	return all, passwords, nil
}

// find returns the entry idOrName names and the password it holds.
//
// Lookup order:
//  1. idOrName as an entry ID.
//  2. idOrName as the name of a root-level entry.
//  3. A case-insensitive name match among all entries.
func (s *DAOStore) find(ctx context.Context, idOrName string) (*record, *StaticPassword, error) {
	ids := []string{idOrName}
	if hashed := s.names.entryID(idOrName, ""); hashed != idOrName {
		ids = append(ids, hashed)
	}
	for _, id := range ids {
		r, err := s.records.load(ctx, s.entryPath(id))
		if err != nil {
			return nil, nil, err
		}
		if r != nil {
			pw, err := s.decodeEntry(r)
			return r, pw, err
		}
	}

	all, passwords, err := s.entries(ctx)
	if err != nil {
		return nil, nil, err
	}
	for i, pw := range passwords {
		if strings.EqualFold(pw.Name, idOrName) {
			return all[i], pw, nil
		}
	}
	return nil, nil, ErrPasswordNotFound
}

// unmarshalPassword deserializes a StaticPassword from JSON bytes.
func unmarshalPassword(data []byte) (*StaticPassword, error) {
	var pw StaticPassword
	if err := json.Unmarshal(data, &pw); err != nil {
		return nil, &errs.Detail{Err: ErrUnmarshalFailed, Detail: err.Error()}
	}
	return &pw, nil
}

// isValidTenantID checks that a tenant ID is non-empty, at most 64 characters,
// starts with an alphanumeric character, and contains only alphanumeric
// characters, hyphens, and underscores.
func isValidTenantID(tenantID string) bool {
	if tenantID == "" {
		return false
	}
	if len(tenantID) > maxTenantIDLength {
		return false
	}
	return tenantIDPattern.MatchString(tenantID)
}

// isValidUserID checks that a user ID is non-empty, at most 128 characters,
// starts with an alphanumeric character, and contains only alphanumeric
// characters, hyphens, underscores, dots, and @ signs.
func isValidUserID(userID string) bool {
	if userID == "" {
		return false
	}
	if len(userID) > maxUserIDLength {
		return false
	}
	return userIDPattern.MatchString(userID)
}
