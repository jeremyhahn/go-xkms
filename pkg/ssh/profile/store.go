// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
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

package profile

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/dao"
	"github.com/jeremyhahn/go-xkms/pkg/errs"
	"github.com/jeremyhahn/go-xkms/pkg/ssh/records"
)

const (
	// profileEntityType is the go-qrdb entity type of a profile record.
	profileEntityType = "ssh_profiles"

	// folderEntityType is the go-qrdb entity type of an explicit folder,
	// which keeps a folder alive while it holds no profile.
	folderEntityType = "ssh_profile_folders"
)

// Store is the persistence interface for SSH connection profiles. It mirrors
// the static-password store's folder semantics (flat slash-delimited paths plus
// explicit folder markers). Implementations MUST be safe for concurrent use.
type Store interface {
	Add(p *Profile) error
	Get(idOrName string) (*Profile, error)
	List() ([]*Profile, error)
	Update(p *Profile) error
	Delete(idOrName string) error

	// ListByFolder returns entries in folderPath and all subfolders (empty ⇒ all).
	ListByFolder(folderPath string) ([]*Profile, error)
	// ListByFolderDirect returns entries directly in folderPath (no subfolders).
	ListByFolderDirect(folderPath string) ([]*Profile, error)
	// ListFolders returns every unique folder path (derived + persisted), sorted.
	ListFolders() ([]string, error)
	// MoveToFolder moves an entry to folderPath, regenerating its ID.
	MoveToFolder(idOrName, folderPath string) error
	// CreateFolder / RemoveFolder manage empty folder markers.
	CreateFolder(path string) error
	RemoveFolder(path string) error
	// RenameFolder renames a folder and every entry/marker beneath it.
	RenameFolder(oldPath, newPath string) error
	// DeleteFolder removes a folder, its markers, and all entries within it.
	DeleteFolder(path string) error
	// Search returns entries whose name/host/user/folder contains query.
	Search(query string) ([]*Profile, error)

	Close() error
}

// record is one stored profile, keyed by its profile ID.
type record struct {
	ID      uint64  `json:"id"`
	Key     string  `json:"key"`
	Profile Profile `json:"profile"`
}

// EntityID returns the record's ID.
func (r *record) EntityID() uint64 { return r.ID }

// SetEntityID sets the record's ID.
func (r *record) SetEntityID(id uint64) { r.ID = id }

// folder is one explicit folder, keyed by its path.
type folder struct {
	ID   uint64 `json:"id"`
	Path string `json:"path"`
}

// EntityID returns the folder's ID.
func (f *folder) EntityID() uint64 { return f.ID }

// SetEntityID sets the folder's ID.
func (f *folder) SetEntityID(id uint64) { f.ID = id }

// DAOStore implements Store as go-qrdb entities in the records.DatabaseName
// database. The mutex serializes the compound operations (rename, move)
// that span more than one record.
type DAOStore struct {
	mu       sync.RWMutex
	profiles qrdbsdk.GenericDAO[*record]
	folders  qrdbsdk.GenericDAO[*folder]
	closed   bool
}

var _ Store = (*DAOStore)(nil)

// NewStore constructs the DAOStore over the DAOs daos builds. Returns
// ErrNilDAOFactory if daos is nil.
func NewStore(daos *qrdbsdk.DAOFactory) (*DAOStore, error) {
	if daos == nil {
		return nil, ErrNilDAOFactory
	}
	profiles, err := dao.New(daos, records.DatabaseName, profileEntityType,
		func() *record { return &record{} },
		qrdbsdk.WithIDGenerator(qrdbsdk.NewCryptoFieldHashGenerator("Key")))
	if err != nil {
		return nil, &errs.Joined{Lead: ErrStorage, Detail: "open profiles", Cause: err}
	}
	folders, err := dao.New(daos, records.DatabaseName, folderEntityType,
		func() *folder { return &folder{} },
		qrdbsdk.WithIDGenerator(qrdbsdk.NewCryptoFieldHashGenerator("Path")))
	if err != nil {
		return nil, &errs.Joined{Lead: ErrStorage, Detail: "open folders", Cause: err}
	}
	return &DAOStore{profiles: profiles, folders: folders}, nil
}

// Add persists a new profile, deriving its ID from name and folder. Returns
// ErrExists if that folder already holds a profile of that name.
func (s *DAOStore) Add(p *Profile) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrStoreClosed
	}
	if err := p.Validate(); err != nil {
		return err
	}
	p.ID = generateID(p.Name, p.FolderPath)
	now := time.Now().UTC()
	p.CreatedAt = now
	p.UpdatedAt = now
	_, err := s.create(p)
	return err
}

// Get retrieves a profile by ID, or by name when no ID matches.
func (s *DAOStore) Get(idOrName string) (*Profile, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return nil, ErrStoreClosed
	}
	r, err := s.find(idOrName)
	if err != nil {
		return nil, err
	}
	return &r.Profile, nil
}

// List returns every profile, sorted by name (case-insensitive).
func (s *DAOStore) List() ([]*Profile, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return nil, ErrStoreClosed
	}
	all, err := s.all()
	if err != nil {
		return nil, err
	}
	out := make([]*Profile, 0, len(all))
	for _, r := range all {
		out = append(out, &r.Profile)
	}
	sort.Slice(out, func(i, j int) bool {
		return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
	})
	return out, nil
}

// Update replaces the profile p.ID names, preserving its CreatedAt. A
// changed name or folder moves the profile to its new ID; ErrExists is
// returned, and nothing changes, if that ID is already taken.
func (s *DAOStore) Update(p *Profile) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrStoreClosed
	}
	if err := p.Validate(); err != nil {
		return err
	}
	existing, err := s.load(p.ID)
	if err != nil {
		return err
	}
	p.CreatedAt = existing.Profile.CreatedAt
	p.UpdatedAt = time.Now().UTC()
	return s.replace(existing, p)
}

// Delete removes a profile by ID or name.
func (s *DAOStore) Delete(idOrName string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrStoreClosed
	}
	r, err := s.find(idOrName)
	if err != nil {
		return err
	}
	if err := s.profiles.Delete(context.Background(), r); err != nil {
		return &errs.Joined{Lead: ErrStorage, Detail: "delete " + r.Key, Cause: err}
	}
	return nil
}

// ListByFolder returns the profiles in folderPath and all its subfolders;
// an empty folderPath returns every profile.
func (s *DAOStore) ListByFolder(folderPath string) ([]*Profile, error) {
	all, err := s.List()
	if err != nil {
		return nil, err
	}
	out := make([]*Profile, 0)
	for _, p := range all {
		if folderPath == "" || p.FolderPath == folderPath || strings.HasPrefix(p.FolderPath, folderPath+"/") {
			out = append(out, p)
		}
	}
	return out, nil
}

// ListByFolderDirect returns the profiles directly in folderPath.
func (s *DAOStore) ListByFolderDirect(folderPath string) ([]*Profile, error) {
	all, err := s.List()
	if err != nil {
		return nil, err
	}
	out := make([]*Profile, 0)
	for _, p := range all {
		if p.FolderPath == folderPath {
			out = append(out, p)
		}
	}
	return out, nil
}

// ListFolders returns every folder path, sorted: each ancestor of a
// profile's folder plus every explicit folder.
func (s *DAOStore) ListFolders() ([]string, error) {
	all, err := s.List()
	if err != nil {
		return nil, err
	}
	unique := make(map[string]struct{})
	for _, p := range all {
		if p.FolderPath == "" {
			continue
		}
		parts := strings.Split(p.FolderPath, "/")
		for i := range parts {
			unique[strings.Join(parts[:i+1], "/")] = struct{}{}
		}
	}
	explicit, err := s.folders.Find(context.Background()).Execute()
	if err != nil {
		return nil, &errs.Joined{Lead: ErrStorage, Detail: "list folders", Cause: err}
	}
	for _, f := range explicit {
		unique[f.Path] = struct{}{}
	}
	folders := make([]string, 0, len(unique))
	for f := range unique {
		folders = append(folders, f)
	}
	sort.Strings(folders)
	return folders, nil
}

// MoveToFolder moves a profile to folderPath, regenerating its ID. Returns
// ErrMoveToSameFolder if it is already there, and ErrExists, changing
// nothing, if the destination already holds a profile of that name.
func (s *DAOStore) MoveToFolder(idOrName, folderPath string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrStoreClosed
	}
	existing, err := s.find(idOrName)
	if err != nil {
		return err
	}
	if existing.Profile.FolderPath == folderPath {
		return ErrMoveToSameFolder
	}
	moved := existing.Profile
	moved.FolderPath = folderPath
	moved.UpdatedAt = time.Now().UTC()
	return s.replace(existing, &moved)
}

// CreateFolder records an explicit folder, so it survives holding no
// profile. Creating an existing folder is a no-op.
func (s *DAOStore) CreateFolder(path string) error {
	return s.createFolder(context.Background(), path)
}

// createFolder records the folder at path; saving an existing folder again
// is a no-op.
func (s *DAOStore) createFolder(ctx context.Context, path string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrStoreClosed
	}
	if path == "" {
		return ErrFolderEmpty
	}
	if err := s.folders.Save(ctx, &folder{Path: path}); err != nil {
		return &errs.Joined{Lead: ErrStorage, Detail: "create folder " + path, Cause: err}
	}
	return nil
}

// RemoveFolder removes an explicit folder; profiles in it are untouched.
// Removing an absent folder is a no-op.
func (s *DAOStore) RemoveFolder(path string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrStoreClosed
	}
	if path == "" {
		return ErrFolderEmpty
	}
	f, err := s.folders.GetByNaturalKey(context.Background(), path)
	if qrdbsdk.IsDAONotFound(err) {
		return nil
	}
	if err != nil {
		return &errs.Joined{Lead: ErrStorage, Detail: "get folder " + path, Cause: err}
	}
	if err := s.folders.Delete(context.Background(), f); err != nil {
		return &errs.Joined{Lead: ErrStorage, Detail: "remove folder " + path, Cause: err}
	}
	return nil
}

// RenameFolder renames a folder, moving every profile and explicit folder
// beneath it.
func (s *DAOStore) RenameFolder(oldPath, newPath string) error {
	if oldPath == "" || newPath == "" {
		return ErrFolderEmpty
	}
	if oldPath == newPath {
		return ErrMoveToSameFolder
	}
	all, err := s.List()
	if err != nil {
		return err
	}
	for _, p := range all {
		if p.FolderPath == oldPath || strings.HasPrefix(p.FolderPath, oldPath+"/") {
			newFolder := newPath + strings.TrimPrefix(p.FolderPath, oldPath)
			if err := s.MoveToFolder(p.ID, newFolder); err != nil && !errors.Is(err, ErrMoveToSameFolder) {
				return err
			}
		}
	}
	folders, err := s.ListFolders()
	if err != nil {
		return err
	}
	for _, f := range folders {
		if f == oldPath || strings.HasPrefix(f, oldPath+"/") {
			if rErr := s.RemoveFolder(f); rErr != nil {
				return rErr
			}
			if cErr := s.CreateFolder(newPath + strings.TrimPrefix(f, oldPath)); cErr != nil {
				return cErr
			}
		}
	}
	return nil
}

// DeleteFolder removes a folder, every explicit folder beneath it, and
// every profile within it.
func (s *DAOStore) DeleteFolder(path string) error {
	if path == "" {
		return ErrFolderEmpty
	}
	entries, err := s.ListByFolder(path)
	if err != nil {
		return err
	}
	for _, p := range entries {
		if err := s.Delete(p.ID); err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
	}
	folders, err := s.ListFolders()
	if err != nil {
		return err
	}
	for _, f := range folders {
		if f == path || strings.HasPrefix(f, path+"/") {
			if rErr := s.RemoveFolder(f); rErr != nil {
				return rErr
			}
		}
	}
	return nil
}

// ImportLegacy upserts a profile the pre-DAO sealed-KV store wrote under
// ssh/profiles/<id>.json: data is its JSON. Unlike Add, the profile keeps
// its ID and timestamps, so importing it twice is harmless. It is the
// per-record step of the SSH store migrator (pkg/ssh/migrate). A record
// that does not decode, names another ID or fails validation is an
// ErrLegacyRecord.
func (s *DAOStore) ImportLegacy(ctx context.Context, id string, data []byte) error {
	var p Profile
	if err := json.Unmarshal(data, &p); err != nil {
		return &errs.Joined{Lead: ErrLegacyRecord, Detail: id, Cause: err}
	}
	if p.ID != id {
		return &errs.Detail{Err: ErrLegacyRecord, Detail: id + " holds profile " + p.ID}
	}
	if err := p.Validate(); err != nil {
		return &errs.Joined{Lead: ErrLegacyRecord, Detail: id, Cause: err}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrStoreClosed
	}
	if err := s.profiles.Save(ctx, &record{Key: id, Profile: p}); err != nil {
		return &errs.Joined{Lead: ErrStorage, Detail: "import " + id, Cause: err}
	}
	return nil
}

// ImportLegacyFolder records a folder the pre-DAO sealed-KV store marked
// under ssh/profiles/__folders__/<path>. It is CreateFolder with the
// migrator's context.
func (s *DAOStore) ImportLegacyFolder(ctx context.Context, path string) error {
	return s.createFolder(ctx, path)
}

// Search returns the profiles whose name, host, user or folder contains
// query (case-insensitive); an empty query returns every profile.
func (s *DAOStore) Search(query string) ([]*Profile, error) {
	all, err := s.List()
	if err != nil {
		return nil, err
	}
	q := strings.ToLower(strings.TrimSpace(query))
	if q == "" {
		return all, nil
	}
	out := make([]*Profile, 0)
	for _, p := range all {
		if strings.Contains(strings.ToLower(p.Name), q) ||
			strings.Contains(strings.ToLower(p.Host), q) ||
			strings.Contains(strings.ToLower(p.User), q) ||
			strings.Contains(strings.ToLower(p.FolderPath), q) {
			out = append(out, p)
		}
	}
	return out, nil
}

// Close marks the store closed; subsequent operations fail with
// ErrStoreClosed. The DAO factory is owned by the caller.
func (s *DAOStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	return nil
}

// create stores p under its ID and returns the new record, which carries
// the entity ID the DAO assigned, or returns ErrExists if the ID is taken.
func (s *DAOStore) create(p *Profile) (*record, error) {
	r := &record{Key: p.ID, Profile: *p}
	stored, err := s.profiles.SaveIfAbsent(context.Background(), r)
	if err != nil {
		return nil, &errs.Joined{Lead: ErrStorage, Detail: "create " + p.ID, Cause: err}
	}
	if !stored {
		return nil, &errs.Detail{Err: ErrExists, Detail: p.Name}
	}
	return r, nil
}

// replace stores p in place of existing. When p's name or folder moved it
// to a new ID, the new record is created first, so a taken destination
// leaves existing untouched, and removed again if existing cannot be
// deleted, so a failed move leaves only existing behind.
func (s *DAOStore) replace(existing *record, p *Profile) error {
	p.ID = generateID(p.Name, p.FolderPath)
	if p.ID == existing.Key {
		if err := s.profiles.Save(context.Background(), &record{Key: p.ID, Profile: *p}); err != nil {
			return &errs.Joined{Lead: ErrStorage, Detail: "save " + p.ID, Cause: err}
		}
		return nil
	}
	moved, err := s.create(p)
	if err != nil {
		return err
	}
	if err := s.profiles.Delete(context.Background(), existing); err != nil {
		deleteErr := &errs.Joined{Lead: ErrStorage, Detail: "delete " + existing.Key, Cause: err}
		if undoErr := s.profiles.Delete(context.Background(), moved); undoErr != nil {
			return errors.Join(deleteErr, &errs.Joined{Lead: ErrStorage, Detail: "undo create " + p.ID, Cause: undoErr})
		}
		return deleteErr
	}
	return nil
}

// find returns the record of a profile ID, of a root-folder profile name's
// ID, or of the first profile with that name; ErrNotFound otherwise.
func (s *DAOStore) find(idOrName string) (*record, error) {
	r, err := s.load(idOrName)
	if !errors.Is(err, ErrNotFound) {
		return r, err
	}
	if hashed := generateID(idOrName, ""); hashed != idOrName {
		r, err = s.load(hashed)
		if !errors.Is(err, ErrNotFound) {
			return r, err
		}
	}
	all, err := s.all()
	if err != nil {
		return nil, err
	}
	for _, r := range all {
		if strings.EqualFold(r.Profile.Name, idOrName) {
			return r, nil
		}
	}
	return nil, &errs.Detail{Err: ErrNotFound, Detail: idOrName}
}

// load returns the record of profile id, or ErrNotFound.
func (s *DAOStore) load(id string) (*record, error) {
	r, err := s.profiles.GetByNaturalKey(context.Background(), id)
	if qrdbsdk.IsDAONotFound(err) {
		return nil, &errs.Detail{Err: ErrNotFound, Detail: id}
	}
	if err != nil {
		return nil, &errs.Joined{Lead: ErrStorage, Detail: "get " + id, Cause: err}
	}
	return r, nil
}

// all returns every profile record.
func (s *DAOStore) all() ([]*record, error) {
	all, err := s.profiles.Find(context.Background()).Execute()
	if err != nil {
		return nil, &errs.Joined{Lead: ErrStorage, Detail: "list", Cause: err}
	}
	return all, nil
}
