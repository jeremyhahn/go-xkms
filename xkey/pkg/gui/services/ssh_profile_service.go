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

package services

import (
	"context"
	"errors"
	"time"

	sshclient "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

// ErrSSHProfileStoreNotSet indicates the profile store has not been configured.
var ErrSSHProfileStoreNotSet = errors.New("ssh_profile_service: store not configured")

// SSHProfileEntry is the frontend-facing view of an SSH connection profile.
type SSHProfileEntry struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	FolderPath string `json:"folder_path"`
	Host       string `json:"host"`
	Port       int    `json:"port"`
	User       string `json:"user"`
	KeyScope   string `json:"key_scope"`
	KeyOwner   string `json:"key_owner"`
	KeyName    string `json:"key_name"`

	// KeySource selects where the authentication key comes from: "" (the
	// default) uses the xkey-managed key above; "local" uses the operator's
	// own ssh-agent/~/.ssh identities instead (see SSHConfigAlias).
	KeySource string `json:"key_source"`

	// SSHConfigAlias names the ssh_config(5) Host alias to connect through
	// when KeySource is "local".
	SSHConfigAlias string `json:"ssh_config_alias"`

	// LocalIdentity pins one specific local key when KeySource is "local":
	// an identity file path or "agent:<SHA256-fingerprint>". Empty offers
	// every discovered local identity.
	LocalIdentity string `json:"local_identity"`

	// PersistSession records embedded-console sessions from this profile
	// in the persistent session store (restored after reload/restart).
	// False (default) keeps sessions memory-only.
	PersistSession bool `json:"persist_session"`

	Options     []string `json:"options,omitempty"`
	ConsoleMode string   `json:"console_mode"`
	Notes       string   `json:"notes"`
	CreatedAt   string   `json:"created_at"`
	UpdatedAt   string   `json:"updated_at"`
}

// SSHProfileParams carries inputs for adding/updating a profile from the GUI.
type SSHProfileParams struct {
	ID         string `json:"id,omitempty"`
	Name       string `json:"name"`
	FolderPath string `json:"folder_path"`
	Host       string `json:"host"`
	Port       int    `json:"port"`
	User       string `json:"user"`
	KeyScope   string `json:"key_scope"`
	KeyOwner   string `json:"key_owner"`
	KeyName    string `json:"key_name"`

	// KeySource / SSHConfigAlias / LocalIdentity / PersistSession — see
	// SSHProfileEntry.
	KeySource      string `json:"key_source"`
	SSHConfigAlias string `json:"ssh_config_alias"`
	LocalIdentity  string `json:"local_identity"`
	PersistSession bool   `json:"persist_session"`

	Options     []string `json:"options,omitempty"`
	ConsoleMode string   `json:"console_mode"`
	Notes       string   `json:"notes"`
}

// SSHProfileService exposes folder-organized SSH connection profiles to the
// frontend, mirroring StaticPasswordService. Profiles reference an xkey-managed
// key by (scope, owner, name) and never store key material.
type SSHProfileService struct {
	ctx   context.Context
	store sshclient.ProfileStore
}

// NewSSHProfileService constructs the service. The store may be nil until
// SetStore wires the barrier-routed backend.
func NewSSHProfileService(store sshclient.ProfileStore) *SSHProfileService {
	return &SSHProfileService{store: store}
}

// SetContext is invoked by the Wails startup lifecycle hook.
func (s *SSHProfileService) SetContext(ctx context.Context) { s.ctx = ctx }

// SetStore wires/replaces the profile store.
func (s *SSHProfileService) SetStore(store sshclient.ProfileStore) { s.store = store }

// Store returns the underlying store (used by the connect service).
func (s *SSHProfileService) Store() sshclient.ProfileStore { return s.store }

// ListProfiles returns all profiles.
func (s *SSHProfileService) ListProfiles() ([]SSHProfileEntry, error) {
	if s.store == nil {
		return nil, ErrSSHProfileStoreNotSet
	}
	all, err := s.store.List()
	if err != nil {
		return nil, err
	}
	return toEntries(all), nil
}

// ListProfilesByFolder returns profiles in folderPath and its subfolders.
func (s *SSHProfileService) ListProfilesByFolder(folderPath string) ([]SSHProfileEntry, error) {
	if s.store == nil {
		return nil, ErrSSHProfileStoreNotSet
	}
	list, err := s.store.ListByFolder(folderPath)
	if err != nil {
		return nil, err
	}
	return toEntries(list), nil
}

// ListFolders returns all unique folder paths.
func (s *SSHProfileService) ListFolders() ([]string, error) {
	if s.store == nil {
		return nil, ErrSSHProfileStoreNotSet
	}
	return s.store.ListFolders()
}

// GetProfile returns a single profile by ID or name.
func (s *SSHProfileService) GetProfile(idOrName string) (*SSHProfileEntry, error) {
	if s.store == nil {
		return nil, ErrSSHProfileStoreNotSet
	}
	p, err := s.store.Get(idOrName)
	if err != nil {
		return nil, err
	}
	e := toEntry(p)
	return &e, nil
}

// AddProfile creates a new profile.
func (s *SSHProfileService) AddProfile(params SSHProfileParams) (*SSHProfileEntry, error) {
	if s.store == nil {
		return nil, ErrSSHProfileStoreNotSet
	}
	p := paramsToProfile(params)
	if err := s.store.Add(p); err != nil {
		return nil, err
	}
	e := toEntry(p)
	return &e, nil
}

// UpdateProfile modifies an existing profile.
func (s *SSHProfileService) UpdateProfile(params SSHProfileParams) error {
	if s.store == nil {
		return ErrSSHProfileStoreNotSet
	}
	p := paramsToProfile(params)
	p.ID = params.ID
	return s.store.Update(p)
}

// DeleteProfile removes a profile by ID or name.
func (s *SSHProfileService) DeleteProfile(idOrName string) error {
	if s.store == nil {
		return ErrSSHProfileStoreNotSet
	}
	return s.store.Delete(idOrName)
}

// MoveProfile moves a profile to a different folder.
func (s *SSHProfileService) MoveProfile(idOrName, folderPath string) error {
	if s.store == nil {
		return ErrSSHProfileStoreNotSet
	}
	return s.store.MoveToFolder(idOrName, folderPath)
}

// CreateFolder persists an empty folder.
func (s *SSHProfileService) CreateFolder(path string) error {
	if s.store == nil {
		return ErrSSHProfileStoreNotSet
	}
	return s.store.CreateFolder(path)
}

// RenameFolder renames a folder and everything beneath it.
func (s *SSHProfileService) RenameFolder(oldPath, newPath string) error {
	if s.store == nil {
		return ErrSSHProfileStoreNotSet
	}
	return s.store.RenameFolder(oldPath, newPath)
}

// DeleteFolder removes a folder and all entries within it.
func (s *SSHProfileService) DeleteFolder(path string) error {
	if s.store == nil {
		return ErrSSHProfileStoreNotSet
	}
	return s.store.DeleteFolder(path)
}

// SearchProfiles returns profiles matching the query.
func (s *SSHProfileService) SearchProfiles(query string) ([]SSHProfileEntry, error) {
	if s.store == nil {
		return nil, ErrSSHProfileStoreNotSet
	}
	res, err := s.store.Search(query)
	if err != nil {
		return nil, err
	}
	return toEntries(res), nil
}

// paramsToProfile maps GUI params to an SDK Profile.
func paramsToProfile(params SSHProfileParams) *sshclient.Profile {
	return &sshclient.Profile{
		Name:       params.Name,
		FolderPath: params.FolderPath,
		Host:       params.Host,
		Port:       params.Port,
		User:       params.User,
		KeyScope:   params.KeyScope,
		KeyOwner:   params.KeyOwner,
		KeyName:    params.KeyName,

		KeySource:      params.KeySource,
		SSHConfigAlias: params.SSHConfigAlias,
		LocalIdentity:  params.LocalIdentity,
		PersistSession: params.PersistSession,

		Options:     params.Options,
		ConsoleMode: params.ConsoleMode,
		Notes:       params.Notes,
	}
}

// toEntry maps an SDK Profile to the frontend view.
func toEntry(p *sshclient.Profile) SSHProfileEntry {
	return SSHProfileEntry{
		ID:         p.ID,
		Name:       p.Name,
		FolderPath: p.FolderPath,
		Host:       p.Host,
		Port:       p.EffectivePort(),
		User:       p.User,
		KeyScope:   p.KeyScope,
		KeyOwner:   p.KeyOwner,
		KeyName:    p.KeyName,

		KeySource:      p.KeySource,
		SSHConfigAlias: p.SSHConfigAlias,
		LocalIdentity:  p.LocalIdentity,
		PersistSession: p.PersistSession,

		Options:     p.Options,
		ConsoleMode: p.ConsoleMode,
		Notes:       p.Notes,
		CreatedAt:   p.CreatedAt.Format(time.RFC3339),
		UpdatedAt:   p.UpdatedAt.Format(time.RFC3339),
	}
}

func toEntries(ps []*sshclient.Profile) []SSHProfileEntry {
	out := make([]SSHProfileEntry, 0, len(ps))
	for _, p := range ps {
		out = append(out, toEntry(p))
	}
	return out
}
