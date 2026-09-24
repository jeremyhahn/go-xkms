// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package secretservice

import xkms "github.com/jeremyhahn/go-xkms/sdk/go"

// errStore wraps a *memoryStore and lets a test inject an error from any of
// a handful of methods that memoryStore itself can never fail, so failure
// branches downstream of those calls (audit-failure guards, error mapping)
// are reachable without a real backend.
type errStore struct {
	*memoryStore

	listByFolderDirectErr error
	removeFolderErr       error
	createFolderErr       error
	listErr               error
	listFoldersErr        error
	setAliasErr           error
	getErr                error
	updateErr             error
}

func newErrStore() *errStore {
	return &errStore{memoryStore: newMemoryStore()}
}

func (s *errStore) Get(idOrName string) (*xkms.StaticPassword, error) {
	if s.getErr != nil {
		return nil, s.getErr
	}
	return s.memoryStore.Get(idOrName)
}

func (s *errStore) Update(pw *xkms.StaticPassword) error {
	if s.updateErr != nil {
		return s.updateErr
	}
	return s.memoryStore.Update(pw)
}

func (s *errStore) ListByFolderDirect(folder string) ([]*xkms.StaticPassword, error) {
	if s.listByFolderDirectErr != nil {
		return nil, s.listByFolderDirectErr
	}
	return s.memoryStore.ListByFolderDirect(folder)
}

func (s *errStore) RemoveFolder(path string) error {
	if s.removeFolderErr != nil {
		return s.removeFolderErr
	}
	return s.memoryStore.RemoveFolder(path)
}

func (s *errStore) CreateFolder(path string) error {
	if s.createFolderErr != nil {
		return s.createFolderErr
	}
	return s.memoryStore.CreateFolder(path)
}

func (s *errStore) List() ([]*xkms.StaticPassword, error) {
	if s.listErr != nil {
		return nil, s.listErr
	}
	return s.memoryStore.List()
}

func (s *errStore) ListFolders() ([]string, error) {
	if s.listFoldersErr != nil {
		return nil, s.listFoldersErr
	}
	return s.memoryStore.ListFolders()
}

// SetAlias and GetAlias implement the aliasStore capability interface (see
// service.go) so a test can exercise SetAlias's/CreateCollection's
// persisted-alias error-handling branches.
func (s *errStore) SetAlias(name string, folderPath string) error {
	if s.setAliasErr != nil {
		return s.setAliasErr
	}
	return nil
}

func (s *errStore) GetAlias(name string) (string, bool, error) {
	return "", false, nil
}
