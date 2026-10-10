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

package ssh

import (
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	pkgprofile "github.com/jeremyhahn/go-xkms/pkg/ssh/profile"
)

// Profile is an SSH host connection profile (folder-organized). Re-exported so
// SDK consumers (the xkey GUI/CLI) never import pkg/ssh/profile directly.
type Profile = pkgprofile.Profile

// ProfileStore is the SSH-profile persistence interface.
type ProfileStore = pkgprofile.Store

// GenerateProfileID returns the deterministic ID for a (name, folderPath).
var GenerateProfileID = pkgprofile.GenerateID

// NewProfileStore constructs a folder-aware SSH profile store over the DAOs
// daos builds.
func NewProfileStore(daos *qrdbsdk.DAOFactory) (ProfileStore, error) {
	return pkgprofile.NewStore(daos)
}

// Re-exported profile error sentinels for errors.Is checks.
var (
	ErrProfileNotFound      = pkgprofile.ErrNotFound
	ErrProfileExists        = pkgprofile.ErrExists
	ErrProfileInvalidName   = pkgprofile.ErrInvalidName
	ErrProfileInvalidHost   = pkgprofile.ErrInvalidHost
	ErrProfileFolderEmpty   = pkgprofile.ErrFolderEmpty
	ErrProfileSameFolder    = pkgprofile.ErrMoveToSameFolder
	ErrProfileStoreClosed   = pkgprofile.ErrStoreClosed
	ErrProfileNilDAOFactory = pkgprofile.ErrNilDAOFactory
)
