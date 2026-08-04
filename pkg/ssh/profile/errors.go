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

import "errors"

var (
	// ErrInvalidName indicates an empty profile name.
	ErrInvalidName = errors.New("ssh/profile: name is required")

	// ErrInvalidHost indicates an empty host.
	ErrInvalidHost = errors.New("ssh/profile: host is required")

	// ErrNotFound indicates the requested profile does not exist.
	ErrNotFound = errors.New("ssh/profile: profile not found")

	// ErrExists indicates a profile with the same name already exists in the
	// target folder.
	ErrExists = errors.New("ssh/profile: profile already exists")

	// ErrStoreClosed indicates an operation on a closed store.
	ErrStoreClosed = errors.New("ssh/profile: store is closed")

	// ErrFolderEmpty indicates an empty folder path was supplied.
	ErrFolderEmpty = errors.New("ssh/profile: folder path is required")

	// ErrMoveToSameFolder indicates a move whose destination equals the source.
	ErrMoveToSameFolder = errors.New("ssh/profile: already in target folder")

	// ErrMarshalFailed / ErrUnmarshalFailed wrap (de)serialization failures.
	ErrMarshalFailed   = errors.New("ssh/profile: failed to marshal profile")
	ErrUnmarshalFailed = errors.New("ssh/profile: failed to unmarshal profile")

	// ErrNilBackend indicates a nil storage backend was supplied.
	ErrNilBackend = errors.New("ssh/profile: nil storage backend")
)
