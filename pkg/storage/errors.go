// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package storage

import "errors"

var (
	// ErrClosed is returned when attempting to use a closed storage.
	ErrClosed = errors.New("storage: closed")

	// ErrNotFound is returned when a key or certificate is not found.
	ErrNotFound = errors.New("storage: not found")

	// ErrAlreadyExists is returned when attempting to save a key or certificate that already exists.
	ErrAlreadyExists = errors.New("storage: already exists")

	// ErrInvalidID is returned when an ID is invalid or empty.
	ErrInvalidID = errors.New("storage: invalid ID")

	// ErrInvalidData is returned when data is invalid or malformed.
	ErrInvalidData = errors.New("storage: invalid data")
)
