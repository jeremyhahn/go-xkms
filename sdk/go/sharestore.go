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

package xkms

import "github.com/jeremyhahn/go-xkms/pkg/sharestore"

// Client-side custodian-vault surface re-exported so the xkey GUI/CLI persist
// recovery shares to the canonical pkg/sharestore local vault through the SDK.

// ShareEntry is a stored custodian recovery share.
type ShareEntry = sharestore.ShareEntry

// ShareStore is the local custodian share-vault interface.
type ShareStore = sharestore.ShareStore

// NewBackendShareStore constructs a barrier-backed custodian share store over
// the given storage backend and key prefix.
var NewBackendShareStore = sharestore.NewBackendShareStore

// NewMemoryShareStore constructs an in-memory custodian share store.
var NewMemoryShareStore = sharestore.NewMemoryShareStore

var (
	// ErrShareStoreInvalidServerURL is returned when a server URL is required but missing.
	ErrShareStoreInvalidServerURL = sharestore.ErrInvalidServerURL
	// ErrShareStoreExists is returned when a share already exists.
	ErrShareStoreExists = sharestore.ErrShareExists
	// ErrShareStoreNotFound is returned when a share is missing.
	ErrShareStoreNotFound = sharestore.ErrShareNotFound
)
