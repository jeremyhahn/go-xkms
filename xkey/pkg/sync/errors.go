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

package sync

import "errors"

var (
	// ErrNilConfig is returned when a nil config is passed to NewService.
	ErrNilConfig = errors.New("sync: nil config")

	// ErrNoDataSources is returned when no data sources are configured.
	ErrNoDataSources = errors.New("sync: no data sources configured")

	// ErrSyncFailed is returned when a synchronization operation fails.
	ErrSyncFailed = errors.New("sync: synchronization failed")

	// ErrTrustStoreSyncFailed is returned when trust store sync fails.
	ErrTrustStoreSyncFailed = errors.New("sync: trust store sync failed")

	// ErrOATHSyncFailed is returned when OATH credential sync fails.
	ErrOATHSyncFailed = errors.New("sync: OATH sync failed")

	// ErrPasswordSyncFailed is returned when password sync fails.
	ErrPasswordSyncFailed = errors.New("sync: password sync failed")

	// ErrCASyncFailed is returned when CA certificate sync fails.
	ErrCASyncFailed = errors.New("sync: CA sync failed")

	// ErrConflictDetected is returned when a sync conflict is detected
	// between local and remote data.
	ErrConflictDetected = errors.New("sync: conflict detected")

	// ErrMergeConflict is returned when a merge conflict cannot be
	// automatically resolved.
	ErrMergeConflict = errors.New("sync: merge conflict unresolved")

	// ErrRemoteUnavailable is returned when the paired remote device
	// is not reachable.
	ErrRemoteUnavailable = errors.New("sync: remote device unavailable")

	// ErrNilDelta is returned when a nil delta is passed to an Apply method.
	ErrNilDelta = errors.New("sync: nil delta")

	// ErrStateSave is returned when sync state persistence fails.
	ErrStateSave = errors.New("sync: failed to save state")

	// ErrStateLoad is returned when sync state loading fails.
	ErrStateLoad = errors.New("sync: failed to load state")
)
