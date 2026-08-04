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

package sessions

import "errors"

var (
	// ErrInvalidTitle indicates an empty session title.
	ErrInvalidTitle = errors.New("ssh/sessions: title is required")

	// ErrInvalidOrigin indicates a record with no (or more than one)
	// reconnect origin: exactly one of Host, ProfileID, or Alias must be set.
	ErrInvalidOrigin = errors.New("ssh/sessions: exactly one reconnect origin is required")

	// ErrNotFound indicates the requested session does not exist.
	ErrNotFound = errors.New("ssh/sessions: session not found")

	// ErrStoreClosed indicates an operation on a closed store.
	ErrStoreClosed = errors.New("ssh/sessions: store is closed")

	// ErrMarshalFailed / ErrUnmarshalFailed wrap (de)serialization failures.
	ErrMarshalFailed   = errors.New("ssh/sessions: failed to marshal session")
	ErrUnmarshalFailed = errors.New("ssh/sessions: failed to unmarshal session")

	// ErrNilBackend indicates a nil storage backend was supplied.
	ErrNilBackend = errors.New("ssh/sessions: nil storage backend")
)
