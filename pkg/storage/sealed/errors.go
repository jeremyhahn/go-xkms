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

package sealed

import "errors"

var (
	// ErrSealFailed indicates the seal operation failed.
	ErrSealFailed = errors.New("sealed: seal operation failed")

	// ErrUnsealFailed indicates the unseal operation failed.
	ErrUnsealFailed = errors.New("sealed: unseal operation failed")

	// ErrSealerNotAvailable indicates the sealer is not available for sealing.
	ErrSealerNotAvailable = errors.New("sealed: sealer not available")

	// ErrMarshalFailed indicates JSON marshaling of sealed data failed.
	ErrMarshalFailed = errors.New("sealed: marshal failed")

	// ErrUnmarshalFailed indicates JSON unmarshaling of sealed data failed.
	ErrUnmarshalFailed = errors.New("sealed: unmarshal failed")
)
