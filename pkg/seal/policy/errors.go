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

package policy

import "errors"

var (
	// ErrNilPCRReader is returned when a nil PCRReader is passed to NewManager.
	ErrNilPCRReader = errors.New("policy: PCR reader must not be nil")

	// ErrNilPolicyStore is returned when a nil PolicyStore is passed to NewManager.
	ErrNilPolicyStore = errors.New("policy: policy store must not be nil")

	// ErrPolicyNotFound is returned when a requested policy does not exist.
	ErrPolicyNotFound = errors.New("policy: not found")

	// ErrPolicyExists is returned when creating a policy with a name that
	// is already in use.
	ErrPolicyExists = errors.New("policy: already exists")

	// ErrInvalidName is returned when a policy name is empty or whitespace-only.
	ErrInvalidName = errors.New("policy: name must not be empty")

	// ErrInvalidBank is returned when a PCR bank algorithm is empty.
	ErrInvalidBank = errors.New("policy: bank must not be empty")

	// ErrNoPCRsSelected is returned when no PCR indices are provided.
	ErrNoPCRsSelected = errors.New("policy: at least one PCR index is required")

	// ErrPolicyMismatch is returned when current PCR values do not match
	// the stored policy values.
	ErrPolicyMismatch = errors.New("policy: current PCR values do not match policy")

	// ErrExportFailed is returned when marshaling a policy to JSON fails.
	ErrExportFailed = errors.New("policy: export failed")

	// ErrPCRIndexOutOfRange is returned when a PCR index is not in [0, 23].
	ErrPCRIndexOutOfRange = errors.New("policy: PCR index out of range (must be 0-23)")

	// ErrDuplicatePCRIndex is returned when the same PCR index appears more than once.
	ErrDuplicatePCRIndex = errors.New("policy: duplicate PCR index")

	// ErrUnsupportedBank is returned when the PCR bank algorithm is not recognized.
	ErrUnsupportedBank = errors.New("policy: unsupported PCR bank algorithm")
)
