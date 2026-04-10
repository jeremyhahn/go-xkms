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

// Package custodian provides custodian group management for M-of-N key
// ceremony participation and share distribution. This supports FIPS 140-2/3
// and PCI DSS separation of duties requirements by enabling tenant-scoped
// custodian groups with threshold-based share management.
package custodian

import "errors"

// Sentinel errors for the custodian package.
var (
	// ErrGroupNotFound is returned when a custodian group cannot be found.
	ErrGroupNotFound = errors.New("custodian: group not found")

	// ErrGroupAlreadyExists is returned when creating a group with an ID that already exists.
	ErrGroupAlreadyExists = errors.New("custodian: group already exists")

	// ErrMemberNotFound is returned when a member is not found in the group.
	ErrMemberNotFound = errors.New("custodian: member not found in group")

	// ErrMemberAlreadyExists is returned when adding a member that is already in the group.
	ErrMemberAlreadyExists = errors.New("custodian: member already exists in group")

	// ErrInvalidThreshold is returned when the threshold is less than 2 or greater than total.
	ErrInvalidThreshold = errors.New("custodian: threshold must be >= 2 and <= total")

	// ErrInvalidTotalShares is returned when total is less than the threshold.
	ErrInvalidTotalShares = errors.New("custodian: total must be >= threshold")

	// ErrGroupFull is returned when adding a member to a group that already has maximum members.
	ErrGroupFull = errors.New("custodian: group already has maximum members")

	// ErrNilStore is returned when a nil store is provided to NewService.
	ErrNilStore = errors.New("custodian: nil store provided")

	// ErrEmptyGroupID is returned when a group ID is empty.
	ErrEmptyGroupID = errors.New("custodian: group ID cannot be empty")

	// ErrEmptyGroupName is returned when a group name is empty.
	ErrEmptyGroupName = errors.New("custodian: group name cannot be empty")

	// ErrEmptyUserID is returned when a user ID is empty.
	ErrEmptyUserID = errors.New("custodian: user ID cannot be empty")

	// ErrInvalidPurpose is returned when a group purpose is empty.
	ErrInvalidPurpose = errors.New("custodian: purpose cannot be empty")

	// ErrShareAlreadyReceived is returned when marking a share as received that was already received.
	ErrShareAlreadyReceived = errors.New("custodian: share already marked as received")

	// ErrGroupEmpty is returned when distributing shares to a group with no members.
	ErrGroupEmpty = errors.New("custodian: group has no members")
)
