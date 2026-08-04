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

package main

import "errors"

// Sentinel errors for acme-client flag validation.
var (
	// ErrAccountFlagRequired is returned when --account is not provided.
	ErrAccountFlagRequired = errors.New("--account is required")

	// ErrDeviceIDFlagRequired is returned when --device-id is not provided.
	ErrDeviceIDFlagRequired = errors.New("--device-id is required")
)
