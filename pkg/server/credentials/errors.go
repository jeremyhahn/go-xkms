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

package credentials

import "errors"

// ErrNilPlatformStore is returned when a nil platform store is provided.
var ErrNilPlatformStore = errors.New("credentials: nil platform store")

// ErrNilBarrier is returned when a nil barrier is provided.
var ErrNilBarrier = errors.New("credentials: nil barrier")

// ErrInvalidStrategy is returned when an unsupported seal strategy is configured.
var ErrInvalidStrategy = errors.New("credentials: invalid seal strategy")

// ErrCredentialNotFound is returned when the requested credential does not exist.
var ErrCredentialNotFound = errors.New("credentials: credential not found")

// ErrManualEntryRequired is returned when the configured strategy is "manual"
// and the credential must be submitted by an operator.
var ErrManualEntryRequired = errors.New("credentials: manual entry required")

// ErrCredentialAlreadySubmitted is returned when a manual credential has
// already been submitted.
var ErrCredentialAlreadySubmitted = errors.New("credentials: credential already submitted")

// ErrEmptyCredentialName is returned when an empty credential name is provided.
var ErrEmptyCredentialName = errors.New("credentials: empty credential name")

// ErrEmptyCredentialValue is returned when an empty credential value is provided.
var ErrEmptyCredentialValue = errors.New("credentials: empty credential value")
