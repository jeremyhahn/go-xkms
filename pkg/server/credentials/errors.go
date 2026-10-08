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

import (
	"errors"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
)

// ErrNilPlatformStore is returned when a nil platform store is provided.
var ErrNilPlatformStore = errors.New("credentials: nil platform store")

// ErrNilBarrier is returned when a nil barrier is provided.
var ErrNilBarrier = errors.New("credentials: nil barrier")

// ErrInvalidStrategy is returned when an unsupported seal strategy is configured.
var ErrInvalidStrategy = errors.New("credentials: invalid seal strategy")

// ErrCredentialAlreadySubmitted is returned when a manual credential has
// already been submitted.
var ErrCredentialAlreadySubmitted = errors.New("credentials: credential already submitted")

// ErrCredentialNotFound is returned when the requested credential does not
// exist. It is go-qrdb's sentinel, so every strategy reports the same one.
var ErrCredentialNotFound = qrdbsdk.ErrCredentialNotFound

// ErrEmptyCredentialName is returned when an empty credential name is provided.
var ErrEmptyCredentialName = qrdbsdk.ErrEmptyCredentialName

// ErrEmptyCredentialValue is returned when an empty credential value is provided.
var ErrEmptyCredentialValue = qrdbsdk.ErrEmptyCredentialValue
