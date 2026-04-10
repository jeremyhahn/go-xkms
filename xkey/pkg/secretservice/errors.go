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

// Package secretservice implements the org.freedesktop.secrets D-Bus API,
// exposing go-xkms password storage to applications like Firefox, Chrome,
// git-credential-libsecret, and other Secret Service consumers.
package secretservice

import "errors"

var (
	// ErrDBusUnavailable is returned when the D-Bus session bus cannot be reached.
	ErrDBusUnavailable = errors.New("secretservice: D-Bus session bus unavailable")

	// ErrServiceAlreadyRunning is returned when attempting to start an already running service.
	ErrServiceAlreadyRunning = errors.New("secretservice: service already running")

	// ErrServiceNotRunning is returned when attempting operations on a stopped service.
	ErrServiceNotRunning = errors.New("secretservice: service not running")

	// ErrSessionNotFound is returned when a session path does not exist.
	ErrSessionNotFound = errors.New("secretservice: session not found")

	// ErrCollectionNotFound is returned when a collection path does not exist.
	ErrCollectionNotFound = errors.New("secretservice: collection not found")

	// ErrItemNotFound is returned when an item path does not exist.
	ErrItemNotFound = errors.New("secretservice: item not found")

	// ErrCollectionLocked is returned when accessing a locked collection.
	ErrCollectionLocked = errors.New("secretservice: collection is locked")

	// ErrInvalidSession is returned when a session is invalid or expired.
	ErrInvalidSession = errors.New("secretservice: invalid session")

	// ErrInvalidAlgorithm is returned when an unsupported encryption algorithm is requested.
	ErrInvalidAlgorithm = errors.New("secretservice: unsupported algorithm")

	// ErrNilPasswordStore is returned when the password store is nil.
	ErrNilPasswordStore = errors.New("secretservice: password store is nil")

	// ErrDHKeyExchangeFailed is returned when Diffie-Hellman key exchange fails.
	ErrDHKeyExchangeFailed = errors.New("secretservice: DH key exchange failed")

	// ErrEncryptionFailed is returned when session encryption fails.
	ErrEncryptionFailed = errors.New("secretservice: encryption failed")

	// ErrDecryptionFailed is returned when session decryption fails.
	ErrDecryptionFailed = errors.New("secretservice: decryption failed")

	// ErrPromptDismissed is returned when a user dismisses a prompt.
	ErrPromptDismissed = errors.New("secretservice: prompt dismissed")

	// ErrNameConflict is returned when an item with the same attributes already exists.
	ErrNameConflict = errors.New("secretservice: item with same attributes exists")
)
