// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

import (
	"github.com/jeremyhahn/go-xkms/pkg/compose"
	"github.com/jeremyhahn/go-xkms/pkg/keyversion"
	pkgxkms "github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// Key-version model (pkg/keyversion) re-exports. A connected client reaches
// the key-version API through Client (ListKeyVersions, EnableKeyVersion,
// RotateKey, ...); these name the model's records and errors, and build the
// record store an embedding host wires into its XKMSService.

// KeyVersionStore persists every rotated key's version record.
type KeyVersionStore = keyversion.Store

// KeyVersionRecord is one key's version record: its versions and the
// current one.
type KeyVersionRecord = keyversion.Record

// KeyVersion is one version of a key.
type KeyVersion = keyversion.Version

// KeyVersionState is a version's lifecycle state.
type KeyVersionState = keyversion.State

// KeyVersionRequiredError reports an AES-CBC or RSA PKCS#1 v1.5 decryption
// of a key with more than one enabled version that named no version.
type KeyVersionRequiredError = keyversion.KeyVersionRequiredError

// ReservedKeyIDError reports a key ID ending in the reserved "--v<digits>"
// version suffix.
type ReservedKeyIDError = keyversion.ReservedKeyIDError

// KeyVersionNotFoundError reports a version a key does not have.
type KeyVersionNotFoundError = keyversion.VersionNotFoundError

// KeyVersionUnavailableError reports a disabled or retired version named
// for an operation.
type KeyVersionUnavailableError = keyversion.VersionUnavailableError

// CurrentKeyVersionError reports an attempt to disable or retire a key's
// current version.
type CurrentKeyVersionError = keyversion.CurrentVersionError

// RetiredKeyVersionError reports an attempt to change a retired version.
type RetiredKeyVersionError = keyversion.RetiredVersionError

// KeyVersionMissingError reports a recorded version whose backend key is
// gone.
type KeyVersionMissingError = pkgxkms.KeyVersionMissingError

// KeyExistsError reports a key ID taken by a rotated key.
type KeyExistsError = pkgxkms.KeyExistsError

// KeyRotationUnsupportedError reports a key whose algorithm cannot be
// rotated.
type KeyRotationUnsupportedError = pkgxkms.KeyRotationUnsupportedError

// Key version states.
const (
	KeyVersionStateEnabled  = keyversion.StateEnabled
	KeyVersionStateDisabled = keyversion.StateDisabled
	KeyVersionStateRetired  = keyversion.StateRetired

	// KeyVersionDatabase is the go-qrdb database key-version records live
	// in.
	KeyVersionDatabase = keyversion.DatabaseName
)

var (
	// ErrKeyVersionsNotConfigured is returned by the operations that change
	// a key's versions when no version store is wired.
	ErrKeyVersionsNotConfigured = pkgxkms.ErrKeyVersionsNotConfigured

	// NewKeyVersionStore returns a KeyVersionStore over a DAO factory that
	// serves the KeyVersionDatabase database, its DAO calls running on the
	// context the call-context function derives (nil: the caller's).
	NewKeyVersionStore = keyversion.NewStore

	// BuildKeyVersionStore builds the KeyVersionStore over a DAO factory
	// serving the KeyVersionDatabase database, as xkmsd does; over an
	// embedded node pass its ServiceContext so the store's calls run as xkms.
	BuildKeyVersionStore = compose.BuildKeyVersionStore

	// KeyVersionName returns the backend key name of a version of a key:
	// the key ID for version 1, "<key ID>--v<n>" after.
	KeyVersionName = keyversion.Name
)
