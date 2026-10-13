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

package xkms

import (
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// ErrNilBackendFactory is returned when an external backend is registered
// without a factory to construct it.
var ErrNilBackendFactory = types.ErrNilBackendFactory

// ExternalBackend describes a backend implemented outside go-xkms, for
// example a firmware's own wire-protocol backend living in that firmware's
// repository.
type ExternalBackend struct {
	// Type names the backend: a-z, 0-9 and '-', at most 64 characters, and
	// not a name a built-in backend or store type holds. It is also the
	// StoreType label of every key the backend holds and the backend
	// segment of their Key IDs ("<type>:signing:ecdsa-p256:<name>").
	Type BackendType

	// Factory constructs the backend's KeyProvider. AutoInitialize calls it
	// with AutoConfig.BackendConfigs[Type], plus a "key_storage"
	// storage.Backend prefixed "<type>/" when AutoConfig.Datastore is set.
	// The KeyProvider's Type must return types.BackendType(Type).
	Factory BackendFactory
}

// RegisterExternalBackend makes an external backend a first-class backend
// type: valid wherever a built-in one is (BackendType.IsValid,
// types.StoreType.IsValid, Key ID parsing), listed by SupportedBackends, and
// constructed by AutoInitialize through its Factory like every compiled-in
// backend. Call it from the external module's init function.
//
// Like the phone package's RegisterPlatform it is accepted at any time and
// is permanent for the process; a backend registered after AutoInitialize
// is constructed by the next AutoInitialize. Registration is lock-free.
//
// A refused registration returns a *types.BackendTypeRegistrationError
// wrapping types.ErrInvalidBackendTypeName, types.ErrBackendTypeRegistered
// or ErrNilBackendFactory, and registers nothing.
func RegisterExternalBackend(backend ExternalBackend) error {
	// pkcs8 and the other xkms-only names have no types-level constant, so
	// they are refused here before the types layer claims the name.
	if backend.Type.isBuiltin() {
		return &types.BackendTypeRegistrationError{
			Type: types.BackendType(backend.Type),
			Err:  types.ErrBackendTypeRegistered,
		}
	}
	// Publishing the name with its factory is the one atomic step: it
	// decides between racing registrations of the same name, and no reader
	// sees the name as a valid type without its factory and availability.
	return types.RegisterBackendType(types.BackendType(backend.Type), backend.Factory)
}
