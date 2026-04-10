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

package backendregistry

import "errors"

var (
	// ErrBackendNotFound is returned when a backend with the given ID is not found.
	ErrBackendNotFound = errors.New("backendregistry: backend not found")

	// ErrBackendAlreadyExists is returned when attempting to register a backend
	// with an ID that is already registered.
	ErrBackendAlreadyExists = errors.New("backendregistry: backend already registered")

	// ErrBackendUnavailable is returned when a backend exists but is not in a usable state.
	ErrBackendUnavailable = errors.New("backendregistry: backend unavailable")

	// ErrEmptyBackendID is returned when a backend registration is attempted with an empty ID.
	ErrEmptyBackendID = errors.New("backendregistry: backend ID must not be empty")

	// ErrInvalidCategory is returned when a backend has an unrecognized category.
	ErrInvalidCategory = errors.New("backendregistry: invalid backend category")

	// ErrInvalidLocation is returned when a backend has an unrecognized location.
	ErrInvalidLocation = errors.New("backendregistry: invalid backend location")

	// ErrNilBackend is returned when a nil backend is passed to Register.
	ErrNilBackend = errors.New("backendregistry: backend must not be nil")

	// ErrNoDefaultSet is returned when GetDefault is called for a capability
	// that has no default backend configured.
	ErrNoDefaultSet = errors.New("backendregistry: no default backend set for capability")

	// ErrDefaultBackendNotFound is returned when the default backend for a capability
	// was previously set but the backend has since been unregistered.
	ErrDefaultBackendNotFound = errors.New("backendregistry: default backend not found in registry")

	// ErrRegistryClosed is returned when an operation is attempted on a closed registry.
	ErrRegistryClosed = errors.New("backendregistry: registry is closed")

	// ErrEmptyDisplayName is returned when an empty display name is provided.
	ErrEmptyDisplayName = errors.New("backendregistry: display name must not be empty")
)
