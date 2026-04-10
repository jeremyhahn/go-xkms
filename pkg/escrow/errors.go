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

package escrow

import "errors"

var (
	// ErrAgentNotConfigured is returned when the escrow agent type is missing
	// or the agent has not been properly configured.
	ErrAgentNotConfigured = errors.New("escrow: agent not configured")

	// ErrAgentUnavailable is returned when the escrow agent cannot be reached.
	ErrAgentUnavailable = errors.New("escrow: agent unavailable")

	// ErrEscrowFailed is returned when the escrow operation fails.
	ErrEscrowFailed = errors.New("escrow: escrow operation failed")

	// ErrRecoverFailed is returned when key recovery from escrow fails.
	ErrRecoverFailed = errors.New("escrow: recover operation failed")

	// ErrRevokeFailed is returned when revoking an escrowed key fails.
	ErrRevokeFailed = errors.New("escrow: revoke operation failed")

	// ErrKeyNotFound is returned when the requested escrowed key does not exist.
	ErrKeyNotFound = errors.New("escrow: escrowed key not found")

	// ErrInvalidRequest is returned when the escrow request is malformed.
	ErrInvalidRequest = errors.New("escrow: invalid request")

	// ErrNilWrappedKey is returned when wrapped key material is empty or nil.
	ErrNilWrappedKey = errors.New("escrow: wrapped key material cannot be nil")

	// ErrEmptyKeyID is returned when a required key ID is empty.
	ErrEmptyKeyID = errors.New("escrow: key ID cannot be empty")

	// ErrEmptyEndpoint is returned when a required endpoint is empty.
	ErrEmptyEndpoint = errors.New("escrow: endpoint cannot be empty")

	// ErrAuthenticationFailed is returned when mTLS or other authentication
	// with the escrow agent fails.
	ErrAuthenticationFailed = errors.New("escrow: authentication failed")

	// ErrAlreadyEscrowed is returned when attempting to escrow a key that
	// already exists in the escrow service.
	ErrAlreadyEscrowed = errors.New("escrow: key already escrowed")

	// ErrNotImplemented is returned by stub implementations that do not yet
	// have a backing protocol library (e.g., KMIP).
	ErrNotImplemented = errors.New("escrow: not implemented")

	// ErrRegistryEmpty is returned when operations are attempted on a registry
	// with no registered agents.
	ErrRegistryEmpty = errors.New("escrow: no agents registered")

	// ErrAgentAlreadyRegistered is returned when attempting to register an
	// agent with a name that is already in use.
	ErrAgentAlreadyRegistered = errors.New("escrow: agent already registered")

	// ErrEmptyAgentName is returned when an agent registration name is empty.
	ErrEmptyAgentName = errors.New("escrow: agent name cannot be empty")

	// ErrNilAgent is returned when a nil agent is passed to Register.
	ErrNilAgent = errors.New("escrow: agent cannot be nil")

	// ErrNilRequest is returned when a nil request is passed.
	ErrNilRequest = errors.New("escrow: request cannot be nil")

	// ErrAgentClosed is returned when operations are attempted on a closed agent.
	ErrAgentClosed = errors.New("escrow: agent is closed")
)
