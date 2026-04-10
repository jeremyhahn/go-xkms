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

package agent

import "errors"

// SSH agent errors.
var (
	ErrAgentLocked           = errors.New("ssh/agent: agent is locked")
	ErrAgentNotConnected     = errors.New("ssh/agent: not connected to xkmsd")
	ErrAgentConnectionFailed = errors.New("ssh/agent: connection to xkmsd failed")
	ErrAgentKeyNotFound      = errors.New("ssh/agent: key not found")
	ErrAgentSignFailed       = errors.New("ssh/agent: signing failed")
	ErrAgentTouchDenied      = errors.New("ssh/agent: touch confirmation denied")
	ErrAgentTouchTimeout     = errors.New("ssh/agent: touch confirmation timeout")
	ErrAgentUnsupportedOp    = errors.New("ssh/agent: operation not supported")
	ErrAgentInvalidKey       = errors.New("ssh/agent: invalid key type")
	ErrAgentSocketExists     = errors.New("ssh/agent: socket already exists")
	ErrAgentNotRunning       = errors.New("ssh/agent: agent is not running")
	ErrAgentAlreadyRunning   = errors.New("ssh/agent: agent is already running")
)

// XKMSdBackend errors.
var (
	ErrBackendNilClient          = errors.New("ssh/agent/backend: client is nil")
	ErrBackendEmptyName          = errors.New("ssh/agent/backend: backend name is empty")
	ErrBackendEmptyKeyID         = errors.New("ssh/agent/backend: key ID is empty")
	ErrBackendListFailed         = errors.New("ssh/agent/backend: failed to list keys")
	ErrBackendGetKeyFailed       = errors.New("ssh/agent/backend: failed to get key")
	ErrBackendNoPublicKey        = errors.New("ssh/agent/backend: no public key data")
	ErrBackendInvalidPEM         = errors.New("ssh/agent/backend: invalid PEM encoding")
	ErrBackendParseFailed        = errors.New("ssh/agent/backend: failed to parse key")
	ErrBackendSignFailed         = errors.New("ssh/agent/backend: signing failed")
	ErrBackendGenerateFailed     = errors.New("ssh/agent/backend: key generation failed")
	ErrBackendImportFailed       = errors.New("ssh/agent/backend: key import failed")
	ErrBackendDeleteFailed       = errors.New("ssh/agent/backend: key deletion failed")
	ErrBackendUnsupportedKeyType = errors.New("ssh/agent/backend: unsupported key type for SSH")
)
