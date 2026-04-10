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

package ipc

import "fmt"

// UnlockPayload carries unlock-specific request data in an IPC Message.
type UnlockPayload struct {
	PIN string `json:"pin"` // user PIN for app unlock
}

// UnlockResult carries unlock-specific response data.
type UnlockResult struct {
	Success bool   `json:"success"`         // true if unlock succeeded
	Error   string `json:"error,omitempty"` // error message on failure
}

// Validate checks the UnlockPayload for correctness.
func (p *UnlockPayload) Validate() error {
	if p.PIN == "" {
		return fmt.Errorf("%w: pin is required for unlock", ErrInvalidMessage)
	}
	return nil
}
