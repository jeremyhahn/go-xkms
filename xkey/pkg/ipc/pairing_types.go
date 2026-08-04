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

// Pairing action constants identify the specific operation within a pairing
// IPC message. Used for map-based O(1) dispatch.
const (
	// ActionPairingNotifyCode is sent by the native host to tell the IPC
	// server (GUI or headless) to display a 6-digit pairing code to the user.
	ActionPairingNotifyCode = "notify_code"

	// ActionPairingCompleted is sent by the native host after the extension
	// successfully submits the correct pairing code and pairing is persisted.
	ActionPairingCompleted = "completed"
)

// validPairingActions is the set of recognized pairing actions for O(1) lookup.
var validPairingActions = map[string]bool{
	ActionPairingNotifyCode: true,
	ActionPairingCompleted:  true,
}

// PairingPayload carries pairing-specific request data in an IPC Message.
type PairingPayload struct {
	Action      string `json:"action"`                 // "notify_code" or "completed"
	Code        string `json:"code,omitempty"`         // 6-digit pairing code
	IdentityKey string `json:"identity_key,omitempty"` // base64 Ed25519 public key
	Origin      string `json:"origin,omitempty"`       // chrome-extension://ID/
}

// PairingResult carries pairing-specific response data.
type PairingResult struct {
	Acknowledged bool `json:"acknowledged"` // true if the code was displayed
}

// Validate checks the PairingPayload for correctness.
func (p *PairingPayload) Validate() error {
	if p.Action == "" {
		return &DetailError{Err: ErrInvalidMessage, Detail: ": pairing action is required"}
	}
	if !validPairingActions[p.Action] {
		return &DetailError{Err: ErrInvalidMessage, Detail: fmt.Sprintf(": unknown pairing action %q", p.Action)}
	}
	switch p.Action {
	case ActionPairingNotifyCode:
		if p.Code == "" {
			return &DetailError{Err: ErrInvalidMessage, Detail: fmt.Sprintf(": code is required for %s action", p.Action)}
		}
	case ActionPairingCompleted:
		if p.Origin == "" {
			return &DetailError{Err: ErrInvalidMessage, Detail: fmt.Sprintf(": origin is required for %s action", p.Action)}
		}
	}
	return nil
}
