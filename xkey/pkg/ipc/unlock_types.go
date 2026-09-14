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

// UnlockPayload carries unlock-specific request data in an IPC Message.
type UnlockPayload struct {
	PIN string `json:"pin"` // user PIN for app unlock
}

// UnlockResult carries unlock-specific response data.
//
// Success alone is not a report an automated caller can act on: an unlock
// that left half of the daemon locked used to answer with a well-formed
// message whose only signal was Success=false, and callers that looked no
// further than the envelope status reported "Unlocked" for it. Unlocked and
// StillLocked name the subsystems the daemon observed after the attempt, so
// the result says what actually happened rather than only whether a call was
// made.
//
// Unlock is a convergence, not a transition: Success states that nothing the
// daemon governs is locked, which is what a caller acts on. An unlock with
// nothing left to do is therefore a success with an empty Unlocked, and a
// caller that needs "did anything change?" reads Unlocked rather than
// Success.
type UnlockResult struct {
	Success bool   `json:"success"`         // true when nothing the daemon governs is locked afterwards
	Error   string `json:"error,omitempty"` // error message on failure

	// Unlocked names the subsystems this unlock released, e.g.
	// "app lock", "barrier". Empty means nothing was unlocked.
	Unlocked []string `json:"unlocked,omitempty"`

	// StillLocked names the subsystems that remained locked afterwards.
	// A non-empty value is a failure regardless of Success.
	StillLocked []string `json:"still_locked,omitempty"`
}

// Validate checks the UnlockPayload for correctness.
func (p *UnlockPayload) Validate() error {
	if p.PIN == "" {
		return &DetailError{Err: ErrInvalidMessage, Detail: ": pin is required for unlock"}
	}
	return nil
}
