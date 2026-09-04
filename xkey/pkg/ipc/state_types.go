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

// This file defines the read-only live-state surface: the questions a CLI
// asks about a *running* device rather than about files on disk. Before it
// existed, `xkey pin status` and `xkey barrier status` answered from the
// sealed on-disk data directory in a separate process, so a configured,
// unsealed device reported itself as unconfigured and sealed.
//
// Every action here DESCRIBES state. None of them returns a PIN, a password
// value, or key material: the socket's only authentication is filesystem
// permission, so every verb reachable on it is reachable by any process
// running as the same user. Describing that a PIN is set is safe; handing
// out its value would turn the socket into a credential exfiltration path.

// State query actions identify which live-state question a state message
// asks. Used for map-based O(1) dispatch.
const (
	ActionStatePIN           = "pin"
	ActionStateBarrier       = "barrier"
	ActionStatePasswordStore = "password_store"
	ActionStatePasswordList  = "password_list"
)

// validStateActions is the set of recognized state actions for O(1) lookup.
var validStateActions = map[string]bool{
	ActionStatePIN:           true,
	ActionStateBarrier:       true,
	ActionStatePasswordStore: true,
	ActionStatePasswordList:  true,
}

// StatePayload carries a live-state query in an IPC Message. The action is
// the only parameter: these are whole-subsystem questions with no arguments.
type StatePayload struct {
	Action string `json:"action"` // "pin", "barrier", "password_store", "password_list"
}

// Validate checks the StatePayload for correctness.
func (p *StatePayload) Validate() error {
	if p.Action == "" {
		return &DetailError{Err: ErrInvalidMessage, Detail: ": state action is required"}
	}
	if !validStateActions[p.Action] {
		return &DetailError{Err: ErrInvalidMessage, Detail: fmt.Sprintf(": unknown state action %q", p.Action)}
	}
	return nil
}

// PINStateResult describes the daemon's PIN configuration and lockout state.
// It reports whether PINs are set, never what they are.
type PINStateResult struct {
	Initialized     bool   `json:"initialized"`      // PIN subsystem has been initialized
	SOPINSet        bool   `json:"so_pin_set"`       // a Security Officer PIN is set
	UserPINSet      bool   `json:"user_pin_set"`     // a User PIN is set
	Strategy        string `json:"strategy"`         // active PIN strategy
	SOPINSupported  bool   `json:"so_pin_supported"` // strategy persists an independent SO PIN
	FailedAttempts  int    `json:"failed_attempts"`  // consecutive failed verifications
	MaxAttempts     int    `json:"max_attempts"`     // retry counter threshold
	IsLocked        bool   `json:"is_locked"`        // lockout is engaged
	RecoverySeconds int    `json:"recovery_seconds"` // seconds until lockout clears
}

// PasswordStoreStateResult describes the daemon's static password store.
// Count is the number of entries, not their contents.
type PasswordStoreStateResult struct {
	Available  bool   `json:"available"`             // the daemon has a store configured
	Locked     bool   `json:"locked"`                // the store cannot be read (barrier sealed)
	Backend    string `json:"backend,omitempty"`     // "barrier" or "file"
	AccessMode string `json:"access_mode,omitempty"` // session access mode, empty when no session server
	Count      int    `json:"count"`                 // number of stored entries
}

// PasswordEntryInfo is the metadata of one stored password. It deliberately
// carries NO password value: the IPC socket is authenticated by filesystem
// permission alone, and a verb that returns secrets over it would let any
// process running as the user exfiltrate the store. Values remain reachable
// only through the on-disk store path, which requires the barrier.
type PasswordEntryInfo struct {
	Name       string `json:"name"`
	Title      string `json:"title,omitempty"`
	Username   string `json:"username,omitempty"`
	URL        string `json:"url,omitempty"`
	FolderPath string `json:"folder_path,omitempty"`
	CreatedAt  string `json:"created_at,omitempty"`
	UpdatedAt  string `json:"updated_at,omitempty"`
}

// PasswordListResult contains password metadata for every stored entry.
type PasswordListResult struct {
	Entries []PasswordEntryInfo `json:"entries"`
}

// StateResult carries live-state response data. Exactly one field is set,
// selected by the requested action.
type StateResult struct {
	PIN           *PINStateResult           `json:"pin,omitempty"`
	Barrier       *BarrierStatusResult      `json:"barrier,omitempty"`
	PasswordStore *PasswordStoreStateResult `json:"password_store,omitempty"`
	PasswordList  *PasswordListResult       `json:"password_list,omitempty"`
}
