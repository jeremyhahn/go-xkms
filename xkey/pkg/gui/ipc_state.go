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

package gui

import (
	"errors"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/ipc"
)

// This file makes the running GUI answer the questions the CLI used to
// answer from the sealed on-disk data directory. `xkey pin status` and
// `xkey barrier status` opened that directory in a *separate* process, which
// necessarily reports a fresh, sealed barrier and unset PINs — a false
// negative on a device whose PINs are set and whose barrier this process
// holds unsealed.
//
// Everything below is a read-only projection of state the GUI already owns.
// No method returns a PIN, a password value, or key material: the socket is
// authenticated by filesystem permission alone, so anything reachable here
// is reachable by any process running as the same user.

// Compile-time check that the GUI IPC handler answers live-state queries.
var _ ipc.StateHandler = (*guiIPCHandler)(nil)

// Static password store backend kinds reported over IPC.
const (
	staticPWBackendBarrier = "barrier"
	staticPWBackendFile    = "file"
)

// State query errors.
var (
	// ErrStatePINUnavailable indicates the PIN service is not wired up.
	ErrStatePINUnavailable = errors.New("gui: PIN service unavailable")

	// ErrStateBarrierUnavailable indicates the barrier service is not wired up.
	ErrStateBarrierUnavailable = errors.New("gui: barrier service unavailable")
)

// HandleStatePIN reports the live PIN configuration and lockout counters.
func (h *guiIPCHandler) HandleStatePIN() (*ipc.PINStateResult, error) {
	svc := h.app.pinService
	if svc == nil {
		return nil, ErrStatePINUnavailable
	}

	status, err := svc.GetPINStatus()
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ipc.ErrStateOperation, Cause: err}
	}

	result := &ipc.PINStateResult{
		Initialized:    status.Initialized,
		SOPINSet:       status.SOPINSet,
		UserPINSet:     status.UserPINSet,
		Strategy:       status.Strategy,
		SOPINSupported: status.SOPINSupported,
	}

	// The lockout counters are reported best-effort: a backend without a
	// software counter yields a zero-value status, and a backend that fails
	// to report must not suppress the PIN-set facts above, which are the
	// answer the caller came for.
	if lockout, lockoutErr := svc.GetLockoutStatus(); lockoutErr == nil && lockout != nil {
		result.FailedAttempts = lockout.FailedAttempts
		result.MaxAttempts = lockout.MaxAttempts
		result.IsLocked = lockout.IsLocked
		result.RecoverySeconds = lockout.RecoverySeconds
	}

	return result, nil
}

// HandleStateBarrier reports the live barrier seal state.
func (h *guiIPCHandler) HandleStateBarrier() (*ipc.BarrierStatusResult, error) {
	svc := h.app.barrierService
	if svc == nil {
		return nil, ErrStateBarrierUnavailable
	}

	status := svc.Status()
	return &ipc.BarrierStatusResult{
		Initialized:    svc.IsInitialized(),
		Sealed:         status.Sealed,
		Strategy:       string(status.Strategy),
		HardwareBacked: status.HardwareBacked,
	}, nil
}

// HandleStatePasswordStore reports whether the static password store is
// readable and how many entries it holds — never their contents.
func (h *guiIPCHandler) HandleStatePasswordStore() (*ipc.PasswordStoreStateResult, error) {
	result := &ipc.PasswordStoreStateResult{
		Backend: h.app.staticpwBackendKind,
	}

	svc := h.app.staticPWService
	if svc == nil || h.app.staticpwStore == nil {
		result.Locked = true
		return result, nil
	}
	result.Available = true

	entries, err := svc.ListPasswords()
	if err != nil {
		// A sealed barrier is a state, not a failure: report the store as
		// locked rather than erroring, so the caller still learns where the
		// store is and why it is unreadable.
		result.Locked = true
		return result, nil
	}

	result.Count = len(entries)
	return result, nil
}

// HandleStatePasswordList reports the metadata of every stored password.
// Password values are deliberately omitted; see ipc.PasswordEntryInfo.
func (h *guiIPCHandler) HandleStatePasswordList() (*ipc.PasswordListResult, error) {
	svc := h.app.staticPWService
	if svc == nil || h.app.staticpwStore == nil {
		return &ipc.PasswordListResult{Entries: []ipc.PasswordEntryInfo{}}, nil
	}

	entries, err := svc.ListPasswords()
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ipc.ErrStateOperation, Cause: err}
	}

	infos := make([]ipc.PasswordEntryInfo, 0, len(entries))
	for _, entry := range entries {
		infos = append(infos, ipc.PasswordEntryInfo{
			Name:       entry.Name,
			Title:      entry.Title,
			Username:   entry.Username,
			URL:        entry.URL,
			FolderPath: entry.FolderPath,
			CreatedAt:  entry.CreatedAt,
			UpdatedAt:  entry.UpdatedAt,
		})
	}

	return &ipc.PasswordListResult{Entries: infos}, nil
}
