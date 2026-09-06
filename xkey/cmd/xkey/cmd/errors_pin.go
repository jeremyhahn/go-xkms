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

package cmd

import "fmt"

// PINCommandError represents a PIN command operation error.
type PINCommandError struct {
	Operation string
	Message   string
	Err       error
}

// Error returns the error message.
func (e *PINCommandError) Error() string {
	if e.Err != nil {
		if e.Message != "" {
			return fmt.Sprintf("pin: %s: %s: %v", e.Operation, e.Message, e.Err)
		}
		return fmt.Sprintf("pin: %s: %v", e.Operation, e.Err)
	}
	if e.Message != "" {
		return fmt.Sprintf("pin: %s: %s", e.Operation, e.Message)
	}
	return fmt.Sprintf("pin: %s", e.Operation)
}

// Unwrap returns the underlying error.
func (e *PINCommandError) Unwrap() error {
	return e.Err
}

// PINStoreNotFoundError reports that the resolved data directory holds no
// PIN state directory. It is a distinct condition from a present-but-empty
// store: it means either the device was never initialized or the command
// is pointed at the wrong data directory, and it must never be rendered
// as a confident "PIN not set".
type PINStoreNotFoundError struct {
	// Dir is the PIN state directory that does not exist.
	Dir string
}

// Error returns the error message.
func (e *PINStoreNotFoundError) Error() string {
	return fmt.Sprintf(
		"pin: no PIN state directory at %s (not initialized, or the wrong data directory; run 'xkey pin set-so' to initialize, or point --data-dir / XKEY_DATA_DIR at the device's data directory)",
		e.Dir)
}

// PIN command sentinel errors.
var (
	ErrPINCmdReadFailed     = &PINCommandError{Operation: "read_pin", Message: "failed to read PIN"}
	ErrPINCmdEmpty          = &PINCommandError{Operation: "read_pin", Message: "PIN cannot be empty"}
	ErrPINCmdMismatch       = &PINCommandError{Operation: "read_pin", Message: "PINs do not match"}
	ErrPINCmdSetSOFailed    = &PINCommandError{Operation: "set_so", Message: "failed to set SO PIN"}
	ErrPINCmdSetUserFailed  = &PINCommandError{Operation: "set_user", Message: "failed to set user PIN"}
	ErrPINCmdChangeSOFailed = &PINCommandError{Operation: "change_so", Message: "failed to change SO PIN"}
	ErrPINCmdChangeUserFail = &PINCommandError{Operation: "change_user", Message: "failed to change user PIN"}
	ErrPINCmdVerifyFailed   = &PINCommandError{Operation: "verify", Message: "failed to verify PIN"}
	ErrPINCmdStatusFailed   = &PINCommandError{Operation: "status", Message: "failed to get PIN status"}
	ErrPINCmdResetFailed    = &PINCommandError{Operation: "reset_lockout", Message: "failed to reset lockout"}
	ErrPINCmdManagerFailed  = &PINCommandError{Operation: "create_manager", Message: "failed to create PIN manager"}
	ErrPINCmdDataDirResolve = &PINCommandError{Operation: "resolve_data_dir", Message: "failed to resolve data directory"}
	ErrPINCmdInvalidType    = &PINCommandError{Operation: "verify", Message: "invalid PIN type, must be 'so' or 'user'"}
)
