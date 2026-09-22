// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package services

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// AppLockPINMaxAttempts is the app lock's own unlock-attempt budget for the
// "unlock" IPC verb, sized like the CTAP2 PIN retry counter it stands
// beside: eight credential rejections before the verb refuses outright,
// independent of and in addition to whatever counter the PIN backend or
// hardware strategy keeps.
//
// It exists because that other counter is not always reachable. The
// software PIN backend keeps no counter of its own at all, and the one
// branch that most needs a budget -- a sealed barrier, which is the normal
// locked state of a wizard-configured device -- has its credential live
// behind the very barrier the unlock is trying to open, so nothing behind
// it can be consulted until the correct PIN has already been supplied.
const AppLockPINMaxAttempts = 8

// appLockAttemptsFileName is the file recording the app lock's remaining
// unlock attempts, kept beside the PIN state under <dataDir>/pin -- NOT
// behind the barrier. The barrier is sealed for exactly the unlock this
// counter guards, so a location the barrier governs would be unreadable
// when the counter is needed most.
const appLockAttemptsFileName = "unlock_attempts"

// appLockAttemptsSubdir is the directory, relative to the data directory,
// the counter is kept under -- the same "pin" directory the PIN state
// itself uses (see pin_strategy.go), because both live outside the
// barrier for the same reason.
const appLockAttemptsSubdir = "pin"

// appLockAttemptsRecord is the on-disk representation of the persisted
// budget.
type appLockAttemptsRecord struct {
	Remaining int `json:"remaining"`
}

// AppLockAttemptsLoadError reports that the persisted unlock-attempt
// counter could not be read or parsed.
type AppLockAttemptsLoadError struct {
	Path  string
	Cause error
}

// Error implements the error interface.
func (e *AppLockAttemptsLoadError) Error() string {
	return fmt.Sprintf("app_lock: failed to read unlock attempt counter at %s: %s", e.Path, e.Cause)
}

// Unwrap returns the underlying cause for errors.Is / errors.As.
func (e *AppLockAttemptsLoadError) Unwrap() error {
	return e.Cause
}

// AppLockAttemptsSaveError reports that the persisted unlock-attempt
// counter could not be written.
type AppLockAttemptsSaveError struct {
	Path  string
	Cause error
}

// Error implements the error interface.
func (e *AppLockAttemptsSaveError) Error() string {
	return fmt.Sprintf("app_lock: failed to persist unlock attempt counter at %s: %s", e.Path, e.Cause)
}

// Unwrap returns the underlying cause for errors.Is / errors.As.
func (e *AppLockAttemptsSaveError) Unwrap() error {
	return e.Cause
}

// appLockAttemptCounter persists the app lock's own unlock-attempt budget
// to a small file outside the barrier, so a wrong PIN is counted even
// while the barrier that would otherwise hold this state is sealed.
//
// It is safe for concurrent use: every operation re-reads the persisted
// record before deciding, under mu, rather than trusting an in-memory
// cache, so a reset from another process -- the "xkey pin reset-lockout" /
// "xkey pin set-user" CLI, running outside the daemon whose AppLockService
// owns the live instance -- is observed on the daemon's very next check
// rather than only after a restart.
type appLockAttemptCounter struct {
	mu   sync.Mutex
	path string // empty: no data directory wired; the count is in-memory only
	mem  int    // used only when path == ""
}

// newAppLockAttemptCounter creates a counter persisted under
// <dataDir>/pin/unlock_attempts. An empty dataDir keeps the budget
// in-memory for the life of the process -- the state every AppLockService
// starts in until SetDataDir is called, and the state tests that never
// call it exercise.
func newAppLockAttemptCounter(dataDir string) *appLockAttemptCounter {
	c := &appLockAttemptCounter{mem: AppLockPINMaxAttempts}
	if dataDir != "" {
		c.path = filepath.Join(dataDir, appLockAttemptsSubdir, appLockAttemptsFileName)
	}
	return c
}

// load returns the persisted remaining count, defaulting to the full
// budget when nothing has been recorded yet -- a fresh install, or PIN
// state that predates this counter. The caller must hold mu.
func (c *appLockAttemptCounter) load() (int, error) {
	if c.path == "" {
		return c.mem, nil
	}

	data, err := os.ReadFile(c.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return AppLockPINMaxAttempts, nil
		}
		return 0, &AppLockAttemptsLoadError{Path: c.path, Cause: err}
	}

	var rec appLockAttemptsRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return 0, &AppLockAttemptsLoadError{Path: c.path, Cause: err}
	}
	if rec.Remaining < 0 || rec.Remaining > AppLockPINMaxAttempts {
		return 0, &AppLockAttemptsLoadError{
			Path:  c.path,
			Cause: fmt.Errorf("remaining count %d is out of range [0,%d]", rec.Remaining, AppLockPINMaxAttempts),
		}
	}
	return rec.Remaining, nil
}

// save persists remaining atomically (temp file, then rename) with 0600
// permissions, deliberately outside the barrier's own encrypted storage so
// it stays readable and writable while the barrier is sealed. The caller
// must hold mu.
func (c *appLockAttemptCounter) save(remaining int) error {
	if c.path == "" {
		c.mem = remaining
		return nil
	}

	if err := os.MkdirAll(filepath.Dir(c.path), 0700); err != nil {
		return &AppLockAttemptsSaveError{Path: c.path, Cause: err}
	}

	data, err := json.Marshal(appLockAttemptsRecord{Remaining: remaining})
	if err != nil {
		return &AppLockAttemptsSaveError{Path: c.path, Cause: err}
	}

	tmpPath := c.path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0600); err != nil {
		return &AppLockAttemptsSaveError{Path: c.path, Cause: err}
	}
	if err := os.Rename(tmpPath, c.path); err != nil {
		return &AppLockAttemptsSaveError{Path: c.path, Cause: err}
	}
	return nil
}

// blocked reports whether the budget is exhausted, along with the current
// remaining count, without consuming an attempt.
func (c *appLockAttemptCounter) blocked() (bool, int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	remaining, err := c.load()
	if err != nil {
		return false, 0, err
	}
	return remaining <= 0, remaining, nil
}

// recordFailure consumes one attempt after a real credential rejection and
// returns the attempts left afterward. It never goes negative: a failure
// recorded against an already-exhausted budget leaves it at zero.
func (c *appLockAttemptCounter) recordFailure() (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	remaining, err := c.load()
	if err != nil {
		return 0, err
	}
	if remaining > 0 {
		remaining--
	}
	if err := c.save(remaining); err != nil {
		return 0, err
	}
	return remaining, nil
}

// recordSuccess resets the budget to AppLockPINMaxAttempts, on either a
// correct credential (Unlock) or an SO-PIN-authorized reset
// (AppLockService.ResetAttempts, ResetAppLockAttempts).
func (c *appLockAttemptCounter) recordSuccess() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.save(AppLockPINMaxAttempts)
}

// ResetAppLockAttempts clears the app lock's own unlock-attempt budget
// persisted at <dataDir>/pin/unlock_attempts, independent of any running
// AppLockService instance.
//
// It exists for out-of-process resets: "xkey pin reset-lockout" and
// "xkey pin set-user" run in a separate process from the daemon whose
// AppLockService holds the live counter, so a successful SO-PIN
// verification there can only reach the persisted budget through this same
// file -- not through AppLockService.ResetAttempts, which only affects the
// calling process's own copy.
func ResetAppLockAttempts(dataDir string) error {
	return newAppLockAttemptCounter(dataDir).recordSuccess()
}
