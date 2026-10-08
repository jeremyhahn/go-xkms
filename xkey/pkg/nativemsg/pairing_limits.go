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

package nativemsg

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jeremyhahn/go-xkms/sdk/go/fsutil"
)

// pairingLimitsSuffix names the rate-limit file beside the pairing state
// file: "pairing.json" keeps its limits in "pairing-limits.json".
const pairingLimitsSuffix = "-limits.json"

// rateLimit is one durable failure counter and its lockout deadline.
type rateLimit struct {
	// Failures counts consecutive failures since the last success or
	// expired lockout.
	Failures int32 `json:"failures"`

	// LockUntil is the Unix time the lockout ends; zero when not locked.
	LockUntil int64 `json:"lock_until"`
}

// pairingLimits is the rate-limit state for pairing codes and identity
// verification. It is persisted beside the pairing state rather than held in
// memory because the browser launches a fresh native host for every
// connection: an in-memory counter would reset on each relaunch and bound
// nothing.
//
// It lives in its own file, not in the pairing state, so unpairing — which
// deletes the pairing state — cannot clear a lockout.
type pairingLimits struct {
	Pairing rateLimit `json:"pairing"`
	Verify  rateLimit `json:"verify"`
}

// limitSelector picks one of the two counters in pairingLimits.
type limitSelector func(*pairingLimits) *rateLimit

// pairingLimit selects the pairing-code counter.
func pairingLimit(l *pairingLimits) *rateLimit { return &l.Pairing }

// verifyLimit selects the identity-verification counter.
func verifyLimit(l *pairingLimits) *rateLimit { return &l.Verify }

// limitsPathFor derives the rate-limit file path from the pairing state path.
func limitsPathFor(statePath string) string {
	return strings.TrimSuffix(statePath, filepath.Ext(statePath)) + pairingLimitsSuffix
}

// lockedOut reports whether sel's lockout is in force. An expired lockout is
// cleared, together with its failure count, and the clearing is persisted.
func (v *PairingVerifier) lockedOut(sel limitSelector) (bool, error) {
	locked := false
	err := v.updateLimits(func(l *pairingLimits) bool {
		r := sel(l)
		if r.LockUntil == 0 {
			return false
		}
		if time.Now().Unix() < r.LockUntil {
			locked = true
			return false
		}
		*r = rateLimit{}
		return true
	})
	return locked, err
}

// recordLimitFailure durably counts one failure against sel and, once
// maxFailures is reached, starts a lockout of lockout. It reports whether this
// failure started the lockout.
func (v *PairingVerifier) recordLimitFailure(sel limitSelector, maxFailures int32, lockout time.Duration) (bool, error) {
	started := false
	err := v.updateLimits(func(l *pairingLimits) bool {
		r := sel(l)
		r.Failures++
		if r.Failures >= maxFailures {
			r.LockUntil = time.Now().Add(lockout).Unix()
			started = true
		}
		return true
	})
	return started, err
}

// resetLimit durably clears sel's failure count after a success.
func (v *PairingVerifier) resetLimit(sel limitSelector) error {
	return v.updateLimits(func(l *pairingLimits) bool {
		r := sel(l)
		if r.Failures == 0 {
			return false
		}
		r.Failures = 0
		return true
	})
}

// updateLimits reads the rate-limit file, applies fn, and writes the result
// back when fn reports a change. The file is re-read on every call because
// the GUI and every native host instance share it.
//
// An unreadable or corrupt file fails the operation closed: guessing a zero
// count would hand an attacker a fresh budget.
func (v *PairingVerifier) updateLimits(fn func(*pairingLimits) bool) error {
	v.limitsMu.Lock()
	defer v.limitsMu.Unlock()

	var limits pairingLimits
	data, err := os.ReadFile(v.limitsPath)
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return &WrappedError{Msg: "nativemsg: failed to read pairing rate-limit state", Err: err}
	default:
		if err := json.Unmarshal(data, &limits); err != nil {
			return &WrappedError{Msg: "nativemsg: invalid pairing rate-limit state", Err: err}
		}
	}

	if !fn(&limits) {
		return nil
	}

	data, err = json.Marshal(limits)
	if err != nil {
		return &WrappedError{Msg: "nativemsg: failed to marshal pairing rate-limit state", Err: err}
	}
	return writeFileAtomic(v.limitsPath, data)
}

// writeFileAtomic writes data to path with 0600 permissions through a temp
// file and rename, creating the parent directory with 0700 if needed, so a
// crash never leaves a truncated file behind.
func writeFileAtomic(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return &WrappedError{Msg: "nativemsg: failed to create pairing directory", Err: err}
	}

	if err := fsutil.WriteFileAtomic(path, data, 0600); err != nil {
		return &WrappedError{Msg: "nativemsg: failed to write pairing temp file", Err: err}
	}
	return nil
}
