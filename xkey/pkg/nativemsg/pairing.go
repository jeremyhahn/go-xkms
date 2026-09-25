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
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/audit"
)

// Rate limiting constants.
const (
	maxPairingFailures     = 3
	pairingLockoutDuration = 15 * time.Minute
	maxVerifyFailures      = 5
	verifyLockoutDuration  = 5 * time.Minute
	pairingCodeExpiry      = 5 * time.Minute
	pairingCodeLength      = 6
	identitySignContext    = "xkey-ext-v1"
)

// PairingState represents a paired browser extension's identity.
type PairingState struct {
	IdentityKey []byte    `json:"identity_key"` // Ed25519 public key
	PairedAt    time.Time `json:"paired_at"`
}

// legacyPairingState is the old single-extension format used for migration.
type legacyPairingState struct {
	ExtensionOrigin string    `json:"extension_origin"`
	IdentityKey     []byte    `json:"identity_key"`
	PairedAt        time.Time `json:"paired_at"`
}

// pendingPairing holds the state of an in-progress pairing ceremony.
type pendingPairing struct {
	code        string
	identityKey []byte
	origin      string
	expiresAt   time.Time
}

// PairingVerifier manages extension identity verification and pairing ceremonies.
// It supports multiple simultaneously paired browser extensions, keyed by origin.
type PairingVerifier struct {
	statePath        string
	states           map[string]*PairingState // keyed by extension origin
	mu               sync.RWMutex
	pending          *pendingPairing
	pairingFailures  atomic.Int32
	pairingLockUntil atomic.Int64 // Unix timestamp
	verifyFailures   atomic.Int32
	verifyLockUntil  atomic.Int64 // Unix timestamp
	auditLog         atomic.Pointer[audit.Logger]
}

// NewPairingVerifier creates a PairingVerifier that stores state at the given path.
// If a pairing state file exists, it loads the existing state. Supports automatic
// migration from the legacy single-extension format.
func NewPairingVerifier(statePath string) (*PairingVerifier, error) {
	v := &PairingVerifier{
		statePath: statePath,
		states:    make(map[string]*PairingState),
	}
	if err := v.load(); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, &WrappedError{Msg: "nativemsg: failed to load pairing state", Err: err}
	}
	return v, nil
}

// IsPaired returns true if any extension identity is currently paired.
func (v *PairingVerifier) IsPaired() bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return len(v.states) > 0
}

// IsPairedForOrigin returns true if a specific extension origin is paired.
func (v *PairingVerifier) IsPairedForOrigin(origin string) bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	_, ok := v.states[origin]
	return ok
}

// GetStateForOrigin returns the pairing state for a specific origin.
func (v *PairingVerifier) GetStateForOrigin(origin string) *PairingState {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.states[origin]
}

// GetStates returns a copy of all paired extension states keyed by origin.
func (v *PairingVerifier) GetStates() map[string]*PairingState {
	v.mu.RLock()
	defer v.mu.RUnlock()
	result := make(map[string]*PairingState, len(v.states))
	for k, s := range v.states {
		cp := *s
		result[k] = &cp
	}
	return result
}

// VerifyIdentity verifies the extension's Ed25519 identity signature over the
// ephemeral X25519 public key and origin. The signature binds the identity to
// the current session, preventing replay attacks.
//
// signData = SHA-256(ephemeralPubKey || origin || identitySignContext)
func (v *PairingVerifier) VerifyIdentity(identityKey, signature, ephemeralPubKey []byte, origin string) error {
	// Check lockout.
	if lockUntil := v.verifyLockUntil.Load(); lockUntil > 0 {
		if time.Now().Unix() < lockUntil {
			return ErrIdentityLocked
		}
		// Lockout expired, reset.
		v.verifyFailures.Store(0)
		v.verifyLockUntil.Store(0)
	}

	v.mu.RLock()
	state, ok := v.states[origin]
	hasPairings := len(v.states) > 0
	v.mu.RUnlock()

	if !hasPairings {
		return ErrPairingRequired
	}

	if !ok {
		// Origin not in map — might be a new extension or mismatch.
		if auditErr := v.recordVerifyFailure(); auditErr != nil {
			return auditErr
		}
		if auditErr := v.logPairingEvent(audit.OpPairingIdentityFail, false, ErrIdentityOriginMismatch, map[string]any{"origin": origin}); auditErr != nil {
			return auditErr
		}
		return ErrIdentityOriginMismatch
	}

	// Check identity key matches stored key.
	if !ed25519.PublicKey(state.IdentityKey).Equal(ed25519.PublicKey(identityKey)) {
		if auditErr := v.recordVerifyFailure(); auditErr != nil {
			return auditErr
		}
		if auditErr := v.logPairingEvent(audit.OpPairingIdentityFail, false, ErrIdentityMismatch, map[string]any{"origin": origin}); auditErr != nil {
			return auditErr
		}
		return ErrIdentityMismatch
	}

	// Verify signature: Ed25519_Sign(privkey, SHA256(ephemeralPubKey || origin || context)).
	signData := computeSignData(ephemeralPubKey, origin)

	if !ed25519.Verify(ed25519.PublicKey(identityKey), signData, signature) {
		if auditErr := v.recordVerifyFailure(); auditErr != nil {
			return auditErr
		}
		if auditErr := v.logPairingEvent(audit.OpPairingIdentityFail, false, ErrIdentitySignature, map[string]any{"origin": origin}); auditErr != nil {
			return auditErr
		}
		return ErrIdentitySignature
	}

	// Success - reset failure counter.
	v.verifyFailures.Store(0)
	return v.logPairingEvent(audit.OpPairingIdentityOK, true, nil, map[string]any{"origin": origin})
}

// StartPairing initiates a pairing ceremony by generating a 6-digit code.
// Returns the code to be displayed in the GUI.
func (v *PairingVerifier) StartPairing(identityKey []byte, origin string) (string, error) {
	// Check lockout.
	if lockUntil := v.pairingLockUntil.Load(); lockUntil > 0 {
		if time.Now().Unix() < lockUntil {
			if auditErr := v.logPairingEvent(audit.OpPairingStarted, false, ErrPairingLocked, map[string]any{"origin": origin}); auditErr != nil {
				return "", auditErr
			}
			return "", ErrPairingLocked
		}
		v.pairingFailures.Store(0)
		v.pairingLockUntil.Store(0)
	}

	code, err := generatePairingCode()
	if err != nil {
		if auditErr := v.logPairingEvent(audit.OpPairingStarted, false, err, map[string]any{"origin": origin}); auditErr != nil {
			return "", auditErr
		}
		return "", &WrappedError{Msg: "nativemsg: failed to generate pairing code", Err: err}
	}

	v.mu.Lock()
	v.pending = &pendingPairing{
		code:        code,
		identityKey: identityKey,
		origin:      origin,
		expiresAt:   time.Now().Add(pairingCodeExpiry),
	}
	v.mu.Unlock()

	if auditErr := v.logPairingEvent(audit.OpPairingStarted, true, nil, map[string]any{"origin": origin}); auditErr != nil {
		return "", auditErr
	}
	return code, nil
}

// CompletePairing validates the pairing code and stores the extension identity.
// The origin is used as the map key; pairing the same origin again updates the
// existing entry (re-pair).
func (v *PairingVerifier) CompletePairing(identityKey []byte, origin, code string) error {
	// Check lockout.
	if lockUntil := v.pairingLockUntil.Load(); lockUntil > 0 {
		if time.Now().Unix() < lockUntil {
			return ErrPairingLocked
		}
		v.pairingFailures.Store(0)
		v.pairingLockUntil.Store(0)
	}

	v.mu.Lock()
	defer v.mu.Unlock()

	if v.pending == nil {
		return ErrPairingRejected
	}

	// Check expiry.
	if time.Now().After(v.pending.expiresAt) {
		v.pending = nil
		return ErrPairingExpired
	}

	// Verify code.
	if v.pending.code != code {
		if auditErr := v.recordPairingFailure(); auditErr != nil {
			return auditErr
		}
		if auditErr := v.logPairingEvent(audit.OpPairingFailed, false, ErrPairingInvalidCode, map[string]any{"origin": origin}); auditErr != nil {
			return auditErr
		}
		return ErrPairingInvalidCode
	}

	// Verify identity key and origin match the pending request.
	if !ed25519.PublicKey(v.pending.identityKey).Equal(ed25519.PublicKey(identityKey)) {
		if auditErr := v.recordPairingFailure(); auditErr != nil {
			return auditErr
		}
		if auditErr := v.logPairingEvent(audit.OpPairingFailed, false, ErrPairingRejected, map[string]any{"origin": origin}); auditErr != nil {
			return auditErr
		}
		return ErrPairingRejected
	}
	if v.pending.origin != origin {
		if auditErr := v.recordPairingFailure(); auditErr != nil {
			return auditErr
		}
		if auditErr := v.logPairingEvent(audit.OpPairingFailed, false, ErrPairingRejected, map[string]any{"origin": origin}); auditErr != nil {
			return auditErr
		}
		return ErrPairingRejected
	}

	// Upsert the pairing into the map.
	v.states[origin] = &PairingState{
		IdentityKey: identityKey,
		PairedAt:    time.Now(),
	}
	v.pending = nil
	v.pairingFailures.Store(0)
	if auditErr := v.logPairingEvent(audit.OpPairingCompleted, true, nil, map[string]any{"origin": origin}); auditErr != nil {
		return auditErr
	}

	return v.saveLocked()
}

// UnpairOrigin removes a specific extension origin from the pairing state.
// If it was the last paired extension, the state file is deleted.
func (v *PairingVerifier) UnpairOrigin(origin string) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	delete(v.states, origin)
	if auditErr := v.logPairingEvent(audit.OpPairingUnpaired, true, nil, map[string]any{"origin": origin}); auditErr != nil {
		return auditErr
	}

	if len(v.states) == 0 {
		return v.removeStateLocked()
	}
	return v.saveLocked()
}

// UnpairAll removes all paired extension identities and deletes the state file.
func (v *PairingVerifier) UnpairAll() error {
	v.mu.Lock()
	defer v.mu.Unlock()

	v.states = make(map[string]*PairingState)
	v.pending = nil
	if auditErr := v.logPairingEvent(audit.OpPairingUnpaired, true, nil, map[string]any{"action": "unpair_all"}); auditErr != nil {
		return auditErr
	}
	return v.removeStateLocked()
}

// Reload re-reads the pairing state from disk. This allows a running native
// host to detect when the GUI unpairs an extension by updating the state file.
func (v *PairingVerifier) Reload() error {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.loadLocked()
}

// VerifyParentProcess checks that the parent process is a supported browser.
// On Linux, reads /proc/$PPID/exe symlink and checks for known browser binaries.
func (v *PairingVerifier) VerifyParentProcess() error {
	ppid := os.Getppid()
	exePath, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", ppid))
	if err != nil {
		// Non-Linux or process not accessible - allow (defense in depth, not sole control).
		return nil
	}
	base := filepath.Base(exePath)
	for _, browser := range supportedBrowsers {
		if base == browser {
			return nil
		}
	}
	return &DetailError{Err: ErrParentProcessInvalid, Detail: fmt.Sprintf(": %s", base)}
}

// supportedBrowsers is the list of known browser binary names that are
// allowed to launch the native messaging host.
var supportedBrowsers = []string{
	"chrome",
	"chromium",
	"google-chrome",
	"google-chrome-stable",
	"chromium-browser",
	"brave-browser",
	"vivaldi-bin",
	"opera",
	"microsoft-edge",
	"firefox",
	"firefox-esr",
	"firefox-bin",
}

// recordPairingFailure increments failure counter and sets lockout if
// threshold reached. Callers must propagate a non-nil return: rate-limit
// lockout is a SeveritySecurity event and a failed write must fail the
// caller.
func (v *PairingVerifier) recordPairingFailure() error {
	failures := v.pairingFailures.Add(1)
	if failures >= int32(maxPairingFailures) {
		v.pairingLockUntil.Store(time.Now().Add(pairingLockoutDuration).Unix())
		return v.logPairingEvent(audit.OpPairingRateLimited, false, nil, map[string]any{"lockout_type": "pairing"})
	}
	return nil
}

// recordVerifyFailure increments failure counter and sets lockout if
// threshold reached. Callers must propagate a non-nil return: rate-limit
// lockout is a SeveritySecurity event and a failed write must fail the
// caller.
func (v *PairingVerifier) recordVerifyFailure() error {
	failures := v.verifyFailures.Add(1)
	if failures >= int32(maxVerifyFailures) {
		v.verifyLockUntil.Store(time.Now().Add(verifyLockoutDuration).Unix())
		return v.logPairingEvent(audit.OpPairingRateLimited, false, nil, map[string]any{"lockout_type": "verify"})
	}
	return nil
}

// load reads the pairing state from disk, handling both the new multi-browser
// map format and the legacy single-extension format.
func (v *PairingVerifier) load() error {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.loadLocked()
}

// loadLocked reads the pairing state from disk (caller must hold mu).
func (v *PairingVerifier) loadLocked() error {
	data, err := os.ReadFile(v.statePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			v.states = make(map[string]*PairingState)
		}
		return err
	}

	// Try the new map format first.
	newStates := make(map[string]*PairingState)
	if err := json.Unmarshal(data, &newStates); err == nil && len(newStates) > 0 {
		// Validate: the new format has origin keys, PairingState has no
		// ExtensionOrigin field. If any key looks like a valid origin, accept it.
		v.states = newStates
		return nil
	}

	// Try legacy single-object format with "extension_origin" key.
	var legacy legacyPairingState
	if err := json.Unmarshal(data, &legacy); err != nil {
		return &WrappedError{Msg: "nativemsg: invalid pairing state", Err: err}
	}

	if legacy.ExtensionOrigin != "" && legacy.IdentityKey != nil {
		// Migrate: insert into map and save in new format.
		v.states = map[string]*PairingState{
			legacy.ExtensionOrigin: {
				IdentityKey: legacy.IdentityKey,
				PairedAt:    legacy.PairedAt,
			},
		}
		// Persist in new format is best-effort: the in-memory state is
		// already migrated and valid, so a write failure here must not fail
		// the load — the legacy on-disk file still parses next time. The
		// failure is no longer silently dropped, though: it is audit-logged
		// so an operator can see the migration never landed on disk (the
		// process keeps re-migrating from the legacy file on every restart
		// until the underlying write failure is fixed). OpPairingStateMigrated
		// is a security event (#688): if the audit record of the failed write
		// cannot be persisted either, nothing would record the failure, so
		// the load fails closed with both errors.
		if err := v.saveLocked(); err != nil {
			if auditErr := v.logPairingEvent(audit.OpPairingStateMigrated, false, err,
				map[string]any{"origin": legacy.ExtensionOrigin}); auditErr != nil {
				return errors.Join(err, auditErr)
			}
		}
		return nil
	}

	// Empty or unrecognized — start fresh.
	v.states = make(map[string]*PairingState)
	return nil
}

// saveLocked writes the pairing state to disk atomically (caller must hold mu).
// Writes to a temp file first, then renames for crash-safety.
func (v *PairingVerifier) saveLocked() error {
	dir := filepath.Dir(v.statePath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return &WrappedError{Msg: "nativemsg: failed to create pairing directory", Err: err}
	}
	data, err := json.MarshalIndent(v.states, "", "  ")
	if err != nil {
		return &WrappedError{Msg: "nativemsg: failed to marshal pairing state", Err: err}
	}

	tmpPath := v.statePath + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0600); err != nil {
		return &WrappedError{Msg: "nativemsg: failed to write pairing temp file", Err: err}
	}
	if err := os.Rename(tmpPath, v.statePath); err != nil {
		// Clean up the temp file on rename failure; a failed removal is
		// joined in rather than dropped so a leaked temp file is visible.
		removeErr := os.Remove(tmpPath)
		return &WrappedError{Msg: "nativemsg: failed to rename pairing temp file", Err: errors.Join(err, removeErr)}
	}
	return nil
}

// save writes the pairing state to disk atomically.
func (v *PairingVerifier) save() error {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.saveLocked()
}

// removeStateLocked deletes the state file (caller must hold mu).
func (v *PairingVerifier) removeStateLocked() error {
	if err := os.Remove(v.statePath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return &WrappedError{Msg: "nativemsg: failed to remove pairing state", Err: err}
	}
	return nil
}

// computeSignData computes SHA-256(ephemeralPubKey || origin || identitySignContext).
func computeSignData(ephemeralPubKey []byte, origin string) []byte {
	h := sha256.New()
	h.Write(ephemeralPubKey)
	h.Write([]byte(origin))
	h.Write([]byte(identitySignContext))
	return h.Sum(nil)
}

// generatePairingCode generates a cryptographically random 6-digit code.
func generatePairingCode() (string, error) {
	max := new(big.Int).SetInt64(1000000) // 0-999999
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}

// SetAuditLogger sets the audit logger for the pairing verifier.
func (v *PairingVerifier) SetAuditLogger(l audit.Logger) {
	v.auditLog.Store(&l)
}

// logPairingEvent logs an audit event for pairing operations. Callers must
// propagate a non-nil return: op.Severity() (audit package) decides
// whether that failure is required to fail the caller.
func (v *PairingVerifier) logPairingEvent(op audit.OperationType, success bool, err error, details map[string]any) error {
	p := v.auditLog.Load()
	if p == nil {
		return nil
	}
	errStr := ""
	if err != nil {
		errStr = err.Error()
	}
	return (*p).Log(audit.Entry{
		Timestamp: time.Now(),
		Operation: op,
		Success:   success,
		Error:     errStr,
		Details:   details,
	})
}
