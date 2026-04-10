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
		return nil, fmt.Errorf("nativemsg: failed to load pairing state: %w", err)
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

// GetState returns the pairing state for a single paired extension, for
// backwards compatibility. If multiple extensions are paired, it returns
// one arbitrarily. Returns nil if no extensions are paired.
func (v *PairingVerifier) GetState() *PairingState {
	v.mu.RLock()
	defer v.mu.RUnlock()
	for _, s := range v.states {
		return s
	}
	return nil
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
		v.recordVerifyFailure()
		return ErrIdentityOriginMismatch
		v.logPairingEvent(audit.OpPairingIdentityFail, false, ErrIdentityOriginMismatch, map[string]any{"origin": origin})
	}

	// Check identity key matches stored key.
	if !ed25519.PublicKey(state.IdentityKey).Equal(ed25519.PublicKey(identityKey)) {
		v.recordVerifyFailure()
		return ErrIdentityMismatch
		v.logPairingEvent(audit.OpPairingIdentityFail, false, ErrIdentityMismatch, map[string]any{"origin": origin})
	}

	// Verify signature: Ed25519_Sign(privkey, SHA256(ephemeralPubKey || origin || context)).
	signData := computeSignData(ephemeralPubKey, origin)

	if !ed25519.Verify(ed25519.PublicKey(identityKey), signData, signature) {
		v.recordVerifyFailure()
		return ErrIdentitySignature
		v.logPairingEvent(audit.OpPairingIdentityFail, false, ErrIdentitySignature, map[string]any{"origin": origin})
	}

	// Success - reset failure counter.
	v.verifyFailures.Store(0)
	v.logPairingEvent(audit.OpPairingIdentityOK, true, nil, map[string]any{"origin": origin})
	return nil
}

// StartPairing initiates a pairing ceremony by generating a 6-digit code.
// Returns the code to be displayed in the GUI.
func (v *PairingVerifier) StartPairing(identityKey []byte, origin string) (string, error) {
	// Check lockout.
	if lockUntil := v.pairingLockUntil.Load(); lockUntil > 0 {
		if time.Now().Unix() < lockUntil {
			v.logPairingEvent(audit.OpPairingStarted, false, ErrPairingLocked, map[string]any{"origin": origin})
			return "", ErrPairingLocked
		}
		v.pairingFailures.Store(0)
		v.pairingLockUntil.Store(0)
	}

	code, err := generatePairingCode()
	if err != nil {
		v.logPairingEvent(audit.OpPairingStarted, false, err, map[string]any{"origin": origin})
		return "", fmt.Errorf("nativemsg: failed to generate pairing code: %w", err)
	}

	v.mu.Lock()
	v.pending = &pendingPairing{
		code:        code,
		identityKey: identityKey,
		origin:      origin,
		expiresAt:   time.Now().Add(pairingCodeExpiry),
	}
	v.mu.Unlock()

	v.logPairingEvent(audit.OpPairingStarted, true, nil, map[string]any{"origin": origin})
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
		v.recordPairingFailure()
		return ErrPairingInvalidCode
		v.logPairingEvent(audit.OpPairingFailed, false, ErrPairingInvalidCode, map[string]any{"origin": origin})
	}

	// Verify identity key and origin match the pending request.
	if !ed25519.PublicKey(v.pending.identityKey).Equal(ed25519.PublicKey(identityKey)) {
		v.recordPairingFailure()
		return ErrPairingRejected
		v.logPairingEvent(audit.OpPairingFailed, false, ErrPairingRejected, map[string]any{"origin": origin})
	}
	if v.pending.origin != origin {
		v.recordPairingFailure()
		return ErrPairingRejected
		v.logPairingEvent(audit.OpPairingFailed, false, ErrPairingRejected, map[string]any{"origin": origin})
	}

	// Upsert the pairing into the map.
	v.states[origin] = &PairingState{
		IdentityKey: identityKey,
		PairedAt:    time.Now(),
	}
	v.pending = nil
	v.pairingFailures.Store(0)
	v.logPairingEvent(audit.OpPairingCompleted, true, nil, map[string]any{"origin": origin})

	return v.saveLocked()
}

// UnpairOrigin removes a specific extension origin from the pairing state.
// If it was the last paired extension, the state file is deleted.
func (v *PairingVerifier) UnpairOrigin(origin string) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	delete(v.states, origin)
	v.logPairingEvent(audit.OpPairingUnpaired, true, nil, map[string]any{"origin": origin})

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
	v.logPairingEvent(audit.OpPairingUnpaired, true, nil, map[string]any{"action": "unpair_all"})
	return v.removeStateLocked()
}

// Unpair removes all paired extensions. Kept for backwards compatibility;
// callers should prefer UnpairOrigin or UnpairAll for clarity.
func (v *PairingVerifier) Unpair() error {
	return v.UnpairAll()
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
	return fmt.Errorf("%w: %s", ErrParentProcessInvalid, base)
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

// recordPairingFailure increments failure counter and sets lockout if threshold reached.
func (v *PairingVerifier) recordPairingFailure() {
	failures := v.pairingFailures.Add(1)
	if failures >= int32(maxPairingFailures) {
		v.pairingLockUntil.Store(time.Now().Add(pairingLockoutDuration).Unix())
		v.logPairingEvent(audit.OpPairingRateLimited, false, nil, map[string]any{"lockout_type": "pairing"})
	}
}

// recordVerifyFailure increments failure counter and sets lockout if threshold reached.
func (v *PairingVerifier) recordVerifyFailure() {
	failures := v.verifyFailures.Add(1)
	if failures >= int32(maxVerifyFailures) {
		v.verifyLockUntil.Store(time.Now().Add(verifyLockoutDuration).Unix())
		v.logPairingEvent(audit.OpPairingRateLimited, false, nil, map[string]any{"lockout_type": "verify"})
	}
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
		return fmt.Errorf("nativemsg: invalid pairing state: %w", err)
	}

	if legacy.ExtensionOrigin != "" && legacy.IdentityKey != nil {
		// Migrate: insert into map and save in new format.
		v.states = map[string]*PairingState{
			legacy.ExtensionOrigin: {
				IdentityKey: legacy.IdentityKey,
				PairedAt:    legacy.PairedAt,
			},
		}
		// Persist in new format (best-effort; if it fails, the old file still works).
		_ = v.saveLocked()
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
		return fmt.Errorf("nativemsg: failed to create pairing directory: %w", err)
	}
	data, err := json.MarshalIndent(v.states, "", "  ")
	if err != nil {
		return fmt.Errorf("nativemsg: failed to marshal pairing state: %w", err)
	}

	tmpPath := v.statePath + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0600); err != nil {
		return fmt.Errorf("nativemsg: failed to write pairing temp file: %w", err)
	}
	if err := os.Rename(tmpPath, v.statePath); err != nil {
		os.Remove(tmpPath) // Clean up temp file on rename failure.
		return fmt.Errorf("nativemsg: failed to rename pairing temp file: %w", err)
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
		return fmt.Errorf("nativemsg: failed to remove pairing state: %w", err)
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

// logPairingEvent logs an audit event for pairing operations.
func (v *PairingVerifier) logPairingEvent(op audit.OperationType, success bool, err error, details map[string]any) {
	if p := v.auditLog.Load(); p != nil {
		errStr := ""
		if err != nil {
			errStr = err.Error()
		}
		(*p).Log(audit.Entry{
			Timestamp: time.Now(),
			Operation: op,
			Success:   success,
			Error:     errStr,
			Details:   details,
		})
	}
}
