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

package authenticator

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/jeremyhahn/go-enclave"
)

// Token lifecycle.
//
// xKey's Security Officer / User split is the PKCS#11 role model, not a FIDO2
// one: CTAP 2.1 defines a single user PIN and has no Security Officer. Two
// specifications therefore govern two halves of this file.
//
//   - PKCS#11 v3.0 §5.6 (C_InitToken / C_InitPIN / C_SetPIN) governs when the
//     SO credential is established and how it changes. A token is
//     *uninitialized* until C_InitToken; before that it refuses operational
//     use, and afterwards the SO PIN changes only by authenticating as SO.
//   - CTAP 2.1 §6.9 (authenticatorReset) governs the trust-on-first-use
//     window. The first SO PIN cannot be authenticated against anything, so
//     §6.9's own two bounds are applied to it: the operation is accepted only
//     within a short window after power-up, and it requires user presence.
//
// There is exactly one source of truth for "is this token initialized":
// state.SOPINManager.IsSet. Initialization *is* establishing the SO PIN, so a
// second boolean would only be a second thing to disagree.

// DefaultTokenInitWindow bounds the trust-on-first-use window for the first SO
// PIN. CTAP 2.1 §6.9 requires authenticatorReset to be refused when it arrives
// "more than 10 seconds after power-up"; the same bound is applied to first
// initialization, which has the same unauthenticated-by-necessity shape.
const DefaultTokenInitWindow = 10 * time.Second

// tokenInitOperation is the operation name shown to the user when presence is
// requested for token initialization.
const tokenInitOperation = "initialize"

// Token lifecycle errors.
var (
	// ErrTokenUninitialized indicates the token has no Security Officer
	// credential, so SO-gated operations are refused. This is distinct from
	// ErrKeyManagerLocked, which means an SO exists but has not authenticated.
	ErrTokenUninitialized = errors.New("authenticator: token uninitialized")

	// ErrTokenInitWindowClosed indicates first initialization arrived outside
	// the post-power-up window. See CTAP 2.1 §6.9.
	ErrTokenInitWindowClosed = errors.New("authenticator: token initialization window closed")
)

// TokenFlags mirrors the PKCS#11 v3.0 CK_TOKEN_INFO flags that describe the
// Security Officer credential's lifecycle state, so a caller sees the same
// state a PKCS#11 application would.
type TokenFlags uint32

const (
	// TokenFlagInitialized corresponds to CKF_TOKEN_INITIALIZED: the token has
	// been initialized and has a Security Officer PIN.
	TokenFlagInitialized TokenFlags = 1 << iota

	// TokenFlagSOPINCountLow corresponds to CKF_SO_PIN_COUNT_LOW: an incorrect
	// SO PIN has been supplied at least once since the last success.
	TokenFlagSOPINCountLow

	// TokenFlagSOPINFinalTry corresponds to CKF_SO_PIN_FINAL_TRY: one more
	// incorrect SO PIN will lock the token out.
	TokenFlagSOPINFinalTry

	// TokenFlagSOPINLocked corresponds to CKF_SO_PIN_LOCKED: the SO PIN retry
	// budget is exhausted and the SO role is unreachable.
	TokenFlagSOPINLocked
)

// String renders the flags for operators and logs. An uninitialized token
// renders as "uninitialized" rather than as an empty flag set, because
// "no flags" and "no Security Officer required" must never read alike.
func (f TokenFlags) String() string {
	if f&TokenFlagInitialized == 0 {
		return "uninitialized"
	}

	parts := []string{"initialized"}
	if f&TokenFlagSOPINCountLow != 0 {
		parts = append(parts, "so-pin-count-low")
	}
	if f&TokenFlagSOPINFinalTry != 0 {
		parts = append(parts, "so-pin-final-try")
	}
	if f&TokenFlagSOPINLocked != 0 {
		parts = append(parts, "so-pin-locked")
	}
	return strings.Join(parts, "|")
}

// IsTokenInitialized reports whether the token has a Security Officer PIN.
func (a *Authenticator) IsTokenInitialized() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.state != nil && a.state.SOPINManager != nil && a.state.SOPINManager.IsSet
}

// TokenFlags reports the PKCS#11-equivalent lifecycle state of the token's
// Security Officer credential.
func (a *Authenticator) TokenFlags() TokenFlags {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return tokenFlags(a.state)
}

// tokenFlags derives the token flags from state. The caller holds a.mu.
func tokenFlags(state *AuthenticatorState) TokenFlags {
	if state == nil || state.SOPINManager == nil || !state.SOPINManager.IsSet {
		return 0
	}

	flags := TokenFlagInitialized
	switch retries := state.SOPINManager.Retries(); {
	case retries <= 0:
		flags |= TokenFlagSOPINCountLow | TokenFlagSOPINFinalTry | TokenFlagSOPINLocked
	case retries == 1:
		flags |= TokenFlagSOPINCountLow | TokenFlagSOPINFinalTry
	case retries < DefaultSOPINMaxRetries:
		flags |= TokenFlagSOPINCountLow
	}
	return flags
}

// tokenInitWindowOpen reports whether the post-power-up initialization window
// is still open. CTAP 2.1 §6.9.
func (a *Authenticator) tokenInitWindowOpen() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return time.Since(a.poweredUpAt) <= a.config.TokenInitWindow
}

// rearmTokenInitWindow reopens the initialization window. Only a completed
// authenticatorReset does this: reset already required user presence, and on an
// initialized token it also required SO authentication, so re-arming grants
// nothing the caller had not already proven. Without it a reset would leave the
// token uninitialized but un-initializable until the next restart.
func (a *Authenticator) rearmTokenInitWindow() {
	a.poweredUpAt = time.Now()
}

// InitializeToken establishes the token's Security Officer PIN and marks the
// token initialized. This is xKey's C_InitToken (PKCS#11 v3.0 §5.6).
//
// The first SO PIN cannot be authenticated against anything that exists yet, so
// it is bounded exactly as CTAP 2.1 §6.9 bounds authenticatorReset:
//
//   - it is accepted only within Config.TokenInitWindow of power-up, and
//   - it requires user presence.
//
// After initialization the SO PIN changes only through ChangeSOPIN, which
// requires the current SO PIN. authenticatorReset is the only way back to the
// uninitialized state.
//
// Returns ErrKeyManagerAlreadyInitialized if the token is already initialized,
// ErrTokenInitWindowClosed outside the window, ErrUserPresenceRequired if the
// user does not confirm, and ErrSOPINPolicyViolation if the PIN is malformed.
func (a *Authenticator) InitializeToken(ctx context.Context, soPIN string) error {
	if a.keyManager == nil {
		return ErrKeyManagerNoSOPIN
	}
	if a.IsTokenInitialized() {
		return ErrKeyManagerAlreadyInitialized
	}
	if err := validateSOPINPolicy(soPIN); err != nil {
		return err
	}
	if !a.tokenInitWindowOpen() {
		return ErrTokenInitWindowClosed
	}

	// User presence is collected before the state lock is taken: the handler
	// may block on a human, and holding a.mu across that would stall every
	// other command.
	if err := a.requestUserPresence(ctx, "", "", "", tokenInitOperation); err != nil {
		return err
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	// Re-check under the lock. Two concurrent initializations would otherwise
	// race between the check above and the write below; InitializeSOPIN is the
	// authoritative guard.
	if err := a.keyManager.InitializeSOPIN(soPIN); err != nil {
		return err
	}

	if err := a.storage.SaveState(a.state); err != nil {
		return ErrStorageError
	}
	return nil
}

// ChangeSOPIN replaces the Security Officer PIN. The current SO PIN is proven
// by authenticated decryption of the wrapped Admin Key, so the SO PIN can be
// changed only by whoever already holds it (PKCS#11 v3.0 C_SetPIN as SO).
//
// A failed attempt spends one retry from the budget and that spend is
// persisted, so a restart cannot be used to reset the counter.
func (a *Authenticator) ChangeSOPIN(ctx context.Context, currentPIN, newPIN string) error {
	if a.keyManager == nil {
		return ErrKeyManagerNoSOPIN
	}
	if !a.IsTokenInitialized() {
		return ErrTokenUninitialized
	}

	// Reject a malformed new PIN before spending a retry: an operator's typo in
	// the *new* PIN is not a failed authentication attempt.
	if err := validateSOPINPolicy(newPIN); err != nil {
		return err
	}

	manager := a.state.SOPINManager
	currentSMK, err := manager.BeginVerify(currentPIN)
	if err != nil {
		return err
	}
	defer enclave.Wipe(currentSMK)

	changeErr := a.keyManager.ChangeSOPIN(currentSMK, newPIN)

	// The retry budget moved whether or not the change succeeded, so it is
	// persisted either way.
	if saveErr := a.saveState(); saveErr != nil && changeErr == nil {
		return saveErr
	}
	return changeErr
}

// UnlockSO authenticates as Security Officer, making the SO key hierarchy
// available to SO-gated operations until Lock is called.
//
// A failed attempt spends one retry and the spend is persisted.
func (a *Authenticator) UnlockSO(ctx context.Context, pin string) error {
	if a.keyManager == nil {
		return ErrKeyManagerNoSOPIN
	}
	if !a.IsTokenInitialized() {
		return ErrTokenUninitialized
	}

	unlockErr := a.keyManager.UnlockWithSOPIN(pin)

	if saveErr := a.saveState(); saveErr != nil && unlockErr == nil {
		return saveErr
	}
	return unlockErr
}

// requireSOUnlocked is the gate for every SO-only operation. It distinguishes
// the two refusals that used to look identical: a token with no Security
// Officer at all, and a Security Officer who has not authenticated.
//
// It never permits. A token without an SO credential cannot satisfy an
// SO-gated operation, so "no SO PIN set" refuses rather than waives.
func (a *Authenticator) requireSOUnlocked() error {
	if a.keyManager == nil || !a.IsTokenInitialized() {
		return ErrTokenUninitialized
	}
	if !a.keyManager.IsSOUnlocked() {
		return ErrKeyManagerLocked
	}
	return nil
}

// saveState persists the authenticator state under the state lock.
func (a *Authenticator) saveState() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.storage.SaveState(a.state); err != nil {
		return ErrStorageError
	}
	return nil
}
