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

package cmd

import (
	"errors"
	"fmt"
)

// Provision command sentinel errors. These name conditions the operator (or
// a script) must fix before "xkey provision" can run at all: a missing
// --agent name, a home that was neither named nor inherited from XKEY_HOME,
// an already-initialized home given without --force, and any of the three
// required secrets (user PIN, SO PIN, barrier password) that never arrived.
var (
	// ErrProvisionAgentNameRequired indicates --agent was not given.
	ErrProvisionAgentNameRequired = errors.New("provision: --agent is required")

	// ErrProvisionHomeRequired indicates neither --home nor XKEY_HOME named
	// a target. Provisioning refuses to guess: falling back to xhome's
	// normal default-home resolution would provision into the operator's
	// own ~/.xkey by accident, exactly the failure this command exists to
	// prevent on a shared host running one xkey instance per agent.
	ErrProvisionHomeRequired = errors.New("provision: --home or XKEY_HOME is required (refusing to guess the operator's own default home)")

	// ErrProvisionAlreadyInitialized indicates the target home already has a
	// barrier root key and --force was not given.
	ErrProvisionAlreadyInitialized = errors.New("provision: this home is already initialized; pass --force to provision it again")

	// ErrProvisionUserPINRequired indicates no user PIN was supplied. It
	// becomes the host PIN service's User PIN (and, through the service's own
	// FIDO2 hash propagation, the FIDO2 authenticator's CTAP2 user PIN); it is
	// never reused as the SO PIN or the barrier password.
	ErrProvisionUserPINRequired = errors.New("provision: a user PIN is required (--pin-stdin or XKEY_PIN)")

	// ErrProvisionSOPINRequired indicates no SO PIN was supplied. It becomes
	// both the host PIN service's SO PIN and the FIDO2 authenticator's own,
	// separate Security Officer PIN -- two credentials that already share
	// that name without sharing a store (see pin_set.go and
	// fido2_init_token.go). It is never reused as the user PIN or the
	// barrier password: doing so would erase the SO/user separation the host
	// PIN service exists to enforce.
	ErrProvisionSOPINRequired = errors.New("provision: an SO PIN is required (--so-pin-stdin or XKEY_SO_PIN)")

	// ErrProvisionBarrierPasswordRequired indicates no barrier password was
	// supplied through any of resolveBarrierPassword's sources
	// (--barrier-password, --barrier-password-file, XKEY_BARRIER_PASSWORD, or
	// an interactive terminal prompt). It is never reused from the user PIN
	// or the SO PIN.
	ErrProvisionBarrierPasswordRequired = errors.New("provision: a barrier password is required (--barrier-password, --barrier-password-file, or XKEY_BARRIER_PASSWORD)")

	// ErrProvisionConfigNotLoaded indicates the unified xkey config was not
	// loaded for the resolved home. This should not happen once
	// PersistentPreRunE has run; it is reported rather than assumed away.
	ErrProvisionConfigNotLoaded = errors.New("provision: xkey configuration not loaded")

	// ErrProvisionHomeNotResolved indicates GetHome() returned nil after
	// PersistentPreRunE ran. Reported rather than assumed away for the same
	// reason as ErrProvisionConfigNotLoaded.
	ErrProvisionHomeNotResolved = errors.New("provision: xkey home not resolved")
)

// ProvisionError wraps a failure at one named provisioning step (ssh,
// barrier, pin, display_name, fido2, piv, chrome_extension) with its cause.
// The step name lets an operator or script see exactly how far provisioning
// got before something needed reads: "the PIV setup failed" and "the SSH
// keygen failed" call for different fixes.
type ProvisionError struct {
	Step string
	Err  error
}

// Error implements the error interface.
func (e *ProvisionError) Error() string {
	return fmt.Sprintf("provision: %s: %v", e.Step, e.Err)
}

// Unwrap returns the underlying cause.
func (e *ProvisionError) Unwrap() error {
	return e.Err
}
