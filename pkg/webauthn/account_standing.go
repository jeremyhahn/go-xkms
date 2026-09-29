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

package webauthn

import (
	"github.com/jeremyhahn/go-xkms/pkg/auth"
)

// CheckAccountStanding reports whether user's account may authenticate with
// a passkey: its lifecycle must be one that can authenticate (only
// qrdbsdk.LifecycleActive can) and its permitted-auth-method policy must
// allow auth.MethodWebAuthn. It returns *AccountNotActiveError or
// *auth.AuthMethodNotPermittedError when it may not.
//
// The Service applies it at every login begin and finish, and callers that
// scope a ceremony to an account themselves (the qrdb factor adapter) apply
// it before doing so. The detail it returns is for the operator: the Service
// never lets it reach a client, because a refusal must not reveal the
// account's state (go-xkms#1298).
func CheckAccountStanding(user User) error {
	if err := checkLifecycle(user); err != nil {
		return err
	}
	return auth.CheckAuthMethod(user.WebAuthnName(), "", user.AuthMethods(), auth.MethodWebAuthn)
}

// checkLifecycle refuses an account whose lifecycle state cannot
// authenticate. It fails closed: an empty or unrecognized state is refused.
func checkLifecycle(user User) error {
	if state := user.Lifecycle(); !state.CanAuthenticate() {
		return &AccountNotActiveError{Account: user.WebAuthnName(), Lifecycle: string(state)}
	}
	return nil
}
