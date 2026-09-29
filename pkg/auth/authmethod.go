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

package auth

import qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

// MethodWebAuthn is the name the WebAuthn relying party (pkg/webauthn)
// authenticates as, and therefore the token an account's permitted-method
// policy must spell to allow a passkey login. qrdb stores policy entries
// normalized, so this is the lowercase form qrdb's NormalizeAuthMethods
// produces.
const MethodWebAuthn = "webauthn"

// CheckAuthMethod enforces an account's permitted-authentication-method
// policy (qrdb User.AuthMethods) against the method that authenticated the
// request. username and tenantID identify the account in the refusal only.
// It applies go-qrdb's auth/middleware checkAuthMethod contract exactly:
//
//   - An EMPTY policy states no restriction and permits every method, so an
//     account written before the field existed keeps working.
//   - The method name is normalized with qrdb's own NormalizeAuthMethods — the
//     normalization the store applied when the policy was written — and
//     compared against the stored entries as they are.
//   - A method whose name does not survive normalization (blank, whitespace)
//     matches nothing and is refused: this is an authentication gate and
//     fails closed.
//
// qrdb's unobservable-method bypass has no counterpart here: every caller
// observed the method it passes. A refusal is an
// *AuthMethodNotPermittedError.
func CheckAuthMethod(username, tenantID string, permitted []string, method string) error {
	if len(permitted) == 0 {
		return nil
	}
	refuse := func(name string) error {
		return &AuthMethodNotPermittedError{
			Username:  username,
			TenantID:  tenantID,
			Method:    name,
			Permitted: permitted,
		}
	}
	normalized, err := qrdbsdk.NormalizeAuthMethods([]string{method})
	if err != nil || len(normalized) == 0 {
		return refuse(method)
	}
	for _, p := range permitted {
		if p == normalized[0] {
			return nil
		}
	}
	return refuse(normalized[0])
}
