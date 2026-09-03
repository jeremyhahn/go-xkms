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

package xkms

import "github.com/jeremyhahn/go-xkms/pkg/autofill"

// Browser-extension autofill surface re-exported so the xkey extension server
// reaches the canonical pkg/autofill policy, domain matcher, rate limiter and
// WebAuthn assertion verifier through the SDK.

// AutoFillPolicy governs when and how credentials are auto-filled.
type AutoFillPolicy = autofill.AutoFillPolicy

// AssertionVerifier verifies WebAuthn assertions produced during autofill.
type AssertionVerifier = autofill.AssertionVerifier

// AutoFillVerifierOptions relaxes individual AssertionVerifier checks. Its zero
// value is the strict posture; see autofill.VerifierOptions before setting any
// field, because each one loosens verification.
type AutoFillVerifierOptions = autofill.VerifierOptions

// AutoFillRateLimiter throttles autofill requests per origin.
type AutoFillRateLimiter = autofill.RateLimiter

const (
	// FillModeAutoFill fills credentials without explicit user click.
	FillModeAutoFill = autofill.FillModeAutoFill
	// FillModeClickToFill requires a user click before filling.
	FillModeClickToFill = autofill.FillModeClickToFill
	// TOTPPolicyPrompt prompts the user before revealing a TOTP code.
	TOTPPolicyPrompt = autofill.TOTPPolicyPrompt
)

// DefaultAutoFillPolicy returns the default autofill policy.
var DefaultAutoFillPolicy = autofill.DefaultPolicy

// AutoFillMatchesEntry reports whether a page domain matches a stored entry's
// URL and match patterns.
var AutoFillMatchesEntry = autofill.MatchesEntry

// NewAssertionVerifier constructs a WebAuthn assertion verifier for the given
// relying-party ID and COSE public key. It requires both user presence and
// user verification.
var NewAssertionVerifier = autofill.NewAssertionVerifier

// NewAssertionVerifierWithOptions constructs a WebAuthn assertion verifier that
// relaxes the checks named by the options. Only for a ceremony whose relaxed
// flag could not have been a genuine signal — see AutoFillVerifierOptions.
var NewAssertionVerifierWithOptions = autofill.NewAssertionVerifierWithOptions

// NewAutoFillRateLimiter constructs an autofill rate limiter.
var NewAutoFillRateLimiter = autofill.NewRateLimiter
