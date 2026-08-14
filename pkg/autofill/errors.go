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

package autofill

import "errors"

// This package supplies the autofill primitives — policy validation, domain
// matching, rate limiting and assertion verification — and reports policy
// outcomes as booleans (AutoFillPolicy.IsDomainAllowed, RateLimiter.Allow).
// Turning a denied outcome into an error is the calling service's job, and the
// deny vocabulary lives there with it (xkey's AutoFillService owns
// ErrAutoFillDomainBlocked, ErrAutoFillRateLimit, ErrAutoFillAppLocked and
// friends). Only the errors this package actually returns belong here.
var (
	ErrInvalidFillMode       = errors.New("autofill: invalid fill mode")
	ErrInvalidTOTPPolicy     = errors.New("autofill: invalid TOTP policy")
	ErrInvalidSessionTimeout = errors.New("autofill: session timeout must be non-negative")
	ErrInvalidMaxFills       = errors.New("autofill: max fills per minute must be non-negative")
	ErrRateLimitExceeded     = errors.New("autofill: rate limit exceeded")
	ErrAuthenticationFailed  = errors.New("autofill: CTAP2 authentication failed")
)
