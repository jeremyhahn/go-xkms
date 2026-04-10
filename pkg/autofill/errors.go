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

var (
	ErrInvalidFillMode        = errors.New("autofill: invalid fill mode")
	ErrInvalidTOTPPolicy      = errors.New("autofill: invalid TOTP policy")
	ErrInvalidSessionTimeout  = errors.New("autofill: session timeout must be non-negative")
	ErrInvalidMaxFills        = errors.New("autofill: max fills per minute must be non-negative")
	ErrDomainBlocked          = errors.New("autofill: domain is blocked by policy")
	ErrDomainNotAllowed       = errors.New("autofill: domain is not in allowed list")
	ErrRateLimitExceeded      = errors.New("autofill: rate limit exceeded")
	ErrAppLocked              = errors.New("autofill: application is locked")
	ErrExtensionDisabled      = errors.New("autofill: browser extension is disabled")
	ErrAuditRequired          = errors.New("autofill: audit logging is required but not available")
	ErrAuthenticationRequired = errors.New("autofill: CTAP2 authentication required")
	ErrAuthenticationFailed   = errors.New("autofill: CTAP2 authentication failed")
	ErrChallengeRequired      = errors.New("autofill: challenge required for authentication")
)
