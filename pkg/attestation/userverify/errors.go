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

package userverify

import "errors"

// User-verification decision errors.
var (
	// ErrVerificationFailed is the umbrella refusal for a verify-user answer
	// that could not be verified. The specific reason is joined to it.
	ErrVerificationFailed = errors.New("userverify: user verification refused")

	// ErrChallengeAnswered indicates a challenge that was already answered
	// once. A nonce is consumed by its first verification.
	ErrChallengeAnswered = errors.New("userverify: challenge already answered")

	// ErrChallengeExpired indicates an answer that arrived after
	// ChallengeLifetime.
	ErrChallengeExpired = errors.New("userverify: challenge expired")

	// ErrIncomplete indicates the decision was called without trust
	// material, an answer, or a well-formed challenge to judge it by.
	ErrIncomplete = errors.New("userverify: user verification has nothing to judge")

	// ErrNonceFailed indicates the system random source could not supply a
	// challenge nonce.
	ErrNonceFailed = errors.New("userverify: generate challenge nonce")
)
