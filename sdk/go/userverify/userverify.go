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

// Package userverify is the SDK re-export of the on-demand user-verification
// decision (pkg/attestation/userverify, ruling 167). Client binaries import
// this package instead of pkg/* so they depend only on the SDK.
//
// It is a package of its own, not part of the root SDK package, because the
// decision is built on pkg/pairingproto, which itself imports the root SDK
// package.
package userverify

import (
	"github.com/jeremyhahn/go-xkms/pkg/attestation/userverify"
)

// ChallengeLifetime bounds how long a verify-user challenge may wait for its
// answer.
const ChallengeLifetime = userverify.ChallengeLifetime

// Challenge is one verify-user request the desktop committed to, answered
// once.
type Challenge = userverify.Challenge

var (
	// NewChallenge draws a fresh challenge for one verify-user exchange.
	NewChallenge = userverify.NewChallenge

	// Verify is the security decision on a local.verifyUser answer.
	Verify = userverify.Verify
)

var (
	ErrVerificationFailed = userverify.ErrVerificationFailed
	ErrChallengeAnswered  = userverify.ErrChallengeAnswered
	ErrChallengeExpired   = userverify.ErrChallengeExpired
	ErrIncomplete         = userverify.ErrIncomplete
	ErrNonceFailed        = userverify.ErrNonceFailed
)
