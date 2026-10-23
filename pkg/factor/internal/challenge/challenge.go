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

// Package challenge builds the message a signature factor's challenge is
// answered over.
//
// The message is go-qrdb's, never one of go-xkms's own: qrdbsdk's
// QuorumChallengeMessage over the challenge ID, the purpose go-qrdb bound the
// challenge to (MethodData[QuorumChallengePurposeKey], "" when none) and the
// nonce. A proof is therefore never a signature over the bare nonce, and a
// proof made for one purpose never answers a challenge bound to another. The
// prover side is qrdbsdk.SignQuorumChallenge over the same three values.
package challenge

import (
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
)

// Message returns the message ch is answered over, exactly as go-qrdb's own
// mtls factor builds it (go-qrdb pkg/authfactors/mtls Factor.Verify).
func Message(ch *qrdbsdk.AuthFactorChallenge) []byte {
	purpose, _ := ch.MethodData[qrdbsdk.QuorumChallengePurposeKey].(string)
	return qrdbsdk.QuorumChallengeMessage(ch.ChallengeID, purpose, ch.Nonce)
}
