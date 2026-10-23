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

package challenge

import (
	"bytes"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
)

func TestMessage_BindsTheBoundPurpose(t *testing.T) {
	nonce := []byte("nonce")
	ch := &qrdbsdk.AuthFactorChallenge{
		ChallengeID: "challenge-id",
		Nonce:       nonce,
		MethodData:  map[string]any{qrdbsdk.QuorumChallengePurposeKey: "quorum:a"},
	}
	want := qrdbsdk.QuorumChallengeMessage("challenge-id", "quorum:a", nonce)
	if got := Message(ch); !bytes.Equal(got, want) {
		t.Fatalf("Message = %q, want %q", got, want)
	}
	if bytes.Equal(Message(ch), qrdbsdk.QuorumChallengeMessage("challenge-id", "quorum:b", nonce)) {
		t.Fatal("Message matches the message for another purpose")
	}
}

func TestMessage_UsesTheEmptyPurposeWhenNoneIsBound(t *testing.T) {
	want := qrdbsdk.QuorumChallengeMessage("challenge-id", "", []byte("nonce"))
	cases := map[string]map[string]any{
		"nil method data":    nil,
		"no purpose key":     {"other": "value"},
		"non-string purpose": {qrdbsdk.QuorumChallengePurposeKey: 42},
	}
	for name, methodData := range cases {
		ch := &qrdbsdk.AuthFactorChallenge{ChallengeID: "challenge-id", Nonce: []byte("nonce"), MethodData: methodData}
		if got := Message(ch); !bytes.Equal(got, want) {
			t.Errorf("%s: Message = %q, want %q", name, got, want)
		}
	}
}
