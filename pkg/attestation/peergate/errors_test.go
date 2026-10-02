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

package peergate_test

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/jeremyhahn/go-xkms/pkg/attestation/peergate"
)

// Every error names its origin and, where it wraps a cause, unwraps to it, so
// a host can both log it and errors.Is the underlying failure.
func TestErrors_NameTheirOriginAndUnwrap(t *testing.T) {
	cause := errors.New("root cause")
	cases := map[string]struct {
		err     error
		message string
		wraps   bool
	}{
		"config":           {&peergate.ConfigError{Field: "Store", Reason: "required", Cause: cause}, "peergate: invalid configuration: Store: required: root cause", true},
		"config, no cause": {&peergate.ConfigError{Field: "Store", Reason: "required"}, "peergate: invalid configuration: Store: required", false},
		"peer certificate": {&peergate.PeerCertificateError{Reason: "none"}, "peergate: no attestable peer: none", false},
		"challenge":        {&peergate.ChallengeError{Reason: "expired"}, "peergate: evidence does not answer a challenge: expired", false},
		"attested peer":    {&peergate.AttestedPeerError{Reason: "no certificate"}, "peergate: unusable attested peer: no certificate", false},
		"capacity":         {&peergate.CapacityError{What: "evidence", Limit: 3}, "peergate: evidence capacity of 3 peers reached", false},
		"store":            {&peergate.StoreError{Op: "get", Cause: cause}, "peergate: evidence store get failed: root cause", true},
		"quote":            {&peergate.QuoteError{Reason: "no quoter", Cause: cause}, "peergate: quote failed: no quoter: root cause", true},
		"quote, no cause":  {&peergate.QuoteError{Reason: "no quoter"}, "peergate: quote failed: no quoter", false},
		"nonce":            {&peergate.NonceError{Cause: cause}, "peergate: challenge nonce generation failed: root cause", true},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.message, tc.err.Error())
			assert.Equal(t, tc.wraps, errors.Is(tc.err, cause))
		})
	}
}
