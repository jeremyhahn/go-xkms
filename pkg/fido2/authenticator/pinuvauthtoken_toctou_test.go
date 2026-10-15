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

package authenticator

import (
	"sync"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
)

// TestConcurrentCommandsCannotBothConsumeOnePinUvAuthToken reproduces the
// TOCTOU window from #323: authorization (checkPinUvAuthTokenLocked) and
// consumption (consumePinUvAuthToken) are two separate acquisitions of mu,
// so two concurrent CTAP2 commands presenting the same pinUvAuthToken could
// both pass authorization before either reached consumption. That is a
// TOCTOU gap, not a data race — every individual access to the token state
// is correctly synchronized under mu, which is why `go test -race` alone
// cannot catch it; this test asserts the outcome instead.
//
// cmdMu in ProcessCBORWithContext fixes this by serializing whole commands,
// so the second goroutine here cannot even begin authorizing until the first
// has finished consuming. The result is deterministic regardless of exactly
// how the goroutines are scheduled: exactly one getAssertion succeeds and the
// other is refused with the same ErrPINAuthInvalid a replayed or unscoped
// token produces.
func TestConcurrentCommandsCannotBothConsumeOnePinUvAuthToken(t *testing.T) {
	auth := newConsumptionAuthenticator(t)
	cred := createAssertionTestCredential(t, auth, consumptionRPA, false)

	// One token, scoped to ga only, bound to consumptionRPA: exactly the
	// shape a platform mints for a single assertion.
	token := mintScopedToken(t, auth, PINPermissionGetAssertion, consumptionRPA)

	buildGetAssertionCBOR := func(t *testing.T, label string) []byte {
		t.Helper()

		clientDataHash := consumptionClientDataHash(label)
		req := map[int]interface{}{
			getAssertionParamRPID:           consumptionRPA,
			getAssertionParamClientDataHash: clientDataHash,
			getAssertionParamAllowList: []interface{}{
				map[string]interface{}{
					"type": "public-key",
					"id":   cred.CredentialID,
				},
			},
			getAssertionParamPINUVAuthParam:    pinUvAuthParamFor(token, clientDataHash),
			getAssertionParamPINUVAuthProtocol: PINProtocol1,
		}

		reqBytes, err := cbor.Marshal(req)
		require.NoError(t, err)
		return reqBytes
	}

	// Each request carries a distinct clientDataHash (and therefore a distinct
	// pinUvAuthParam), as two genuinely different platform requests would —
	// only the underlying token is shared.
	reqA := buildGetAssertionCBOR(t, "goroutine-a")
	reqB := buildGetAssertionCBOR(t, "goroutine-b")

	type outcome struct {
		status byte
		err    error
	}

	// Both goroutines signal readiness before either calls ProcessCBOR, then
	// are released together, so the race (if the fix regresses) is not left
	// to luck: they arrive at ProcessCBORWithContext as close together as the
	// scheduler allows.
	var ready sync.WaitGroup
	ready.Add(2)
	start := make(chan struct{})
	results := make(chan outcome, 2)

	fire := func(reqBytes []byte) {
		ready.Done()
		<-start
		resp, err := auth.ProcessCBOR(CmdGetAssertion, reqBytes)
		var status byte
		if len(resp) > 0 {
			status = resp[0]
		}
		results <- outcome{status: status, err: err}
	}

	go fire(reqA)
	go fire(reqB)

	ready.Wait()
	close(start)

	first := <-results
	second := <-results

	outcomes := [2]outcome{first, second}
	var successes int
	var failure *outcome
	for i := range outcomes {
		if outcomes[i].err == nil {
			successes++
			require.Equal(t, byte(StatusOK), outcomes[i].status,
				"a successful assertion must report StatusOK")
			continue
		}
		failure = &outcomes[i]
	}

	require.Equal(t, 1, successes,
		"exactly one of the two concurrent commands sharing a token must succeed")
	require.NotNil(t, failure, "the losing command must have failed, not merely differed")
	require.ErrorIs(t, failure.err, ErrPINAuthInvalid,
		"the command that lost the race must fail exactly as a replayed token would")
	require.Equal(t, byte(StatusPINAuthInvalid), failure.status)
}
