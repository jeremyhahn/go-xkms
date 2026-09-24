//go:build tpm_simulator
// +build tpm_simulator

package tpm2

import (
	"errors"
	"fmt"
	"testing"

	"github.com/google/go-tpm/tpm2/transport"
	"github.com/stretchr/testify/require"
)

// errNSendTransportFault is returned by nSendTransport once its command
// budget is exhausted.
var errNSendTransportFault = errors.New("tpm: synthetic transport failure (command budget exhausted)")

// nSendTransport lets the first n Sends through to a real transport, then
// fails every Send after that. It carries no state beyond a call counter, so
// it needs no simulator instance of its own.
type nSendTransport struct {
	inner transport.TPM
	n     int
	calls int
}

func (f *nSendTransport) Send(input []byte) ([]byte, error) {
	f.calls++
	if f.calls > f.n {
		return nil, errNSendTransportFault
	}
	return f.inner.Send(input)
}

// sweepEachCommandFailure proves that every TPM command a multi-step
// operation issues has its error checked and returned, not swallowed. setup
// is called once per subtest (including one extra "precondition" call) to
// build a fresh, independently-provisioned harness; it returns the healthy
// transport to wrap and a run closure that performs the operation under
// test against whatever transport it is given.
//
// The precondition call learns how many commands the happy path issues by
// running run against an effectively unlimited budget. Each subsequent
// subtest then cuts the transport off one command earlier than the last,
// proving the operation surfaces that specific command's failure as an
// error instead of continuing past it.
//
// bestEffort names 1-based command numbers whose failure the operation
// deliberately does NOT propagate -- the documented shape of a trailing
// best-effort cleanup command (e.g. a deferred session FlushContext logged
// but not returned, matching the same contract session.go and capabilities.go
// pin elsewhere) rather than a dropped error check. Those positions are
// asserted the other way: the operation must still succeed even though that
// one command failed.
//
// This is a generic regression net for the "return nil, err" checks that
// follow every TPM round trip in a multi-command operation: dropping any one
// of those checks would let a mid-operation failure be silently ignored,
// and this sweep is what would catch it.
func sweepEachCommandFailure(
	t *testing.T,
	setup func(t *testing.T) (transport.TPM, func(transport.TPM) error),
	bestEffort ...int,
) {
	t.Helper()

	tolerated := make(map[int]bool, len(bestEffort))
	for _, n := range bestEffort {
		tolerated[n] = true
	}

	// The simulator is a one-per-process singleton (see newSimHarness):
	// opening a second one blocks until the first is Close()d. Running the
	// precondition in its own subtest, rather than directly against the
	// outer t, ensures its harness is torn down before the loop below opens
	// the next one -- otherwise every iteration would deadlock waiting for
	// a simulator the outer test's own (not-yet-run) cleanup still holds.
	var total int
	t.Run("precondition", func(t *testing.T) {
		inner, run := setup(t)
		unlimited := &nSendTransport{inner: inner, n: 1 << 30}
		require.NoError(t, run(unlimited), "precondition: the operation must succeed against a healthy transport")
		total = unlimited.calls
	})
	require.Greater(t, total, 0, "precondition: the operation must issue at least one TPM command")

	for n := 0; n < total; n++ {
		n := n
		if tolerated[n+1] {
			t.Run(fmt.Sprintf("bestEffortCommand%dFailureDoesNotAbort", n+1), func(t *testing.T) {
				inner, run := setup(t)
				ft := &nSendTransport{inner: inner, n: n}
				err := run(ft)
				require.NoError(t, err, "command %d of %d is documented best-effort and must not abort the operation", n+1, total)
			})
			continue
		}
		t.Run(fmt.Sprintf("failAfterCommand%d", n+1), func(t *testing.T) {
			inner, run := setup(t)
			ft := &nSendTransport{inner: inner, n: n}
			err := run(ft)
			require.Error(t, err, "command %d of %d must have its failure propagated, not swallowed", n+1, total)
		})
	}
}
