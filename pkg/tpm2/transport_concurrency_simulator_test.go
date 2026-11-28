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

//go:build tpm_simulator

package tpm2

import (
	"sync"
	"testing"

	"github.com/google/go-tpm/tpm2"
)

// TestTransport_ConcurrentCommands_Simulator drives TPM commands from many
// goroutines at once, as go-enclave's provider conformance suite does with
// the key protector. Every command must get its own response: the
// transport serialises each command/response pair.
func TestTransport_ConcurrentCommands_Simulator(t *testing.T) {
	h := newSimHarness(t, nil)
	tr := h.TPM.Transport()

	const workers, rounds = 8, 25
	errs := make(chan error, workers*rounds)
	var wg sync.WaitGroup
	for range workers {
		wg.Go(func() {
			for range rounds {
				rsp, err := tpm2.GetRandom{BytesRequested: 16}.Execute(tr)
				if err != nil {
					errs <- err
					continue
				}
				if n := len(rsp.RandomBytes.Buffer); n != 16 {
					t.Errorf("GetRandom returned %d bytes, want 16", n)
				}
			}
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("concurrent GetRandom: %v", err)
	}
}
