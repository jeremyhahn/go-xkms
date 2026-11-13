//go:build tpm_simulator

package tpm2

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// TestSealer_SealUnseal_ConcurrentUse drives Seal and Unseal from several
// goroutines on one TPM2. Each operation is a sequence of TPM commands
// (salted sessions, Create/Load, Unseal, Flush); interleaved, one caller
// flushes a session or handle another is still using and the TPM refuses
// the salted session start (TPM_RC_VALUE). Run under -race it also catches
// the unsynchronised writes to the transport.
func TestSealer_SealUnseal_ConcurrentUse(t *testing.T) {
	h := newSimHarness(t, nil)
	ctx := context.Background()

	const workers = 4
	const rounds = 3

	type job struct {
		plaintext []byte
		sealAttrs []*types.KeyAttributes
		openAttrs []*types.KeyAttributes
	}
	jobs := make([]job, workers)
	for w := range jobs {
		jobs[w].plaintext = []byte(fmt.Sprintf("concurrent-secret-%d", w))
		for r := 0; r < rounds; r++ {
			cn := fmt.Sprintf("concurrent-seal-%d-%d", w, r)
			jobs[w].sealAttrs = append(jobs[w].sealAttrs,
				sealedKeyAttrs(t, h, cn, false, mustPassword(t, []byte("object-password"))))
			jobs[w].openAttrs = append(jobs[w].openAttrs,
				sealedKeyAttrs(t, h, cn, false, mustPassword(t, []byte("object-password"))))
		}
	}

	errCh := make(chan error, workers*rounds)
	var wg sync.WaitGroup
	for w := range jobs {
		j := jobs[w]
		wg.Go(func() {
			for r := 0; r < rounds; r++ {
				sealed, err := h.TPM.Seal(ctx, j.plaintext, &types.SealOptions{KeyAttributes: j.sealAttrs[r]})
				if err != nil {
					errCh <- fmt.Errorf("worker %d round %d: Seal: %w", w, r, err)
					return
				}
				got, err := h.TPM.Unseal(ctx, sealed, &types.UnsealOptions{KeyAttributes: j.openAttrs[r]})
				if err != nil {
					errCh <- fmt.Errorf("worker %d round %d: Unseal: %w", w, r, err)
					return
				}
				if string(got) != string(j.plaintext) {
					errCh <- fmt.Errorf("worker %d round %d: Unseal returned another secret", w, r)
					return
				}
			}
		})
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		require.NoError(t, err)
	}
}
