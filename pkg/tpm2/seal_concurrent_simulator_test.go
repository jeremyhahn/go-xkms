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
	"bytes"
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// TestSealUnseal_ConcurrentCallers_Simulator: Seal and Unseal on one TPM2
// are safe for concurrent use; each caller gets back its own secret.
func TestSealUnseal_ConcurrentCallers_Simulator(t *testing.T) {
	h := newSimHarness(t, nil)
	ctx := context.Background()
	const callers = 8
	var wg sync.WaitGroup
	errc := make(chan error, callers)
	for i := range callers {
		wg.Go(func() {
			cn := fmt.Sprintf("concurrent-seal-%d", i)
			want := bytes.Repeat([]byte{byte(i + 1)}, 32)
			attrs := sealedKeyAttrs(t, h, cn, false, mustPassword(t, objectPassword))
			sealed, err := h.TPM.Seal(ctx, want, &types.SealOptions{KeyAttributes: attrs})
			if err != nil {
				errc <- fmt.Errorf("%s: Seal: %w", cn, err)
				return
			}
			attrs = sealedKeyAttrs(t, h, cn, false, mustPassword(t, objectPassword))
			got, err := h.TPM.Unseal(ctx, sealed, &types.UnsealOptions{KeyAttributes: attrs})
			if err != nil {
				errc <- fmt.Errorf("%s: Unseal: %w", cn, err)
				return
			}
			if !bytes.Equal(got, want) {
				errc <- fmt.Errorf("%s: Unseal returned another caller's secret", cn)
			}
		})
	}
	wg.Wait()
	close(errc)
	for err := range errc {
		t.Error(err)
	}
}
