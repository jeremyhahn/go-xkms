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
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// TestSealUnseal_ConcurrentCallersOnOneTPM proves Seal and Unseal are safe to
// call from many goroutines on one TPM2. Each call is a sequence of commands
// over sessions and transient objects the TPM holds between them, so callers
// that interleave those sequences exhaust the TPM's object slots or answer
// one session's nonce with another's, and the TPM refuses the command.
func TestSealUnseal_ConcurrentCallersOnOneTPM(t *testing.T) {
	const callers = 8
	h := newSimHarness(t, nil)

	// The key attributes are built here: sealedKeyAttrs may stop the test,
	// which only the test goroutine can do.
	attrs := make([]*types.KeyAttributes, callers)
	for i := range callers {
		attrs[i] = sealedKeyAttrs(t, h, fmt.Sprintf("concurrent-seal-%d", i), false, mustPassword(t, objectPassword))
	}

	var wg sync.WaitGroup
	for i := range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			plaintext := []byte(fmt.Sprintf("caller-%d-secret", i))

			sealed, err := h.TPM.Seal(t.Context(), plaintext, &types.SealOptions{KeyAttributes: attrs[i]})
			if !assert.NoError(t, err, "caller %d: seal", i) {
				return
			}
			unsealed, err := h.TPM.Unseal(t.Context(), sealed, &types.UnsealOptions{KeyAttributes: attrs[i]})
			if !assert.NoError(t, err, "caller %d: unseal", i) {
				return
			}
			assert.Equal(t, plaintext, unsealed, "caller %d must get back its own plaintext", i)
		}()
	}
	wg.Wait()
}
