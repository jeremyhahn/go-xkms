//go:build tpm_simulator
// +build tpm_simulator

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

package tpm2

import (
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/stretchr/testify/assert"
)

// TestGetActiveTransientHandles_NilTransport proves the transient-handle
// query used by Close's cleanup sweep returns an empty result for a TPM2
// that was never opened, rather than dereferencing a nil transport.
func TestGetActiveTransientHandles_NilTransport(t *testing.T) {
	tpm := &TPM2{logger: discardLogger()}
	assert.Nil(t, tpm.getActiveTransientHandles())
}

// TestGetActiveTransientHandles_UnionMismatch proves the handle query
// rejects a GetCapability response carrying a different TPMU_CAPABILITIES
// union member (the same class of fault capabilitySelectorRewritingTransport
// exercises against the package's other capability accessors), returning
// an empty list instead of panicking on the failed type assertion.
func TestGetActiveTransientHandles_UnionMismatch(t *testing.T) {
	h := newSimHarness(t, nil)
	original := h.TPM.transport
	h.TPM.transport = &capabilitySelectorRewritingTransport{inner: original, newCap: tpm2.TPMCapAlgs}
	t.Cleanup(func() { h.TPM.transport = original })

	assert.Nil(t, h.TPM.getActiveTransientHandles())
}

// TestFlushSilent_SwallowsAndLogsFlushFailure proves flushSilent tolerates a
// handle the TPM refuses to flush (never loaded, or already gone) without
// panicking or returning an error the caller would have to check -- the
// point of using it from Close's best-effort cleanup sweep.
func TestFlushSilent_SwallowsAndLogsFlushFailure(t *testing.T) {
	h := newSimHarness(t, nil)
	assert.NotPanics(t, func() { h.TPM.flushSilent(tpm2.TPMHandle(0x81FFFFFE)) })
}
