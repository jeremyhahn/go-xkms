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

package usb

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/jeremyhahn/go-xkms/pkg/testutil/appraisaltest"
)

// TestAttestationAppraisal_NotSupported proves no Verifier method is served
// over USB.
func TestAttestationAppraisal_NotSupported(t *testing.T) {
	calls := appraisaltest.Calls(context.Background(), &Transport{})
	assert.Len(t, calls, 8, "every method of transport.AttestationAppraisalService")
	for name, call := range calls {
		t.Run(name, func(t *testing.T) { assert.ErrorIs(t, call(), ErrNotSupported) })
	}
}

// TestAttestationAppraisal_NilRequestNotSupported proves a nil request is
// refused the same way rather than dereferenced.
func TestAttestationAppraisal_NilRequestNotSupported(t *testing.T) {
	for name, call := range appraisaltest.NilRequestCalls(context.Background(), &Transport{}) {
		t.Run(name, func(t *testing.T) { assert.ErrorIs(t, call(), ErrNotSupported) })
	}
}
