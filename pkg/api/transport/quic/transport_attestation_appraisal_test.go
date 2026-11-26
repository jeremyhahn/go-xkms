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

package quic

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/jeremyhahn/go-xkms/pkg/api/rest/wire"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/appraisaltest"
)

// TestAttestationAppraisal_RefusesANilRequest proves a connected transport
// hands its calls to the wire client, which refuses a nil request.
func TestAttestationAppraisal_RefusesANilRequest(t *testing.T) {
	tr, cleanup := newMockTransport(t)
	defer cleanup()
	for name, call := range appraisaltest.NilRequestCalls(context.Background(), tr) {
		t.Run(name, func(t *testing.T) { assert.ErrorIs(t, call(), wire.ErrNilRequest) })
	}
}

// TestAttestationAppraisal_NotConnected proves every Verifier method refuses
// before the transport is connected.
func TestAttestationAppraisal_NotConnected(t *testing.T) {
	for name, call := range appraisaltest.Calls(context.Background(), newDisconnected(t)) {
		t.Run(name, func(t *testing.T) { assert.ErrorIs(t, call(), ErrNotConnected) })
	}
}
