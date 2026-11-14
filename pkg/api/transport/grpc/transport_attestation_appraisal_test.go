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

package grpc

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-xkms/pkg/testutil/appraisaltest"
)

// TestAttestationAppraisal_ReachesTheServer proves a connected transport
// sends every Verifier call over its connection: the mock server serves none
// of them, so each answers with the server's Unimplemented status. The
// conversions themselves are tested once, in pkg/api/grpc/pbconv.
func TestAttestationAppraisal_ReachesTheServer(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()
	for name, call := range appraisaltest.Calls(context.Background(), tr) {
		t.Run(name, func(t *testing.T) { assert.Equal(t, codes.Unimplemented, status.Code(call())) })
	}
}

// TestAttestationAppraisal_NotConnected proves every Verifier method refuses
// before the transport is connected.
func TestAttestationAppraisal_NotConnected(t *testing.T) {
	for name, call := range appraisaltest.Calls(context.Background(), newDisconnected(t)) {
		t.Run(name, func(t *testing.T) { assert.ErrorIs(t, call(), ErrNotConnected) })
	}
}
