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

package rest

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/jeremyhahn/go-xkms/pkg/api/rest/wire"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// verdictCalls returns the three attestation verdict verbs on tr with req.
func verdictCalls(tr *Transport, req *transport.AttestationVerdictRequest) map[string]func() error {
	ctx := context.Background()
	return map[string]func() error{
		"list": func() error {
			_, err := tr.ListAttestationVerdicts(ctx, req)
			return err
		},
		"latest": func() error {
			_, err := tr.GetLatestAttestationVerdict(ctx, req)
			return err
		},
		"reattest": func() error {
			_, err := tr.ReattestDevice(ctx, req)
			return err
		},
	}
}

// TestAttestationVerdicts_RefusesANilRequest proves a connected transport
// refuses a nil request on every verdict verb.
func TestAttestationVerdicts_RefusesANilRequest(t *testing.T) {
	srv := newFullMockServer(t)
	defer srv.Close()
	tr := connectFullMock(t, srv)
	for name, call := range verdictCalls(tr, nil) {
		t.Run(name, func(t *testing.T) { assert.ErrorIs(t, call(), wire.ErrNilRequest) })
	}
}

// TestAttestationVerdicts_NotConnected proves every verdict verb returns
// ErrNotConnected before the transport connects.
func TestAttestationVerdicts_NotConnected(t *testing.T) {
	req := &transport.AttestationVerdictRequest{DeviceID: "dev-1"}
	for name, call := range verdictCalls(&Transport{}, req) {
		t.Run(name, func(t *testing.T) { assert.ErrorIs(t, call(), ErrNotConnected) })
	}
}
