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

	"github.com/jeremyhahn/go-xkms/pkg/api/rest/wire"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

var _ transport.AttestationVerdictService = (*Transport)(nil)

// verdicts returns the wire client that serves the attestation verdict
// verbs over the REST routes, once the transport is connected.
func (t *Transport) verdicts() (wire.AttestationVerdictClient, error) {
	if !t.connected {
		return wire.AttestationVerdictClient{}, ErrNotConnected
	}
	return wire.AttestationVerdictClient{Do: t.doRawRequest}, nil
}

// ListAttestationVerdicts returns a device's verdicts, oldest first.
func (t *Transport) ListAttestationVerdicts(ctx context.Context, req *transport.AttestationVerdictRequest) (*transport.ListAttestationVerdictsResponse, error) {
	c, err := t.verdicts()
	if err != nil {
		return nil, err
	}
	return c.ListAttestationVerdicts(ctx, req)
}

// GetLatestAttestationVerdict returns a device's newest verdict.
func (t *Transport) GetLatestAttestationVerdict(ctx context.Context, req *transport.AttestationVerdictRequest) (*transport.AttestationVerdict, error) {
	c, err := t.verdicts()
	if err != nil {
		return nil, err
	}
	return c.GetLatestAttestationVerdict(ctx, req)
}

// ReattestDevice re-attests a device now and returns the verdict.
func (t *Transport) ReattestDevice(ctx context.Context, req *transport.AttestationVerdictRequest) (*transport.AttestationVerdict, error) {
	c, err := t.verdicts()
	if err != nil {
		return nil, err
	}
	return c.ReattestDevice(ctx, req)
}
