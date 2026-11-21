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

package unix

import (
	"context"

	"github.com/jeremyhahn/go-xkms/pkg/api/grpc/pbconv"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// The continuous attestation verdict verbs are served by
// pbconv.AttestationVerdictClient, shared by the gRPC and Unix-socket
// transports, once this transport holds a connection.

var _ transport.AttestationVerdictService = (*Transport)(nil)

// verdicts returns the shared verdict client over this transport's
// connection, or ErrNotConnected before it holds one.
func (t *Transport) verdicts() (pbconv.AttestationVerdictClient, error) {
	if t.client == nil {
		return pbconv.AttestationVerdictClient{}, ErrNotConnected
	}
	return pbconv.AttestationVerdictClient{Client: t.client}, nil
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
