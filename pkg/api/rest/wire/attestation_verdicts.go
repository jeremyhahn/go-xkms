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

package wire

import (
	"context"
	"net/http"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// Continuous attestation verdict routes (go-xkms#2088). The server scopes
// every verb to the caller's tenant; no request carries one.
const (
	// AttestationVerdictsPath lists a device's verdicts (GET) and
	// re-attests a device (POST).
	AttestationVerdictsPath = "/api/v1/attestation/verdicts"
	// AttestationVerdictLatestPath returns a device's newest verdict.
	AttestationVerdictLatestPath = AttestationVerdictsPath + "/latest"
	// AttestationVerdictDeviceParam names the device on the GET routes.
	AttestationVerdictDeviceParam = "device"
)

// AttestationVerdictClient serves transport.AttestationVerdictService over
// the REST routes through Do.
type AttestationVerdictClient struct {
	Do Requester
}

var _ transport.AttestationVerdictService = AttestationVerdictClient{}

// ListAttestationVerdicts sends GET /api/v1/attestation/verdicts?device=.
func (c AttestationVerdictClient) ListAttestationVerdicts(ctx context.Context, req *transport.AttestationVerdictRequest) (*transport.ListAttestationVerdictsResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	var resp transport.ListAttestationVerdictsResponse
	path := withQuery(AttestationVerdictsPath, map[string]string{AttestationVerdictDeviceParam: req.DeviceID})
	if err := callJSON(ctx, c.Do, http.MethodGet, path, nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// GetLatestAttestationVerdict sends
// GET /api/v1/attestation/verdicts/latest?device=.
func (c AttestationVerdictClient) GetLatestAttestationVerdict(ctx context.Context, req *transport.AttestationVerdictRequest) (*transport.AttestationVerdict, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	var resp transport.AttestationVerdict
	path := withQuery(AttestationVerdictLatestPath, map[string]string{AttestationVerdictDeviceParam: req.DeviceID})
	if err := callJSON(ctx, c.Do, http.MethodGet, path, nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// ReattestDevice sends POST /api/v1/attestation/verdicts with the device in
// the body.
func (c AttestationVerdictClient) ReattestDevice(ctx context.Context, req *transport.AttestationVerdictRequest) (*transport.AttestationVerdict, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	var resp transport.AttestationVerdict
	if err := callJSON(ctx, c.Do, http.MethodPost, AttestationVerdictsPath, req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}
