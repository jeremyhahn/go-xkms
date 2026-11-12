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

package transport

import (
	"context"

	"github.com/jeremyhahn/go-xkms/pkg/attestation/continuous"
)

// AttestationVerdictService serves the verdicts the continuous attestation
// engine reaches. Every verb is bound to the caller's tenant; no request
// names a tenant.
type AttestationVerdictService interface {
	// ListAttestationVerdicts returns a device's verdicts, oldest first.
	// Permission: attestation_verdicts:list.
	ListAttestationVerdicts(ctx context.Context, req *AttestationVerdictRequest) (*ListAttestationVerdictsResponse, error)

	// GetLatestAttestationVerdict returns a device's newest verdict.
	// Permission: attestation_verdicts:get.
	GetLatestAttestationVerdict(ctx context.Context, req *AttestationVerdictRequest) (*AttestationVerdict, error)

	// ReattestDevice re-attests a device now and returns the verdict.
	// Permission: attestation_verdicts:create.
	ReattestDevice(ctx context.Context, req *AttestationVerdictRequest) (*AttestationVerdict, error)
}

// AttestationVerdictServicer is the servicer the transports call.
type AttestationVerdictServicer interface {
	AttestationVerdictService
}

// AttestationVerdict is one re-attestation verdict.
type AttestationVerdict = continuous.Verdict

// AttestationVerdictRequest names the device of a verdict verb.
type AttestationVerdictRequest struct {
	DeviceID string `json:"device_id"`
}

// ListAttestationVerdictsResponse carries a device's verdicts, oldest first.
type ListAttestationVerdictsResponse struct {
	Verdicts []AttestationVerdict `json:"verdicts"`
}
