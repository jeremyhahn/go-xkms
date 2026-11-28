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

// AttestationVerdictRequest names the device of a verdict verb. Limit and
// Offset page ListAttestationVerdicts: a zero Limit asks for the default
// page (continuous.DefaultVerdictPageSize) and a Limit above
// continuous.MaxVerdictPageSize is capped to it. The other verbs ignore them.
type AttestationVerdictRequest struct {
	DeviceID string `json:"device_id"`
	Limit    int32  `json:"limit,omitempty"`
	Offset   int32  `json:"offset,omitempty"`
}

// ListAttestationVerdictsResponse carries one page of a device's verdicts,
// oldest first, and the number of verdicts in the whole history.
type ListAttestationVerdictsResponse struct {
	Verdicts []AttestationVerdict `json:"verdicts"`
	Total    int32                `json:"total"`
}
