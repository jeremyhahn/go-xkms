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

package pbconv

import (
	"context"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/appraisal"
)

// AttestationVerdictRequestToProto converts a verdict request to its proto
// form; nil is absent.
func AttestationVerdictRequestToProto(r *transport.AttestationVerdictRequest) *pb.AttestationVerdictRequest {
	if r == nil {
		return nil
	}
	return &pb.AttestationVerdictRequest{DeviceId: r.DeviceID}
}

// AttestationVerdictRequestFromProto converts a proto verdict request to its
// transport form; absent is nil.
func AttestationVerdictRequestFromProto(r *pb.AttestationVerdictRequest) *transport.AttestationVerdictRequest {
	if r == nil {
		return nil
	}
	return &transport.AttestationVerdictRequest{DeviceID: r.GetDeviceId()}
}

// attestationResultToProto converts an appraisal result to its proto form;
// nil is absent.
func attestationResultToProto(r *appraisal.AttestationResult) *pb.AttestationResult {
	if r == nil {
		return nil
	}
	out := &pb.AttestationResult{
		Verified:             r.Verified,
		CryptographicFailure: r.CryptographicFailure,
		ReferenceValues:      r.ReferenceValues,
		ManifestId:           r.ManifestID,
		Signer:               r.Signer,
		BaselineSource:       r.BaselineSource,
		AppraisedAt:          timeToProto(r.AppraisedAt),
	}
	for _, c := range r.Checks {
		out.Checks = append(out.Checks, &pb.AppraisalCheck{Name: c.Name, Outcome: string(c.Outcome), Reason: c.Reason})
	}
	return out
}

// attestationResultFromProto converts a proto appraisal result to its
// transport form; absent is nil, and no checks stay nil.
func attestationResultFromProto(r *pb.AttestationResult) *appraisal.AttestationResult {
	if r == nil {
		return nil
	}
	out := &appraisal.AttestationResult{
		Verified:             r.GetVerified(),
		CryptographicFailure: r.GetCryptographicFailure(),
		ReferenceValues:      r.GetReferenceValues(),
		ManifestID:           r.GetManifestId(),
		Signer:               r.GetSigner(),
		BaselineSource:       r.GetBaselineSource(),
		AppraisedAt:          timeFromProto(r.GetAppraisedAt()),
	}
	for _, c := range r.GetChecks() {
		out.Checks = append(out.Checks, appraisal.AppraisalCheck{
			Name:    c.GetName(),
			Outcome: appraisal.AppraisalOutcome(c.GetOutcome()),
			Reason:  c.GetReason(),
		})
	}
	return out
}

// AttestationVerdictToProto converts a verdict to its proto form; nil is
// absent.
func AttestationVerdictToProto(v *transport.AttestationVerdict) *pb.AttestationVerdict {
	if v == nil {
		return nil
	}
	return &pb.AttestationVerdict{
		Tenant:   v.Tenant,
		DeviceId: v.DeviceID,
		Result:   attestationResultToProto(v.Result),
		Verified: v.Verified,
		At:       timeToProto(v.At),
		Cause:    v.Cause,
	}
}

// AttestationVerdictFromProto converts a proto verdict to its transport
// form; absent is nil.
func AttestationVerdictFromProto(v *pb.AttestationVerdict) *transport.AttestationVerdict {
	if v == nil {
		return nil
	}
	return &transport.AttestationVerdict{
		Tenant:   v.GetTenant(),
		DeviceID: v.GetDeviceId(),
		Result:   attestationResultFromProto(v.GetResult()),
		Verified: v.GetVerified(),
		At:       timeFromProto(v.GetAt()),
		Cause:    v.GetCause(),
	}
}

// ListAttestationVerdictsResponseToProto converts a verdict list to its
// proto form; nil is absent.
func ListAttestationVerdictsResponseToProto(r *transport.ListAttestationVerdictsResponse) *pb.ListAttestationVerdictsResponse {
	if r == nil {
		return nil
	}
	out := &pb.ListAttestationVerdictsResponse{Verdicts: make([]*pb.AttestationVerdict, 0, len(r.Verdicts))}
	for i := range r.Verdicts {
		out.Verdicts = append(out.Verdicts, AttestationVerdictToProto(&r.Verdicts[i]))
	}
	return out
}

// ListAttestationVerdictsResponseFromProto converts a proto verdict list to
// its transport form; absent is nil, and an empty list decodes as [] rather
// than null.
func ListAttestationVerdictsResponseFromProto(r *pb.ListAttestationVerdictsResponse) *transport.ListAttestationVerdictsResponse {
	if r == nil {
		return nil
	}
	out := &transport.ListAttestationVerdictsResponse{Verdicts: make([]transport.AttestationVerdict, 0, len(r.GetVerdicts()))}
	for _, v := range r.GetVerdicts() {
		out.Verdicts = append(out.Verdicts, *AttestationVerdictFromProto(v))
	}
	return out
}

// AttestationVerdictClient serves the verdict verbs over a generated
// KeystoreService client, which the gRPC and Unix transports share.
type AttestationVerdictClient struct {
	Client pb.KeystoreServiceClient
}

var _ transport.AttestationVerdictService = AttestationVerdictClient{}

// ListAttestationVerdicts returns a device's verdicts, oldest first.
func (c AttestationVerdictClient) ListAttestationVerdicts(ctx context.Context, req *transport.AttestationVerdictRequest) (*transport.ListAttestationVerdictsResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	resp, err := c.Client.ListAttestationVerdicts(ctx, AttestationVerdictRequestToProto(req))
	if err != nil {
		return nil, err
	}
	return ListAttestationVerdictsResponseFromProto(resp), nil
}

// GetLatestAttestationVerdict returns a device's newest verdict.
func (c AttestationVerdictClient) GetLatestAttestationVerdict(ctx context.Context, req *transport.AttestationVerdictRequest) (*transport.AttestationVerdict, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	resp, err := c.Client.GetLatestAttestationVerdict(ctx, AttestationVerdictRequestToProto(req))
	if err != nil {
		return nil, err
	}
	return AttestationVerdictFromProto(resp), nil
}

// ReattestDevice re-attests a device now and returns the verdict.
func (c AttestationVerdictClient) ReattestDevice(ctx context.Context, req *transport.AttestationVerdictRequest) (*transport.AttestationVerdict, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	resp, err := c.Client.ReattestDevice(ctx, AttestationVerdictRequestToProto(req))
	if err != nil {
		return nil, err
	}
	return AttestationVerdictFromProto(resp), nil
}
