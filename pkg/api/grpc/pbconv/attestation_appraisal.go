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
)

// AttestationEndorsementToProto converts an endorsement to its wire form.
func AttestationEndorsementToProto(e *transport.AttestationEndorsement) *pb.AttestationEndorsement {
	if e == nil {
		return nil
	}
	return &pb.AttestationEndorsement{
		Name:           e.Name,
		Kind:           string(e.Kind),
		CertificatePem: e.CertificatePEM,
		PublicKeyPem:   e.PublicKeyPEM,
		CreatedAt:      timeToProto(e.CreatedAt),
	}
}

// AttestationEndorsementFromProto converts a wire endorsement.
func AttestationEndorsementFromProto(e *pb.AttestationEndorsement) *transport.AttestationEndorsement {
	if e == nil {
		return nil
	}
	return &transport.AttestationEndorsement{
		Name:           e.GetName(),
		Kind:           transport.AttestationEndorsementKind(e.GetKind()),
		CertificatePEM: e.GetCertificatePem(),
		PublicKeyPEM:   e.GetPublicKeyPem(),
		CreatedAt:      timeFromProto(e.GetCreatedAt()),
	}
}

// ListAttestationEndorsementsResponseToProto converts an endorsement list.
func ListAttestationEndorsementsResponseToProto(r *transport.ListAttestationEndorsementsResponse) *pb.ListAttestationEndorsementsResponse {
	out := &pb.ListAttestationEndorsementsResponse{}
	if r == nil {
		return out
	}
	for _, e := range r.Endorsements {
		out.Endorsements = append(out.Endorsements, AttestationEndorsementToProto(e))
	}
	return out
}

// ListAttestationEndorsementsResponseFromProto converts a wire endorsement
// list.
func ListAttestationEndorsementsResponseFromProto(r *pb.ListAttestationEndorsementsResponse) *transport.ListAttestationEndorsementsResponse {
	out := &transport.ListAttestationEndorsementsResponse{Endorsements: []*transport.AttestationEndorsement{}}
	for _, e := range r.GetEndorsements() {
		out.Endorsements = append(out.Endorsements, AttestationEndorsementFromProto(e))
	}
	return out
}

// PutAttestationEndorsementRequestFromProto converts a wire endorsement
// request.
func PutAttestationEndorsementRequestFromProto(r *pb.PutAttestationEndorsementRequest) *transport.PutAttestationEndorsementRequest {
	return &transport.PutAttestationEndorsementRequest{
		Name:           r.GetName(),
		Kind:           transport.AttestationEndorsementKind(r.GetKind()),
		CertificatePEM: r.GetCertificatePem(),
		PublicKeyPEM:   r.GetPublicKeyPem(),
	}
}

// AttestationReferenceValuesToProto converts reference values to their wire
// form.
func AttestationReferenceValuesToProto(v *transport.AttestationReferenceValues) *pb.AttestationReferenceValues {
	if v == nil {
		return nil
	}
	return &pb.AttestationReferenceValues{
		Name:        v.Name,
		ManifestId:  v.ManifestID,
		Profile:     v.Profile,
		Signer:      v.Signer,
		Repository:  v.Repository,
		NotBefore:   timeToProto(v.NotBefore),
		NotAfter:    timeToProto(v.NotAfter),
		PcrIndices:  v.PCRIndices,
		StoredAt:    timeToProto(v.StoredAt),
		SignedCorim: v.SignedCoRIM,
	}
}

// AttestationReferenceValuesFromProto converts wire reference values.
func AttestationReferenceValuesFromProto(v *pb.AttestationReferenceValues) *transport.AttestationReferenceValues {
	if v == nil {
		return nil
	}
	return &transport.AttestationReferenceValues{
		Name:        v.GetName(),
		ManifestID:  v.GetManifestId(),
		Profile:     v.GetProfile(),
		Signer:      v.GetSigner(),
		Repository:  v.GetRepository(),
		NotBefore:   timeFromProto(v.GetNotBefore()),
		NotAfter:    timeFromProto(v.GetNotAfter()),
		PCRIndices:  v.GetPcrIndices(),
		StoredAt:    timeFromProto(v.GetStoredAt()),
		SignedCoRIM: v.GetSignedCorim(),
	}
}

// ListAttestationReferenceValuesResponseToProto converts a reference-values
// list.
func ListAttestationReferenceValuesResponseToProto(r *transport.ListAttestationReferenceValuesResponse) *pb.ListAttestationReferenceValuesResponse {
	out := &pb.ListAttestationReferenceValuesResponse{}
	if r == nil {
		return out
	}
	for _, v := range r.ReferenceValues {
		out.ReferenceValues = append(out.ReferenceValues, AttestationReferenceValuesToProto(v))
	}
	return out
}

// ListAttestationReferenceValuesResponseFromProto converts a wire
// reference-values list.
func ListAttestationReferenceValuesResponseFromProto(r *pb.ListAttestationReferenceValuesResponse) *transport.ListAttestationReferenceValuesResponse {
	out := &transport.ListAttestationReferenceValuesResponse{ReferenceValues: []*transport.AttestationReferenceValues{}}
	for _, v := range r.GetReferenceValues() {
		out.ReferenceValues = append(out.ReferenceValues, AttestationReferenceValuesFromProto(v))
	}
	return out
}

// PutAttestationReferenceValuesRequestFromProto converts a wire
// reference-values request.
func PutAttestationReferenceValuesRequestFromProto(r *pb.PutAttestationReferenceValuesRequest) *transport.PutAttestationReferenceValuesRequest {
	return &transport.PutAttestationReferenceValuesRequest{
		Name:        r.GetName(),
		SignedCoRIM: r.GetSignedCorim(),
		Repository:  r.GetRepository(),
	}
}

// AppraiseAttestationQuoteRequestToProto converts quote evidence to its wire
// form.
func AppraiseAttestationQuoteRequestToProto(r *transport.AppraiseAttestationQuoteRequest) *pb.AppraiseAttestationQuoteRequest {
	return &pb.AppraiseAttestationQuoteRequest{
		AkCertificatePem: r.AKCertificatePEM,
		Quote:            r.Quote,
		Signature:        r.Signature,
		Nonce:            r.Nonce,
		Pcrs:             r.PCRs,
		EventLog:         r.EventLog,
		ReferenceValues:  r.ReferenceValues,
	}
}

// AppraiseAttestationQuoteRequestFromProto converts wire quote evidence.
func AppraiseAttestationQuoteRequestFromProto(r *pb.AppraiseAttestationQuoteRequest) *transport.AppraiseAttestationQuoteRequest {
	return &transport.AppraiseAttestationQuoteRequest{
		AKCertificatePEM: r.GetAkCertificatePem(),
		Quote:            r.GetQuote(),
		Signature:        r.GetSignature(),
		Nonce:            r.GetNonce(),
		PCRs:             r.GetPcrs(),
		EventLog:         r.GetEventLog(),
		ReferenceValues:  r.GetReferenceValues(),
	}
}

// AttestationResultToProto converts an attestation result to its wire form.
func AttestationResultToProto(r *transport.AttestationResult) *pb.AttestationResult {
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
		out.Checks = append(out.Checks, &pb.AttestationAppraisalCheck{Name: c.Name, Outcome: string(c.Outcome), Reason: c.Reason})
	}
	return out
}

// AttestationResultFromProto converts a wire attestation result.
func AttestationResultFromProto(r *pb.AttestationResult) *transport.AttestationResult {
	if r == nil {
		return nil
	}
	out := &transport.AttestationResult{
		Verified:             r.GetVerified(),
		CryptographicFailure: r.GetCryptographicFailure(),
		Checks:               []transport.AttestationAppraisalCheck{},
		ReferenceValues:      r.GetReferenceValues(),
		ManifestID:           r.GetManifestId(),
		Signer:               r.GetSigner(),
		BaselineSource:       r.GetBaselineSource(),
		AppraisedAt:          timeFromProto(r.GetAppraisedAt()),
	}
	for _, c := range r.GetChecks() {
		out.Checks = append(out.Checks, transport.AttestationAppraisalCheck{
			Name:    c.GetName(),
			Outcome: transport.AttestationAppraisalOutcome(c.GetOutcome()),
			Reason:  c.GetReason(),
		})
	}
	return out
}

// Compile-time check that the client serves the whole Verifier API.
var _ transport.AttestationAppraisalService = AttestationAppraisalClient{}

// AttestationAppraisalClient serves transport.AttestationAppraisalService
// over a generated xkms.v1 client. The gRPC and Unix-socket transports, which
// both speak the generated protocol, delegate to it once they hold a
// connection. Errors are the server's gRPC status errors, unchanged.
type AttestationAppraisalClient struct {
	// Client is the connected generated client.
	Client pb.KeystoreServiceClient
}

// PutAttestationEndorsement stores a trust anchor.
func (c AttestationAppraisalClient) PutAttestationEndorsement(ctx context.Context, req *transport.PutAttestationEndorsementRequest) (*transport.AttestationEndorsement, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	resp, err := c.Client.PutAttestationEndorsement(ctx, &pb.PutAttestationEndorsementRequest{
		Name: req.Name, Kind: string(req.Kind), CertificatePem: req.CertificatePEM, PublicKeyPem: req.PublicKeyPEM,
	})
	if err != nil {
		return nil, err
	}
	return AttestationEndorsementFromProto(resp), nil
}

// ListAttestationEndorsements lists trust anchors, optionally by kind.
func (c AttestationAppraisalClient) ListAttestationEndorsements(ctx context.Context, req *transport.ListAttestationEndorsementsRequest) (*transport.ListAttestationEndorsementsResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	resp, err := c.Client.ListAttestationEndorsements(ctx, &pb.ListAttestationEndorsementsRequest{Kind: string(req.Kind)})
	if err != nil {
		return nil, err
	}
	return ListAttestationEndorsementsResponseFromProto(resp), nil
}

// DeleteAttestationEndorsement removes a trust anchor.
func (c AttestationAppraisalClient) DeleteAttestationEndorsement(ctx context.Context, req *transport.DeleteAttestationEndorsementRequest) error {
	if req == nil {
		return ErrNilRequest
	}
	_, err := c.Client.DeleteAttestationEndorsement(ctx, &pb.DeleteAttestationEndorsementRequest{Name: req.Name})
	return err
}

// PutAttestationReferenceValues verifies and stores a signed CoRIM.
func (c AttestationAppraisalClient) PutAttestationReferenceValues(ctx context.Context, req *transport.PutAttestationReferenceValuesRequest) (*transport.AttestationReferenceValues, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	resp, err := c.Client.PutAttestationReferenceValues(ctx, &pb.PutAttestationReferenceValuesRequest{
		Name: req.Name, SignedCorim: req.SignedCoRIM, Repository: req.Repository,
	})
	if err != nil {
		return nil, err
	}
	return AttestationReferenceValuesFromProto(resp), nil
}

// GetAttestationReferenceValues returns stored reference values.
func (c AttestationAppraisalClient) GetAttestationReferenceValues(ctx context.Context, req *transport.GetAttestationReferenceValuesRequest) (*transport.AttestationReferenceValues, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	resp, err := c.Client.GetAttestationReferenceValues(ctx, &pb.GetAttestationReferenceValuesRequest{Name: req.Name})
	if err != nil {
		return nil, err
	}
	return AttestationReferenceValuesFromProto(resp), nil
}

// ListAttestationReferenceValues lists stored reference values.
func (c AttestationAppraisalClient) ListAttestationReferenceValues(ctx context.Context) (*transport.ListAttestationReferenceValuesResponse, error) {
	resp, err := c.Client.ListAttestationReferenceValues(ctx, &pb.ListAttestationReferenceValuesRequest{})
	if err != nil {
		return nil, err
	}
	return ListAttestationReferenceValuesResponseFromProto(resp), nil
}

// DeleteAttestationReferenceValues removes stored reference values.
func (c AttestationAppraisalClient) DeleteAttestationReferenceValues(ctx context.Context, req *transport.DeleteAttestationReferenceValuesRequest) error {
	if req == nil {
		return ErrNilRequest
	}
	_, err := c.Client.DeleteAttestationReferenceValues(ctx, &pb.DeleteAttestationReferenceValuesRequest{Name: req.Name})
	return err
}

// AppraiseAttestationQuote appraises TPM quote evidence.
func (c AttestationAppraisalClient) AppraiseAttestationQuote(ctx context.Context, req *transport.AppraiseAttestationQuoteRequest) (*transport.AttestationResult, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	resp, err := c.Client.AppraiseAttestationQuote(ctx, AppraiseAttestationQuoteRequestToProto(req))
	if err != nil {
		return nil, err
	}
	return AttestationResultFromProto(resp), nil
}
