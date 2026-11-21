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
	"errors"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/appraisal"
)

// AttestationEndorsementToProto converts a trust anchor to its proto form.
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

// AttestationEndorsementFromProto converts a proto trust anchor.
func AttestationEndorsementFromProto(e *pb.AttestationEndorsement) *transport.AttestationEndorsement {
	if e == nil {
		return nil
	}
	return &transport.AttestationEndorsement{
		Name:           e.GetName(),
		Kind:           appraisal.EndorsementKind(e.GetKind()),
		CertificatePEM: e.GetCertificatePem(),
		PublicKeyPEM:   e.GetPublicKeyPem(),
		CreatedAt:      timeFromProto(e.GetCreatedAt()),
	}
}

// PutAttestationEndorsementRequestToProto converts a put request.
func PutAttestationEndorsementRequestToProto(r *transport.PutAttestationEndorsementRequest) *pb.PutAttestationEndorsementRequest {
	if r == nil {
		return nil
	}
	return &pb.PutAttestationEndorsementRequest{
		Name:           r.Name,
		Kind:           string(r.Kind),
		CertificatePem: r.CertificatePEM,
		PublicKeyPem:   r.PublicKeyPEM,
	}
}

// PutAttestationEndorsementRequestFromProto converts a proto put request.
func PutAttestationEndorsementRequestFromProto(r *pb.PutAttestationEndorsementRequest) *transport.PutAttestationEndorsementRequest {
	if r == nil {
		return nil
	}
	return &transport.PutAttestationEndorsementRequest{
		Name:           r.GetName(),
		Kind:           appraisal.EndorsementKind(r.GetKind()),
		CertificatePEM: r.GetCertificatePem(),
		PublicKeyPEM:   r.GetPublicKeyPem(),
	}
}

// ListAttestationEndorsementsRequestFromProto converts a proto list request.
func ListAttestationEndorsementsRequestFromProto(r *pb.ListAttestationEndorsementsRequest) *transport.ListAttestationEndorsementsRequest {
	if r == nil {
		return nil
	}
	return &transport.ListAttestationEndorsementsRequest{Kind: appraisal.EndorsementKind(r.GetKind())}
}

// ListAttestationEndorsementsResponseToProto converts a trust-anchor list.
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

// ListAttestationEndorsementsResponseFromProto converts a proto trust-anchor
// list; an absent list is an empty one.
func ListAttestationEndorsementsResponseFromProto(r *pb.ListAttestationEndorsementsResponse) *transport.ListAttestationEndorsementsResponse {
	out := &transport.ListAttestationEndorsementsResponse{Endorsements: []*transport.AttestationEndorsement{}}
	for _, e := range r.GetEndorsements() {
		out.Endorsements = append(out.Endorsements, AttestationEndorsementFromProto(e))
	}
	return out
}

// DeleteAttestationEndorsementRequestFromProto converts a proto delete request.
func DeleteAttestationEndorsementRequestFromProto(r *pb.DeleteAttestationEndorsementRequest) *transport.DeleteAttestationEndorsementRequest {
	if r == nil {
		return nil
	}
	return &transport.DeleteAttestationEndorsementRequest{Name: r.GetName()}
}

// AttestationReferenceValuesToProto converts stored reference values.
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

// AttestationReferenceValuesFromProto converts proto reference values.
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

// PutAttestationReferenceValuesRequestToProto converts a put request.
func PutAttestationReferenceValuesRequestToProto(r *transport.PutAttestationReferenceValuesRequest) *pb.PutAttestationReferenceValuesRequest {
	if r == nil {
		return nil
	}
	return &pb.PutAttestationReferenceValuesRequest{Name: r.Name, SignedCorim: r.SignedCoRIM, Repository: r.Repository}
}

// PutAttestationReferenceValuesRequestFromProto converts a proto put request.
func PutAttestationReferenceValuesRequestFromProto(r *pb.PutAttestationReferenceValuesRequest) *transport.PutAttestationReferenceValuesRequest {
	if r == nil {
		return nil
	}
	return &transport.PutAttestationReferenceValuesRequest{
		Name:        r.GetName(),
		SignedCoRIM: r.GetSignedCorim(),
		Repository:  r.GetRepository(),
	}
}

// GetAttestationReferenceValuesRequestFromProto converts a proto get request.
func GetAttestationReferenceValuesRequestFromProto(r *pb.GetAttestationReferenceValuesRequest) *transport.GetAttestationReferenceValuesRequest {
	if r == nil {
		return nil
	}
	return &transport.GetAttestationReferenceValuesRequest{Name: r.GetName()}
}

// ListAttestationReferenceValuesResponseToProto converts a reference-values list.
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

// ListAttestationReferenceValuesResponseFromProto converts a proto
// reference-values list; an absent list is an empty one.
func ListAttestationReferenceValuesResponseFromProto(r *pb.ListAttestationReferenceValuesResponse) *transport.ListAttestationReferenceValuesResponse {
	out := &transport.ListAttestationReferenceValuesResponse{ReferenceValues: []*transport.AttestationReferenceValues{}}
	for _, v := range r.GetReferenceValues() {
		out.ReferenceValues = append(out.ReferenceValues, AttestationReferenceValuesFromProto(v))
	}
	return out
}

// DeleteAttestationReferenceValuesRequestFromProto converts a proto delete request.
func DeleteAttestationReferenceValuesRequestFromProto(r *pb.DeleteAttestationReferenceValuesRequest) *transport.DeleteAttestationReferenceValuesRequest {
	if r == nil {
		return nil
	}
	return &transport.DeleteAttestationReferenceValuesRequest{Name: r.GetName()}
}

// AppraiseAttestationQuoteRequestToProto converts an appraisal request.
func AppraiseAttestationQuoteRequestToProto(r *transport.AppraiseAttestationQuoteRequest) *pb.AppraiseAttestationQuoteRequest {
	if r == nil {
		return nil
	}
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

// AppraiseAttestationQuoteRequestFromProto converts a proto appraisal request.
func AppraiseAttestationQuoteRequestFromProto(r *pb.AppraiseAttestationQuoteRequest) *transport.AppraiseAttestationQuoteRequest {
	if r == nil {
		return nil
	}
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

// AttestationResultToProto converts an attestation result.
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
		out.Checks = append(out.Checks, &pb.AttestationAppraisalCheck{
			Name: c.Name, Outcome: string(c.Outcome), Reason: c.Reason,
		})
	}
	return out
}

// AttestationResultFromProto converts a proto attestation result.
func AttestationResultFromProto(r *pb.AttestationResult) *transport.AttestationResult {
	if r == nil {
		return nil
	}
	out := &transport.AttestationResult{
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
			Name: c.GetName(), Outcome: appraisal.AppraisalOutcome(c.GetOutcome()), Reason: c.GetReason(),
		})
	}
	return out
}

var _ transport.AttestationAppraisalService = AttestationAppraisalClient{}

// AttestationAppraisalClient serves transport.AttestationAppraisalService
// over a generated xkms.v1 client. The gRPC and Unix-socket transports,
// which both speak the generated protocol, delegate to it once they hold a
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
	resp, err := c.Client.PutAttestationEndorsement(ctx, PutAttestationEndorsementRequestToProto(req))
	if err != nil {
		return nil, err
	}
	return AttestationEndorsementFromProto(resp), nil
}

// ListAttestationEndorsements lists the trust anchors, optionally by kind.
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

// PutAttestationReferenceValues verifies a signed CoRIM and stores its
// reference values.
func (c AttestationAppraisalClient) PutAttestationReferenceValues(ctx context.Context, req *transport.PutAttestationReferenceValuesRequest) (*transport.AttestationReferenceValues, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	resp, err := c.Client.PutAttestationReferenceValues(ctx, PutAttestationReferenceValuesRequestToProto(req))
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

// ListAttestationReferenceValues lists the stored reference values.
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

// AppraiseAttestationQuote appraises a TPM quote and returns the
// attestation result.
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

// AppraiseAndroidKeyAttestation is not on the gRPC API yet.
// slice B: replaced by the gRPC verb of row 1660.
func (c AttestationAppraisalClient) AppraiseAndroidKeyAttestation(_ context.Context, _ *transport.AppraiseAndroidKeyAttestationRequest) (*transport.AttestationResult, error) {
	return nil, errors.ErrUnsupported
}

// AppraiseEKCertificate is not on the gRPC API yet.
// slice B: replaced by the gRPC verb of row 1660.
func (c AttestationAppraisalClient) AppraiseEKCertificate(_ context.Context, _ *transport.AppraiseEKCertificateRequest) (*transport.AttestationResult, error) {
	return nil, errors.ErrUnsupported
}
