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

// Package pbconv converts between the xkms.v1 protobuf messages and the
// pkg/api/transport types. The gRPC server (pkg/api/grpc) and both clients
// that speak the generated protocol (pkg/api/transport/grpc and
// pkg/api/transport/unix) convert through it, so the wire mapping of a
// message is written once.
package pbconv

import (
	"math"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// uintsToProto converts PCR indices to their proto form.
func uintsToProto(in []uint) []uint32 {
	if in == nil {
		return nil
	}
	out := make([]uint32, len(in))
	for i, v := range in {
		out[i] = uint32(v) // #nosec G115 -- PCR indices are 0 through 23
	}
	return out
}

// uintsFromProto converts proto PCR indices to their transport form.
func uintsFromProto(in []uint32) []uint {
	if in == nil {
		return nil
	}
	out := make([]uint, len(in))
	for i, v := range in {
		out[i] = uint(v)
	}
	return out
}

// pcrValuesToProto converts hex PCR values keyed by index to their proto
// form.
func pcrValuesToProto(in map[uint]string) map[uint32]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[uint32]string, len(in))
	for pcr, value := range in {
		out[uint32(pcr)] = value // #nosec G115 -- PCR indices are 0 through 23
	}
	return out
}

// pcrValuesFromProto converts proto PCR values to their transport form.
func pcrValuesFromProto(in map[uint32]string) map[uint]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[uint]string, len(in))
	for pcr, value := range in {
		out[uint(pcr)] = value
	}
	return out
}

// TPMPolicyBranchesToProto converts TPM policy branches to their proto form.
func TPMPolicyBranchesToProto(in []transport.TPMPolicyBranch) []*pb.TPMPolicyBranch {
	out := make([]*pb.TPMPolicyBranch, len(in))
	for i, b := range in {
		conditions := make([]*pb.TPMPolicyCondition, len(b.Conditions))
		for j, c := range b.Conditions {
			conditions[j] = &pb.TPMPolicyCondition{
				Type:       c.Type,
				Bank:       c.Bank,
				Pcrs:       uintsToProto(c.PCRs),
				PcrValues:  pcrValuesToProto(c.PCRValues),
				PcrDigest:  c.PCRDigest,
				Localities: uintsToProto(c.Localities),
			}
		}
		out[i] = &pb.TPMPolicyBranch{Conditions: conditions, Approved: b.Approved, Reference: tpmReferenceToProto(b.Reference)}
	}
	return out
}

// TPMPolicyBranchesFromProto converts proto TPM policy branches to their
// transport form.
func TPMPolicyBranchesFromProto(in []*pb.TPMPolicyBranch) []transport.TPMPolicyBranch {
	out := make([]transport.TPMPolicyBranch, len(in))
	for i, b := range in {
		conditions := make([]transport.TPMPolicyCondition, len(b.GetConditions()))
		for j, c := range b.GetConditions() {
			conditions[j] = transport.TPMPolicyCondition{
				Type:       c.GetType(),
				Bank:       c.GetBank(),
				PCRs:       uintsFromProto(c.GetPcrs()),
				PCRValues:  pcrValuesFromProto(c.GetPcrValues()),
				PCRDigest:  c.GetPcrDigest(),
				Localities: uintsFromProto(c.GetLocalities()),
			}
		}
		out[i] = transport.TPMPolicyBranch{Conditions: conditions, Approved: b.GetApproved(), Reference: tpmReferenceFromProto(b.GetReference())}
	}
	return out
}

// TPMPolicyToProto converts a TPM policy to its proto form.
func TPMPolicyToProto(p *transport.TPMPolicy) *pb.TPMPolicy {
	return &pb.TPMPolicy{
		Name:                p.Name,
		TenantId:            p.TenantID,
		Description:         p.Description,
		Branches:            TPMPolicyBranchesToProto(p.Branches),
		Index:               p.Index,
		Approved:            p.Approved,
		Epoch:               p.Epoch,
		AuthorityGeneration: p.AuthorityGeneration,
		AutoUnseal:          p.AutoUnseal,
		CreatedAt:           p.CreatedAt,
		UpdatedAt:           p.UpdatedAt,
	}
}

// TPMPolicyFromProto converts a proto TPM policy to its transport form.
func TPMPolicyFromProto(p *pb.TPMPolicy) *transport.TPMPolicy {
	return &transport.TPMPolicy{
		Name:                p.GetName(),
		TenantID:            p.GetTenantId(),
		Description:         p.GetDescription(),
		Branches:            TPMPolicyBranchesFromProto(p.GetBranches()),
		Index:               p.GetIndex(),
		Approved:            p.GetApproved(),
		Epoch:               p.GetEpoch(),
		AuthorityGeneration: p.GetAuthorityGeneration(),
		AutoUnseal:          p.GetAutoUnseal(),
		CreatedAt:           p.GetCreatedAt(),
		UpdatedAt:           p.GetUpdatedAt(),
	}
}

// TPMPolicyCreateRequestToProto converts a create request to its proto form.
func TPMPolicyCreateRequestToProto(r *transport.TPMPolicyCreateRequest) *pb.TPMPolicyCreateRequest {
	return &pb.TPMPolicyCreateRequest{
		TenantId:    r.TenantID,
		Name:        r.Name,
		Description: r.Description,
		Branches:    TPMPolicyBranchesToProto(r.Branches),
		AutoUnseal:  r.AutoUnseal,
		OwnerAuth:   r.OwnerAuth,
	}
}

// TPMPolicyCreateRequestFromProto converts a proto create request to its
// transport form.
func TPMPolicyCreateRequestFromProto(r *pb.TPMPolicyCreateRequest) *transport.TPMPolicyCreateRequest {
	return &transport.TPMPolicyCreateRequest{
		TenantID:    r.GetTenantId(),
		Name:        r.GetName(),
		Description: r.GetDescription(),
		Branches:    TPMPolicyBranchesFromProto(r.GetBranches()),
		AutoUnseal:  r.GetAutoUnseal(),
		OwnerAuth:   r.GetOwnerAuth(),
	}
}

// TPMPolicyDescriptionRequestToProto converts a description change to its
// proto form.
func TPMPolicyDescriptionRequestToProto(r *transport.TPMPolicyDescriptionRequest) *pb.TPMPolicyDescriptionRequest {
	return &pb.TPMPolicyDescriptionRequest{TenantId: r.TenantID, Name: r.Name, Description: r.Description}
}

// TPMPolicyDescriptionRequestFromProto converts a proto description change
// to its transport form.
func TPMPolicyDescriptionRequestFromProto(r *pb.TPMPolicyDescriptionRequest) *transport.TPMPolicyDescriptionRequest {
	return &transport.TPMPolicyDescriptionRequest{TenantID: r.GetTenantId(), Name: r.GetName(), Description: r.GetDescription()}
}

// TPMPolicyRequestToProto converts a policy-name request to its proto form.
func TPMPolicyRequestToProto(r *transport.TPMPolicyRequest) *pb.TPMPolicyRequest {
	return &pb.TPMPolicyRequest{TenantId: r.TenantID, Name: r.Name}
}

// TPMPolicyRequestFromProto converts a proto policy-name request to its
// transport form.
func TPMPolicyRequestFromProto(r *pb.TPMPolicyRequest) *transport.TPMPolicyRequest {
	return &transport.TPMPolicyRequest{TenantID: r.GetTenantId(), Name: r.GetName()}
}

// TPMPolicyUpdateRequestToProto converts a policy update request to its
// proto form. A branch index int32 cannot carry becomes -1, which names no
// branch, so the server refuses it rather than updating a truncated index.
func TPMPolicyUpdateRequestToProto(r *transport.TPMPolicyUpdateRequest) *pb.TPMPolicyUpdateRequest {
	out := &pb.TPMPolicyUpdateRequest{TenantId: r.TenantID, Name: r.Name, ReferenceValues: r.ReferenceValues}
	if r.Branch != nil {
		branch := int32(-1)
		if *r.Branch >= 0 && *r.Branch <= math.MaxInt32 {
			branch = int32(*r.Branch) // #nosec G115 -- bounds checked above
		}
		out.Branch = &branch
	}
	return out
}

// TPMPolicyUpdateRequestFromProto converts a proto policy update request to
// its transport form.
func TPMPolicyUpdateRequestFromProto(r *pb.TPMPolicyUpdateRequest) *transport.TPMPolicyUpdateRequest {
	out := &transport.TPMPolicyUpdateRequest{TenantID: r.GetTenantId(), Name: r.GetName(), ReferenceValues: r.GetReferenceValues()}
	if r.Branch != nil {
		branch := int(r.GetBranch())
		out.Branch = &branch
	}
	return out
}

// tpmReferenceToProto converts a branch's reference to its proto form.
func tpmReferenceToProto(r *transport.TPMPolicyReference) *pb.TPMPolicyReference {
	if r == nil {
		return nil
	}
	return &pb.TPMPolicyReference{Id: r.ID, Profile: r.Profile, Signer: r.Signer, Digest: r.Digest}
}

// tpmReferenceFromProto converts a proto branch reference to its transport
// form.
func tpmReferenceFromProto(r *pb.TPMPolicyReference) *transport.TPMPolicyReference {
	if r == nil {
		return nil
	}
	return &transport.TPMPolicyReference{ID: r.GetId(), Profile: r.GetProfile(), Signer: r.GetSigner(), Digest: r.GetDigest()}
}

// TPMPolicyListResponseToProto converts a policy list to its proto form.
func TPMPolicyListResponseToProto(r *transport.TPMPolicyListResponse) *pb.TPMPolicyListResponse {
	out := &pb.TPMPolicyListResponse{Policies: make([]*pb.TPMPolicy, 0, len(r.Policies))}
	for i := range r.Policies {
		out.Policies = append(out.Policies, TPMPolicyToProto(&r.Policies[i]))
	}
	return out
}

// TPMPolicyListResponseFromProto converts a proto policy list to its
// transport form.
func TPMPolicyListResponseFromProto(r *pb.TPMPolicyListResponse) *transport.TPMPolicyListResponse {
	out := &transport.TPMPolicyListResponse{Policies: make([]transport.TPMPolicy, 0, len(r.GetPolicies()))}
	for _, p := range r.GetPolicies() {
		out.Policies = append(out.Policies, *TPMPolicyFromProto(p))
	}
	return out
}

// TPMPolicyDeleteRequestToProto converts a delete request to its proto form.
func TPMPolicyDeleteRequestToProto(r *transport.TPMPolicyDeleteRequest) *pb.TPMPolicyDeleteRequest {
	return &pb.TPMPolicyDeleteRequest{TenantId: r.TenantID, Name: r.Name, OwnerAuth: r.OwnerAuth}
}

// TPMPolicyDeleteRequestFromProto converts a proto delete request to its
// transport form.
func TPMPolicyDeleteRequestFromProto(r *pb.TPMPolicyDeleteRequest) *transport.TPMPolicyDeleteRequest {
	return &transport.TPMPolicyDeleteRequest{TenantID: r.GetTenantId(), Name: r.GetName(), OwnerAuth: r.GetOwnerAuth()}
}

// TPMPolicyVerifyResponseToProto converts a verification to its proto form.
func TPMPolicyVerifyResponseToProto(r *transport.TPMPolicyVerifyResponse) *pb.TPMPolicyVerifyResponse {
	branches := make([]*pb.TPMPolicyBranchVerification, len(r.Branches))
	for i, b := range r.Branches {
		branches[i] = &pb.TPMPolicyBranchVerification{
			Match:      b.Match,
			Mismatched: uintsToProto(b.Mismatched),
			Approved:   b.Approved,
			Reference:  tpmReferenceToProto(b.Reference),
		}
	}
	return &pb.TPMPolicyVerifyResponse{
		Name:     r.Name,
		Match:    r.Match,
		Approved: r.Approved,
		Branches: branches,
	}
}

// TPMPolicyVerifyResponseFromProto converts a proto verification to its
// transport form.
func TPMPolicyVerifyResponseFromProto(r *pb.TPMPolicyVerifyResponse) *transport.TPMPolicyVerifyResponse {
	branches := make([]transport.TPMPolicyBranchVerification, len(r.GetBranches()))
	for i, b := range r.GetBranches() {
		branches[i] = transport.TPMPolicyBranchVerification{
			Match:      b.GetMatch(),
			Mismatched: uintsFromProto(b.GetMismatched()),
			Approved:   b.GetApproved(),
			Reference:  tpmReferenceFromProto(b.GetReference()),
		}
	}
	return &transport.TPMPolicyVerifyResponse{
		Name:     r.GetName(),
		Match:    r.GetMatch(),
		Approved: r.GetApproved(),
		Branches: branches,
	}
}

// TPMPolicyObjectsResponseToProto converts a policy's object list to its
// proto form.
func TPMPolicyObjectsResponseToProto(r *transport.TPMPolicyObjectsResponse) *pb.TPMPolicyObjectsResponse {
	return &pb.TPMPolicyObjectsResponse{Name: r.Name, Objects: r.Objects}
}

// TPMPolicyObjectsResponseFromProto converts a proto object list to its
// transport form.
func TPMPolicyObjectsResponseFromProto(r *pb.TPMPolicyObjectsResponse) *transport.TPMPolicyObjectsResponse {
	objects := r.GetObjects()
	if objects == nil {
		objects = []string{}
	}
	return &transport.TPMPolicyObjectsResponse{Name: r.GetName(), Objects: objects}
}

// TPMPolicyAutoUnsealRequestToProto converts an auto-unseal request to its
// proto form.
func TPMPolicyAutoUnsealRequestToProto(r *transport.TPMPolicyAutoUnsealRequest) *pb.TPMPolicyAutoUnsealRequest {
	return &pb.TPMPolicyAutoUnsealRequest{TenantId: r.TenantID, Name: r.Name, Enabled: r.Enabled}
}

// TPMPolicyAutoUnsealRequestFromProto converts a proto auto-unseal request to
// its transport form.
func TPMPolicyAutoUnsealRequestFromProto(r *pb.TPMPolicyAutoUnsealRequest) *transport.TPMPolicyAutoUnsealRequest {
	return &transport.TPMPolicyAutoUnsealRequest{TenantID: r.GetTenantId(), Name: r.GetName(), Enabled: r.GetEnabled()}
}

// TPMObjectPolicyRequestToProto converts an object-policy request to its
// proto form.
func TPMObjectPolicyRequestToProto(r *transport.TPMObjectPolicyRequest) *pb.TPMObjectPolicyRequest {
	return &pb.TPMObjectPolicyRequest{TenantId: r.TenantID, KeyId: r.KeyID, Kind: r.Kind}
}

// TPMObjectPolicyRequestFromProto converts a proto object-policy request to
// its transport form.
func TPMObjectPolicyRequestFromProto(r *pb.TPMObjectPolicyRequest) *transport.TPMObjectPolicyRequest {
	return &transport.TPMObjectPolicyRequest{TenantID: r.GetTenantId(), KeyID: r.GetKeyId(), Kind: r.GetKind()}
}

// TPMObjectPolicyResponseToProto converts an object's assignment to its
// proto form.
func TPMObjectPolicyResponseToProto(r *transport.TPMObjectPolicyResponse) *pb.TPMObjectPolicyResponse {
	return &pb.TPMObjectPolicyResponse{
		ObjectId:   r.ObjectID,
		Kind:       r.Kind,
		Policy:     r.Policy,
		AuthPolicy: r.AuthPolicy,
		CreatedAt:  r.CreatedAt,
	}
}

// TPMObjectPolicyResponseFromProto converts a proto assignment to its
// transport form.
func TPMObjectPolicyResponseFromProto(r *pb.TPMObjectPolicyResponse) *transport.TPMObjectPolicyResponse {
	return &transport.TPMObjectPolicyResponse{
		ObjectID:   r.GetObjectId(),
		Kind:       r.GetKind(),
		Policy:     r.GetPolicy(),
		AuthPolicy: r.GetAuthPolicy(),
		CreatedAt:  r.GetCreatedAt(),
	}
}

// TPMAuthorityRotateResponseToProto converts a rotation result to its proto
// form.
func TPMAuthorityRotateResponseToProto(r *transport.TPMAuthorityRotateResponse) *pb.TPMAuthorityRotateResponse {
	return &pb.TPMAuthorityRotateResponse{
		TenantId:      r.TenantID,
		Generation:    r.Generation,
		AuthorityName: r.AuthorityName,
		Epoch:         r.Epoch,
	}
}

// TPMAuthorityRotateResponseFromProto converts a proto rotation result to
// its transport form.
func TPMAuthorityRotateResponseFromProto(r *pb.TPMAuthorityRotateResponse) *transport.TPMAuthorityRotateResponse {
	return &transport.TPMAuthorityRotateResponse{
		TenantID:      r.GetTenantId(),
		Generation:    r.GetGeneration(),
		AuthorityName: r.GetAuthorityName(),
		Epoch:         r.GetEpoch(),
	}
}

// TenantTPMModeResponseToProto converts a tenant's TPM mode to its proto form.
func TenantTPMModeResponseToProto(r *transport.TenantTPMModeResponse) *pb.TenantTPMModeResponse {
	return &pb.TenantTPMModeResponse{TenantId: r.TenantID, Mode: r.Mode}
}

// TenantTPMModeResponseFromProto converts a proto TPM mode to its transport
// form.
func TenantTPMModeResponseFromProto(r *pb.TenantTPMModeResponse) *transport.TenantTPMModeResponse {
	return &transport.TenantTPMModeResponse{TenantID: r.GetTenantId(), Mode: r.GetMode()}
}

// SetTenantTPMModeRequestToProto converts a mode change to its proto form.
func SetTenantTPMModeRequestToProto(r *transport.SetTenantTPMModeRequest) *pb.SetTenantTPMModeRequest {
	return &pb.SetTenantTPMModeRequest{TenantId: r.TenantID, Mode: r.Mode, OwnerAuth: r.OwnerAuth}
}

// SetTenantTPMModeRequestFromProto converts a proto mode change to its
// transport form.
func SetTenantTPMModeRequestFromProto(r *pb.SetTenantTPMModeRequest) *transport.SetTenantTPMModeRequest {
	return &transport.SetTenantTPMModeRequest{TenantID: r.GetTenantId(), Mode: r.GetMode(), OwnerAuth: r.GetOwnerAuth()}
}

// TenantVTPMStatusResponseToProto converts a vTPM status to its proto form.
func TenantVTPMStatusResponseToProto(r *transport.TenantVTPMStatusResponse) *pb.TenantVTPMStatusResponse {
	return &pb.TenantVTPMStatusResponse{
		TenantId: r.TenantID,
		Running:  r.Running,
		Pid:      int64(r.PID),
		Socket:   r.Socket,
		Restarts: r.Restarts,
	}
}

// TenantVTPMStatusResponseFromProto converts a proto vTPM status to its
// transport form.
func TenantVTPMStatusResponseFromProto(r *pb.TenantVTPMStatusResponse) *transport.TenantVTPMStatusResponse {
	return &transport.TenantVTPMStatusResponse{
		TenantID: r.GetTenantId(),
		Running:  r.GetRunning(),
		PID:      int(r.GetPid()),
		Socket:   r.GetSocket(),
		Restarts: r.GetRestarts(),
	}
}
